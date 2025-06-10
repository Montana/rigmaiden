#!/usr/bin/env python3

import os
import platform
import logging
import time
import base64
import json
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

logger = logging.getLogger(__name__)

@dataclass
class KeyMetadata:
    key_id: str
    created_at: float
    expires_at: float
    algorithm: str
    version: int
    nonce_history: set
    hardware_backed: bool = False

class KeyManager:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.keys: Dict[str, Tuple[bytes, KeyMetadata]] = {}
        self.hardware_support = self._init_hardware_support()
        self._load_config()
        
    def _init_hardware_support(self) -> bool:
        """Initialize hardware security support."""
        try:
            if platform.system() == 'Darwin':
                # Check for Secure Enclave support
                return self._check_secure_enclave()
            elif platform.system() == 'Windows':
                # Check for TPM support
                return self._check_tpm()
            return False
        except Exception as e:
            logger.error(f"Hardware support initialization failed: {e}")
            return False
            
    def _check_secure_enclave(self) -> bool:
        """Check for Secure Enclave support on macOS."""
        try:
            import ctypes
            lib = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
            return bool(lib.SecKeychainIsLocked(None))
        except Exception:
            return False
            
    def _check_tpm(self) -> bool:
        """Check for TPM support on Windows."""
        try:
            import win32com.client
            wmi = win32com.client.GetObject("winmgmts:")
            tpm = wmi.InstancesOf("Win32_Tpm")
            return len(tpm) > 0
        except Exception:
            return False
            
    def _load_config(self) -> None:
        """Load key management configuration."""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                self.key_rotation_interval = config.get('key_rotation_interval', 86400)  # 24 hours
                self.max_nonce_history = config.get('max_nonce_history', 1000)
                self.key_size = config.get('key_size', 32)
                self.iterations = config.get('iterations', 100000)
        except Exception as e:
            logger.error(f"Failed to load key management config: {e}")
            # Set defaults
            self.key_rotation_interval = 86400
            self.max_nonce_history = 1000
            self.key_size = 32
            self.iterations = 100000
            
    def generate_key(self, key_id: str) -> Tuple[str, bytes]:
        """Generate a new key with hardware backing if available."""
        try:
            if self.hardware_support:
                if platform.system() == 'Darwin':
                    key = self._generate_secure_enclave_key()
                else:
                    key = self._generate_tpm_key()
            else:
                key = secrets.token_bytes(self.key_size)
                
            metadata = KeyMetadata(
                key_id=key_id,
                created_at=time.time(),
                expires_at=time.time() + self.key_rotation_interval,
                algorithm='AES-256-GCM',
                version=1,
                nonce_history=set(),
                hardware_backed=self.hardware_support
            )
            
            self.keys[key_id] = (key, metadata)
            return key_id, key
            
        except Exception as e:
            logger.error(f"Key generation failed: {e}")
            raise
            
    def _generate_secure_enclave_key(self) -> bytes:
        """Generate a key using macOS Secure Enclave."""
        try:
            import ctypes
            from Security import kSecAttrKeyTypeAES, kSecAttrKeySizeInBits256
            
            key_size = ctypes.c_size_t(32)
            key_data = ctypes.create_string_buffer(32)
            
            lib = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
            result = lib.SecKeyGeneratePair(
                kSecAttrKeyTypeAES,
                kSecAttrKeySizeInBits256,
                key_data,
                ctypes.byref(key_size)
            )
            
            if result != 0:
                raise Exception("Secure Enclave key generation failed")
                
            return bytes(key_data)
        except Exception as e:
            logger.error(f"Secure Enclave key generation failed: {e}")
            return secrets.token_bytes(32)
            
    def _generate_tpm_key(self) -> bytes:
        """Generate a key using Windows TPM."""
        try:
            import win32com.client
            wmi = win32com.client.GetObject("winmgmts:")
            tpm = wmi.InstancesOf("Win32_Tpm").Item(0)
            
            result = tpm.CreateKey(32)
            if result != 0:
                raise Exception("TPM key generation failed")
                
            return result
        except Exception as e:
            logger.error(f"TPM key generation failed: {e}")
            return secrets.token_bytes(32)
            
    def store_key(self, key_id: str, key: bytes, metadata: KeyMetadata) -> None:
        """Store a key with its metadata."""
        self.keys[key_id] = (key, metadata)
        
    def get_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve a key by ID."""
        if key_id in self.keys:
            key, metadata = self.keys[key_id]
            if time.time() > metadata.expires_at:
                logger.warning(f"Key {key_id} has expired")
                return None
            return key
        return None
        
    def rotate_keys(self) -> None:
        """Rotate expired keys."""
        current_time = time.time()
        for key_id, (key, metadata) in list(self.keys.items()):
            if current_time > metadata.expires_at:
                try:
                    new_key_id, new_key = self.generate_key(key_id)
                    logger.info(f"Rotated key {key_id}")
                except Exception as e:
                    logger.error(f"Key rotation failed for {key_id}: {e}")
                    
    def validate_nonce(self, key_id: str, nonce: str) -> bool:
        """Validate a nonce to prevent reuse."""
        if key_id not in self.keys:
            return False
            
        _, metadata = self.keys[key_id]
        if nonce in metadata.nonce_history:
            logger.warning(f"Nonce reuse detected for key {key_id}")
            return False
            
        metadata.nonce_history.add(nonce)
        if len(metadata.nonce_history) > self.max_nonce_history:
            metadata.nonce_history.pop()
            
        return True
        
    def encrypt_data(self, key_id: str, data: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt data using the specified key."""
        key = self.get_key(key_id)
        if not key:
            raise ValueError(f"Invalid or expired key: {key_id}")
            
        nonce = os.urandom(12)
        if not self.validate_nonce(key_id, base64.b64encode(nonce).decode()):
            raise ValueError("Nonce validation failed")
            
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return ciphertext, nonce, encryptor.tag
        
    def decrypt_data(self, key_id: str, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """Decrypt data using the specified key."""
        key = self.get_key(key_id)
        if not key:
            raise ValueError(f"Invalid or expired key: {key_id}")
            
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize() 