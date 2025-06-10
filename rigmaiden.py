#!/usr/bin/env python3

from __future__ import annotations

__version__ = "1.0.0"

import re
import subprocess
import platform
import os
import sys
import signal
import logging
import configparser
import shutil
from pathlib import Path
from time import sleep
from datetime import datetime
from typing import Dict, List, Set, Optional, Union, Any, Tuple
from dataclasses import dataclass, field
from contextlib import contextmanager
import asyncio
from concurrent.futures import ThreadPoolExecutor
import psutil
import sqlite3
import json
import hashlib
import socket
import threading
import queue
import ssl
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import tempfile
import mmap
import struct
import binascii
import ctypes
import array
import argparse
import statistics
import shlex
from scripts.secure_commands import SecureCommandExecutor, CommandResult
from scripts.resource_manager import ResourceManager, ResourceLimits
from helpers.platform_utils import get_platform_utils, PlatformUtils

CURRENT_PLATFORM = platform.system().upper()

if CURRENT_PLATFORM.startswith("DARWIN"):
	import plistlib

DEVICE_RE = [
	re.compile(r".+ID\s(?P<id>\w+:\w+)"),
	re.compile(r"0x([0-9a-z]{4})")
]

IOS_DEVICE_IDS = {
	'05ac': 'Apple',  
	'05ac:12a8': 'iPhone',
	'05ac:12ab': 'iPad',
	'05ac:12a9': 'iPod',
	'05ac:12aa': 'Apple Watch',
	'05ac:12ac': 'Apple TV'
}

CELLEBRITE_PATTERNS = {
	'process_names': [
		'cellebrite', 'ufed', 'physical', 'logical',
		'ufed4pc', 'ufedphysical', 'ufedlogical',
		'ufedreader', 'ufed4pc', 'ufed4pc.exe',
		'physicalanalyzer', 'logicalanalyzer',
		'ufedphysicalanalyzer', 'ufedlogicalanalyzer'
	],
	'keywords': [
		'cellebrite', 'ufed', 'extraction', 'forensic',
		'physical', 'logical', 'backup', 'analyzer',
		'reader', 'extractor', 'forensics', 'evidence',
		'investigation', 'acquisition', 'extraction'
	],
	'ports': [8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089],
	'file_extensions': [
		'.ufd', '.ufdr', '.ufdx', '.ufd4pc',
		'.ufdphysical', '.ufdlogical', '.ufdreader',
		'.ufdanalyzer', '.ufdbackup', '.ufdextraction'
	],
	'registry_keys': [
		'SOFTWARE\\Cellebrite',
		'SOFTWARE\\UFED',
		'SOFTWARE\\Physical Analyzer',
		'SOFTWARE\\Logical Analyzer'
	]
}

JIGGLER_PATTERNS = {
	'keywords': [
		"jiggler", "mouse mover", "wiggler", "mousejiggle",
		"caffeine", "nosleep", "stayawake", "mousejiggler",
		"mousejiggle", "mousejiggler", "mousejiggle.exe",
		"jiggler.exe", "wiggler.exe", "caffeine.exe",
		"nosleep.exe", "stayawake.exe"
	],
	'suspicious_processes': [
		"mousejiggle", "jiggler", "wiggler", "caffeine",
		"nosleep", "stayawake", "jiggler.exe", "wiggler.exe",
		"caffeine.exe", "nosleep.exe", "stayawake.exe"
	],
	'suspicious_ports': [8080, 8081, 8082, 8083, 8084, 8085],
	'file_extensions': [
		'.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1',
		'.vbs', '.js', '.wsf', '.msi', '.inf', '.reg'
	],
	'registry_keys': [
		'SOFTWARE\\MouseJiggle',
		'SOFTWARE\\Jiggler',
		'SOFTWARE\\Wiggler',
		'SOFTWARE\\Caffeine',
		'SOFTWARE\\NoSleep',
		'SOFTWARE\\StayAwake'
	]
}

USB_PATTERNS = {
	'blocked_vendors': {
		'05ac', '0483', '0781', '0951', '0bda', '0cf3',
		'04f3', '046d', '045e', '0461', '0451', '0457',
		'04e8', '04b4', '04b3', '04b0', '04a9', '04a5'
	},
	'blocked_products': {
		'8600', '5740', '5583', '1666', '8176', '8179',
		'8178', '8177', '8176', '8175', '8174', '8173',
		'8172', '8171', '8170', '8169', '8168', '8167'
	},
	'suspicious_ports': {8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089},
	'suspicious_files': {
		'.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1',
		'.vbs', '.js', '.wsf', '.msi', '.inf', '.reg',
		'.ufd', '.ufdr', '.ufdx', '.ufd4pc', '.ufdphysical',
		'.ufdlogical', '.ufdreader', '.ufdanalyzer', '.ufdbackup'
	}
}

ENCRYPTION_SETTINGS = {
	'salt_length': 16,
	'key_length': 32,
	'iterations': 100000,
	'algorithm': 'AES-256-GCM',
	'tag_length': 16,
	'nonce_length': 12
}

SECURITY_SETTINGS = {
	'max_retries': 3,
	'retry_delay': 5,
	'alert_threshold': 2,
	'backup_interval': 1800,
	'max_backups': 48,
	'check_interval': 0.5,
	'shred_passes': 3,
	'encryption_enabled': True,
	'network_blocking': True,
	'file_shredding': True,
	'process_killing': True,
	'registry_monitoring': True
}

SETTINGS_FILE = '/etc/rigmaiden.ini'
DEFAULT_LOG_FILE = '/var/log/rigmaiden/kills.log'

USERNAME = os.getlogin()
CELLEBRITE_DB_PATH = f"/Users/{USERNAME}/Library/Application Support/Knowledge/knowledgeC.db"

logging.basicConfig(
	level=logging.DEBUG,
	format='%(asctime)s - %(levelname)s - %(message)s',
	handlers=[
		logging.FileHandler('/var/log/rigmaiden/rigmaiden.log'),
		logging.StreamHandler(sys.stdout)
	]
)
logger = logging.getLogger(__name__)

ENCRYPTION_KEY = Fernet.generate_key()

MEMORY_PROTECTION = {
	'PAGE_EXECUTE': 0x10,
	'PAGE_EXECUTE_READ': 0x20,
	'PAGE_EXECUTE_READWRITE': 0x40,
	'PAGE_EXECUTE_WRITECOPY': 0x80,
	'PAGE_NOACCESS': 0x01,
	'PAGE_READONLY': 0x02,
	'PAGE_READWRITE': 0x04,
	'PAGE_WRITECOPY': 0x08,
	'PAGE_GUARD': 0x100,
	'PAGE_NOCACHE': 0x200,
	'PAGE_WRITECOMBINE': 0x400
}

@dataclass
class MemoryRegion:
	start: int
	size: int
	protection: int
	hash: str = field(default='')
	last_check: float = field(default=0.0)

class IMSEProtection:
	def __init__(self):
		self.protected_regions: List[MemoryRegion] = []
		self.memory_hashes: Dict[int, str] = {}
		self.suspicious_patterns: Set[bytes] = {
			b'\x90' * 16,
			b'\xCC' * 16,
			b'\xEB\xFF',
			b'\xE8\x00\x00\x00\x00',
		}
		self.check_interval: float = 0.1
		self.last_check: float = 0.0

	def protect_memory_region(self, start: int, size: int, protection: int) -> bool:
		try:
			if CURRENT_PLATFORM.startswith("WIN"):
				kernel32 = ctypes.windll.kernel32
				old_protect = ctypes.c_ulong(0)
				result = kernel32.VirtualProtect(
					ctypes.c_void_p(start),
					ctypes.c_size_t(size),
					protection,
					ctypes.byref(old_protect)
				)
				if result:
					region = MemoryRegion(start, size, protection)
					region.hash = self._calculate_region_hash(start, size)
					self.protected_regions.append(region)
					return True
			else:
				libc = ctypes.CDLL('libc.so.6')
				result = libc.mprotect(
					ctypes.c_void_p(start),
					ctypes.c_size_t(size),
					protection
				)
				if result == 0:
					region = MemoryRegion(start, size, protection)
					region.hash = self._calculate_region_hash(start, size)
					self.protected_regions.append(region)
					return True
			return False
		except Exception as e:
			logger.error(f"Failed to protect memory region: {e}")
			return False

	def _calculate_region_hash(self, start: int, size: int) -> str:
		try:
			if CURRENT_PLATFORM.startswith("WIN"):
				kernel32 = ctypes.windll.kernel32
				buffer = (ctypes.c_char * size)()
				bytes_read = ctypes.c_size_t(0)
				kernel32.ReadProcessMemory(
					kernel32.GetCurrentProcess(),
					ctypes.c_void_p(start),
					buffer,
					size,
					ctypes.byref(bytes_read)
				)
			else:
				with open(f"/proc/self/mem", "rb") as f:
					f.seek(start)
					buffer = f.read(size)
			
			return hashlib.sha256(buffer).hexdigest()
		except Exception as e:
			logger.error(f"Failed to calculate memory hash: {e}")
			return ""

	def check_memory_integrity(self) -> bool:
		try:
			current_time = time.time()
			if current_time - self.last_check < self.check_interval:
				return True

			for region in self.protected_regions:
				current_hash = self._calculate_region_hash(region.start, region.size)
				if current_hash != region.hash:
					logger.warning(f"Memory integrity violation detected at {hex(region.start)}")
					return False
				region.last_check = current_time

			self.last_check = current_time
			return True
		except Exception as e:
			logger.error(f"Memory integrity check failed: {e}")
			return False

	def scan_for_suspicious_patterns(self) -> List[Tuple[int, bytes]]:
		suspicious_found = []
		try:
			if CURRENT_PLATFORM.startswith("WIN"):
				kernel32 = ctypes.windll.kernel32
				process = kernel32.GetCurrentProcess()
				address = 0
				while address < 0x7FFFFFFF:
					try:
						buffer = (ctypes.c_char * 4096)()
						bytes_read = ctypes.c_size_t(0)
						if kernel32.ReadProcessMemory(
							process,
							ctypes.c_void_p(address),
							buffer,
							4096,
							ctypes.byref(bytes_read)
						):
							for pattern in self.suspicious_patterns:
								if pattern in buffer:
									suspicious_found.append((address + buffer.index(pattern), pattern))
					except:
						pass
					address += 4096
			else:
				with open("/proc/self/maps", "r") as f:
					for line in f:
						if "r-xp" in line:
							start, end = map(lambda x: int(x, 16), line.split()[0].split("-"))
							with open("/proc/self/mem", "rb") as mem:
								mem.seek(start)
								data = mem.read(end - start)
								for pattern in self.suspicious_patterns:
									pos = 0
									while True:
										pos = data.find(pattern, pos)
										if pos == -1:
											break
										suspicious_found.append((start + pos, pattern))
										pos += 1

			return suspicious_found
		except Exception as e:
			logger.error(f"Memory pattern scan failed: {e}")
			return []

	def protect_critical_memory(self) -> None:
		try:
			if CURRENT_PLATFORM.startswith("WIN"):
				kernel32 = ctypes.windll.kernel32
				process = kernel32.GetCurrentProcess()
				address = 0
				while address < 0x7FFFFFFF:
					try:
						buffer = (ctypes.c_char * 4096)()
						bytes_read = ctypes.c_size_t(0)
						if kernel32.ReadProcessMemory(
							process,
							ctypes.c_void_p(address),
							buffer,
							4096,
							ctypes.byref(bytes_read)
						):
							self.protect_memory_region(
								address,
								4096,
								MEMORY_PROTECTION['PAGE_EXECUTE_READ']
							)
					except:
						pass
					address += 4096
			else:
				with open("/proc/self/maps", "r") as f:
					for line in f:
						if "r-xp" in line:
							start, end = map(lambda x: int(x, 16), line.split()[0].split("-"))
							self.protect_memory_region(
								start,
								end - start,
								MEMORY_PROTECTION['PAGE_EXECUTE_READ']
							)
		except Exception as e:
			logger.error(f"Failed to protect critical memory: {e}")

class StingrayProtection:
	def __init__(self):
		self.known_cells = {}
		self.suspicious_events = []
		self.check_interval = 1.0
		self.last_check = 0.0
		self.alert_threshold = 3
		self.force_airplane_mode = True
		self.known_operators = set()
		self.signal_history = []
		self.max_signal_history = 100
		self.signal_variance_threshold = 15.0
		self.frequency_hopping_detected = False
		self.last_frequencies = []
		self.max_frequency_history = 10

	def get_cellular_info(self):
		try:
			if not CURRENT_PLATFORM.startswith('DARWIN'):
				return None

			output = subprocess.check_output(
				['system_profiler', 'SPCellularDataType']
			).decode()

			if 'Cellular' not in output:
				return None

			mcc = int(re.search(r'MCC:\s*(\d+)', output).group(1))
			mnc = int(re.search(r'MNC:\s*(\d+)', output).group(1))
			cell_id = int(re.search(r'Cell ID:\s*(\d+)', output).group(1))
			lac = int(re.search(r'LAC:\s*(\d+)', output).group(1))
			signal = int(re.search(r'Signal Strength:\s*([-\d]+)', output).group(1))
			band = re.search(r'Band:\s*(\w+)', output).group(1)
			freq = int(re.search(r'Frequency:\s*(\d+)', output).group(1))

			self._update_signal_history(signal)
			self._update_frequency_history(freq)

			return CellularInfo(
				mcc=mcc,
				mnc=mnc,
				cell_id=cell_id,
				lac=lac,
				signal_strength=signal,
				band=band,
				frequency=freq,
			)

		except Exception as e:
			logger.error(f'Failed to get cellular info: {e}')
			return None

	def _update_signal_history(self, signal):
		self.signal_history.append((time.time(), signal))
		if len(self.signal_history) > self.max_signal_history:
			self.signal_history.pop(0)

	def _update_frequency_history(self, freq):
		self.last_frequencies.append(freq)
		if len(self.last_frequencies) > self.max_frequency_history:
			self.last_frequencies.pop(0)

	def detect_frequency_hopping(self):
		if len(self.last_frequencies) < 3:
			return False

		freq_changes = [
			abs(self.last_frequencies[i] - self.last_frequencies[i - 1])
			for i in range(1, len(self.last_frequencies))
		]

		if any(change > 1000 for change in freq_changes):
			return True

		unique_freqs = len(set(self.last_frequencies))
		if unique_freqs > len(self.last_frequencies) * 0.7:
			return True

		return False

	def analyze_signal_patterns(self):
		if len(self.signal_history) < 10:
			return False, []

		reasons = []
		signals = [s[1] for s in self.signal_history]
		mean_signal = sum(signals) / len(signals)
		variance = sum((s - mean_signal) ** 2 for s in signals) / len(signals)

		if variance > self.signal_variance_threshold:
			reasons.append('Unusual signal variance')

		if any(s > -30 for s in signals):
			reasons.append('Abnormally strong signals detected')

		signal_changes = [
			abs(signals[i] - signals[i - 1])
			for i in range(1, len(signals))
		]
		if any(change > 20 for change in signal_changes):
			reasons.append('Rapid signal strength changes')

		return bool(reasons), reasons

	def check_for_stingray(self):
		try:
			current_time = time.time()
			if current_time - self.last_check < self.check_interval:
				return False

			cell_info = self.get_cellular_info()
			if not cell_info:
				return False

			reasons = []
			suspicious = False

			if cell_info.signal_strength in range(-50, -30):
				suspicious = True
				reasons.append('Unusually strong signal')

			if cell_info.cell_id in [0, 1, 65535]:
				suspicious = True
				reasons.append('Suspicious cell ID')

			if cell_info.lac in [0, 65535]:
				suspicious = True
				reasons.append('Suspicious location area code')

			freq_hopping = self.detect_frequency_hopping()
			if freq_hopping:
				suspicious = True
				reasons.append('Frequency hopping detected')
				self.frequency_hopping_detected = True

			signal_suspicious, signal_reasons = self.analyze_signal_patterns()
			if signal_suspicious:
				suspicious = True
				reasons.extend(signal_reasons)

			operator_key = f'{cell_info.mcc}:{cell_info.mnc}'
			if operator_key not in self.known_operators:
				self.known_operators.add(operator_key)
				if len(self.known_operators) > 2:
					suspicious = True
					reasons.append('Multiple operator changes detected')

			cell_key = f'{cell_info.mcc}:{cell_info.mnc}:{cell_info.cell_id}'
			if cell_key in self.known_cells:
				old_cell = self.known_cells[cell_key]
				if abs(old_cell.signal_strength - cell_info.signal_strength) > 20:
					suspicious = True
					reasons.append('Rapid signal strength change')

			self.known_cells[cell_key] = cell_info

			if suspicious:
				self._handle_suspicious_activity(
					current_time,
					reasons,
					cell_info,
					freq_hopping,
					signal_reasons,
				)

			self.last_check = current_time
			return suspicious

		except Exception as e:
			logger.error(f'Stingray check failed: {e}')
			return False

	def _handle_suspicious_activity(
		self,
		current_time,
		reasons,
		cell_info,
		freq_hopping,
		signal_reasons,
	):
		self.suspicious_events.append({
			'timestamp': current_time,
			'reasons': reasons,
			'cell_info': cell_info,
			'frequency_hopping': freq_hopping,
			'signal_analysis': signal_reasons,
		})

		recent_events = [
			e for e in self.suspicious_events
			if current_time - e['timestamp'] < 60
		]

		if len(recent_events) >= self.alert_threshold:
			logger.warning('Potential Stingray device detected!')
			logger.warning(f'Reasons: {reasons}')
			if freq_hopping:
				logger.warning('Frequency hopping pattern detected!')
			if signal_reasons:
				logger.warning('Suspicious signal patterns detected!')

	def enable_airplane_mode(self):
		try:
			if not CURRENT_PLATFORM.startswith('DARWIN'):
				return False

			commands = [
				['networksetup', '-setairportpower', 'en0', 'off'],
				['networksetup', '-setbluetoothpower', 'off'],
				['networksetup', '-setwwanpowerstate', 'off'],
				[
					'defaults',
					'write',
					'/Library/Preferences/com.apple.locationd',
					'LocationServicesEnabled',
					'-bool',
					'false',
				],
				['killall', 'locationd'],
			]

			for cmd in commands:
				subprocess.run(cmd, check=True)

			return True

		except Exception as e:
			logger.error(f'Failed to enable airplane mode: {e}')
			return False

@dataclass
class CellularInfo:
	mcc: int
	mnc: int
	cell_id: int
	lac: int
	signal_strength: int
	band: str
	frequency: int
	timestamp: float = field(default_factory=time.time)

@dataclass
class Settings:
	sleep_time: float
	whitelist: Set[str]
	log_file: str
	remove_file_cmd: str
	melt_usbkill: bool
	folders_to_remove: List[str]
	files_to_remove: List[str]
	kill_commands: List[str]
	do_sync: bool
	do_wipe_ram: bool
	do_wipe_swap: bool
	wipe_ram_cmd: str
	wipe_swap_cmd: str
	shut_down: bool
	check_jiggler: bool
	check_cellebrite: bool
	block_ios_access: bool
	check_interval: float = 0.5
	backup_interval: int = 1800
	max_backups: int = 48
	alert_threshold: int = 2
	do_backup: bool = True
	do_monitor: bool = True
	do_cleanup: bool = True
	backup_location: str = '/var/backups/rigmaiden'
	encrypt_backups: bool = True
	notify_email: bool = True
	notify_api: bool = True
	shred_files: bool = True
	block_network: bool = True
	max_retries: int = 3
	retry_delay: int = 5
	allowed_vendors: Set[str] = None
	allowed_products: Set[str] = None
	wipe_ram: bool = True
	wipe_swap: bool = True
	ram_wipe_passes: int = 3
	swap_wipe_passes: int = 3
	wipe_delay: float = 0.1
	safe_mode: bool = True
	dry_run: bool = False
	security_level: str = 'LOW'
	notify_only: bool = True
	backup_enabled: bool = True
	quarantine_enabled: bool = True
	quarantine_location: str = './quarantine'
	system_lock_enabled: bool = True
	network_block_enabled: bool = True
	memory_protection_enabled: bool = True
	file_monitoring_enabled: bool = True
	process_monitoring_enabled: bool = True
	device_monitoring_enabled: bool = True
	suspicious_patterns: Dict = field(default_factory=dict)
	custom_actions: Dict = field(default_factory=dict)
	
	encryption_settings: Dict = None
	security_settings: Dict = None
	cellebrite_patterns: Dict = None
	jiggler_patterns: Dict = None
	usb_patterns: Dict = None
	
	def __post_init__(self):
		if self.allowed_vendors is None:
			self.allowed_vendors = set()
		if self.allowed_products is None:
			self.allowed_products = set()
		if self.encryption_settings is None:
			self.encryption_settings = ENCRYPTION_SETTINGS
		if self.security_settings is None:
			self.security_settings = SECURITY_SETTINGS
		if self.cellebrite_patterns is None:
			self.cellebrite_patterns = CELLEBRITE_PATTERNS
		if self.jiggler_patterns is None:
			self.jiggler_patterns = JIGGLER_PATTERNS
		if self.usb_patterns is None:
			self.usb_patterns = USB_PATTERNS
		if not hasattr(self, 'safe_mode'):
			self.safe_mode = True
		if not hasattr(self, 'dry_run'):
			self.dry_run = False
		if self.security_level == 'HIGH':
			self.safe_mode = False
			self.dry_run = False
			self.notify_only = False
			self.max_retries = 10
			self.retry_delay = 1
		elif self.security_level == 'MEDIUM':
			self.safe_mode = True
			self.dry_run = False
			self.notify_only = False
			self.max_retries = 5
			self.retry_delay = 3
		else:  # LOW
			self.safe_mode = True
			self.dry_run = True
			self.notify_only = True
			self.max_retries = 3
			self.retry_delay = 5

class DeviceCountSet(dict):
	def __init__(self, items: Union[List[str], List[Dict[str, int]]]) -> None:
		count: Dict[str, int] = {}
		for item in items:
			if isinstance(item, dict):
				count.update(item)
			elif item in count:
				count[item] += 1
			else:
				count[item] = 1
		super().__init__(count)

	def __add__(self, other: Union[DeviceCountSet, List[str]]) -> DeviceCountSet:
		new_dict = dict(self)
		if isinstance(other, (list, tuple)):
			for k in other:
				new_dict[k] = new_dict.get(k, 0) + 1
		else:
			for k, v in other.items():
				new_dict[k] = max(new_dict.get(k, 0), v)
		return DeviceCountSet(new_dict)

class SecurityError(Exception):
	"""Base class for security-related exceptions."""
	pass

class CommandInjectionError(SecurityError):
	"""Raised when command injection is detected."""
	pass

class ResourceLimitError(SecurityError):
	"""Raised when resource limits are exceeded."""
	pass

# Resource limits
MAX_MEMORY_USAGE = 1024 * 1024 * 1024  # 1GB
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_PROCESS_COUNT = 1000
MAX_OPEN_FILES = 100

def sanitize_command(cmd: Union[str, List[str]]) -> List[str]:
	"""Sanitize command to prevent injection attacks."""
	if isinstance(cmd, str):
		cmd = shlex.split(cmd)
	
	sanitized = []
	for arg in cmd:
		if any(c in arg for c in [';', '|', '&', '>', '<', '`', '$', '(', ')', '{', '}']):
			raise CommandInjectionError(f"Potentially dangerous command argument: {arg}")
		sanitized.append(arg)
	return sanitized

def check_resource_limits() -> None:
	"""Check if resource usage is within limits."""
	try:
		process = psutil.Process()
		if process.memory_info().rss > MAX_MEMORY_USAGE:
			raise ResourceLimitError(f"Memory usage exceeded limit: {process.memory_info().rss}")
		
		if process.num_fds() > MAX_OPEN_FILES:
			raise ResourceLimitError(f"Too many open files: {process.num_fds()}")
		
		if len(psutil.pids()) > MAX_PROCESS_COUNT:
			raise ResourceLimitError(f"Too many processes: {len(psutil.pids())}")
	except Exception as e:
		logger.error(f"Resource limit check failed: {e}")
		raise

@contextmanager
def secure_file_operation(filepath: str, mode: str = 'a+', max_size: int = MAX_FILE_SIZE) -> Any:
	"""Secure file operation with size limits and proper cleanup."""
	file = None
	try:
		if os.path.exists(filepath) and os.path.getsize(filepath) > max_size:
			raise ResourceLimitError(f"File too large: {filepath}")
		
		file = open(filepath, mode)
		yield file
	except (IOError, PermissionError) as e:
		logger.error(f"Failed to access file {filepath}: {e}")
		raise
	finally:
		if file:
			try:
				file.close()
			except Exception as e:
				logger.error(f"Failed to close file {filepath}: {e}")

async def run_secure_command(cmd: Union[str, List[str]], **kwargs) -> Tuple[int, str, str]:
	"""Run command with security checks and resource limits."""
	try:
		check_resource_limits()
		sanitized_cmd = sanitize_command(cmd)
		
		process = await asyncio.create_subprocess_exec(
			*sanitized_cmd,
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE,
			**kwargs
		)
		
		stdout, stderr = await process.communicate()
		return process.returncode, stdout.decode(), stderr.decode()
	except Exception as e:
		logger.error(f"Command execution failed: {e}")
		raise

async def log(settings: Settings, msg: str) -> None:
	async with secure_file_operation(settings.log_file) as f:
		f.write(f"{datetime.now().isoformat()} - {msg}\n")

async def shred(settings: Settings) -> None:
	if not settings.shred_files:
		return

	async def shred_path(path: str) -> None:
		if os.path.exists(path):
			os.remove(path)

	for path in settings.files_to_remove:
		await shred_path(path)

async def lock_system() -> bool:
	try:
		if CURRENT_PLATFORM.startswith("WIN"):
			subprocess.run(['rundll32.exe', 'user32.dll,LockWorkStation'], check=True)
		else:
			subprocess.run(['loginctl', 'lock-session'], check=True)
		return True
	except Exception as e:
		logger.error(f"Failed to lock system: {e}")
		return False

async def force_shutdown() -> bool:
	try:
		if CURRENT_PLATFORM.startswith("WIN"):
			subprocess.run(['shutdown', '/s', '/t', '0'], check=True)
		else:
			subprocess.run(['shutdown', '-h', 'now'], check=True)
		return True
	except Exception as e:
		logger.error(f"Failed to force shutdown: {e}")
		return False

async def handle_usb_disconnect(settings: Settings) -> None:
	if settings.do_sync:
		subprocess.run(['sync'], check=True)

	if settings.do_wipe_ram:
		await shred(settings)

	if settings.do_wipe_swap:
		await wipe_swap()

	if settings.shut_down:
		await force_shutdown()

async def create_backup(settings: Settings) -> None:
	if not settings.do_backup:
		return

	backup_dir = Path(settings.backup_location)
	backup_dir.mkdir(parents=True, exist_ok=True)

	timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
	backup_file = backup_dir / f'backup_{timestamp}.tar.gz'

	subprocess.run(['tar', '-czf', str(backup_file), *settings.folders_to_remove], check=True)

	if settings.encrypt_backups:
		secure_encrypt_file(backup_file, ENCRYPTION_KEY.decode())

async def quarantine_suspicious_files(settings: Settings) -> None:
	if not settings.quarantine_enabled:
		return

	quarantine_dir = Path(settings.quarantine_location)
	quarantine_dir.mkdir(parents=True, exist_ok=True)

	for file in settings.files_to_remove:
		file_path = Path(file)
		if file_path.exists():
			quarantine_path = quarantine_dir / file_path.name
			shutil.move(str(file_path), str(quarantine_path))

async def kill_computer(settings: Settings) -> None:
	if settings.dry_run:
		logger.info("Dry run - would have killed computer")
		return

	async def run_command(command: str) -> None:
		try:
			subprocess.run(command.split(), check=True)
		except Exception as e:
			logger.error(f"Failed to run command {command}: {e}")

	if settings.melt_usbkill:
		await run_command(settings.remove_file_cmd)

	if settings.do_sync:
		await run_command('sync')

	if settings.do_wipe_ram:
		await run_command(settings.wipe_ram_cmd)

	if settings.do_wipe_swap:
		await run_command(settings.wipe_swap_cmd)

	if settings.shut_down:
		await run_command('shutdown -h now')

async def lsusb_darwin() -> List[str]:
	try:
		output = subprocess.check_output(['system_profiler', 'SPUSBDataType']).decode()
		devices = []
		for line in output.split('\n'):
			for pattern in DEVICE_RE:
				match = pattern.search(line)
				if match:
					devices.append(match.group(1))
		return devices
	except Exception as e:
		logger.error(f"Failed to get USB devices on Darwin: {e}")
		return []

def check_inside(result: dict, devices: List[str]) -> None:
	for device in devices:
		if device in result:
			result[device] += 1
		else:
			result[device] = 1

async def lsusb() -> DeviceCountSet:
	try:
		if CURRENT_PLATFORM.startswith("DARWIN"):
			return DeviceCountSet(await lsusb_darwin())
		else:
			output = subprocess.check_output(['lsusb']).decode()
			return DeviceCountSet([line.split()[5] for line in output.split('\n') if line])
	except Exception as e:
		logger.error(f"Failed to get USB devices: {e}")
		return DeviceCountSet([])

def program_present(program: str) -> bool:
	return shutil.which(program) is not None

def load_settings(filename: str) -> Settings:
	config = configparser.ConfigParser()
	config.read(filename)
	return Settings(**config['DEFAULT'])

async def check_jiggler() -> bool:
	try:
		for proc in psutil.process_iter(['name']):
			if proc.info['name'].lower() in JIGGLER_PATTERNS['suspicious_processes']:
				return True
		return False
	except Exception as e:
		logger.error(f"Failed to check for jiggler: {e}")
		return False

async def check_cellebrite() -> bool:
	try:
		for proc in psutil.process_iter(['name']):
			if proc.info['name'].lower() in CELLEBRITE_PATTERNS['process_names']:
				return True
		return False
	except Exception as e:
		logger.error(f"Failed to check for Cellebrite: {e}")
		return False

async def is_ios_device(device_id: str) -> bool:
	return device_id in IOS_DEVICE_IDS

async def check_cellebrite_processes() -> bool:
	try:
		for proc in psutil.process_iter(['name', 'cmdline']):
			if proc.info['name'].lower() in CELLEBRITE_PATTERNS['process_names']:
				return True
			if proc.info['cmdline']:
				for cmd in proc.info['cmdline']:
					if any(keyword in cmd.lower() for keyword in CELLEBRITE_PATTERNS['keywords']):
						return True
		return False
	except Exception as e:
		logger.error(f"Failed to check Cellebrite processes: {e}")
		return False

async def check_ios_cellebrite_conflict(settings: Settings, current_devices: DeviceCountSet) -> bool:
	if not settings.block_ios_access:
		return False

	for device in current_devices:
		if await is_ios_device(device):
			if await check_cellebrite_processes():
				return True
	return False

async def security_checks(settings: Settings, current_devices: DeviceCountSet) -> bool:
	if settings.check_jiggler and await check_jiggler():
		return True

	if settings.check_cellebrite and await check_cellebrite():
		return True

	if await check_ios_cellebrite_conflict(settings, current_devices):
		return True

	return False

def wipe_memory_region(start: int, size: int, passes: int = 3) -> bool:
	try:
		if CURRENT_PLATFORM.startswith("WIN"):
			kernel32 = ctypes.windll.kernel32
			buffer = (ctypes.c_char * size)()
			for _ in range(passes):
				os.urandom(size, buffer)
				kernel32.WriteProcessMemory(
					kernel32.GetCurrentProcess(),
					ctypes.c_void_p(start),
					buffer,
					size,
					None
				)
		else:
			with open("/proc/self/mem", "wb") as f:
				f.seek(start)
				for _ in range(passes):
					f.write(os.urandom(size))
		return True
	except Exception as e:
		logger.error(f"Failed to wipe memory region: {e}")
		return False

def wipe_swap() -> bool:
	try:
		if CURRENT_PLATFORM.startswith("WIN"):
			return False
		subprocess.run(['swapoff', '-a'], check=True)
		subprocess.run(['swapon', '-a'], check=True)
		return True
	except Exception as e:
		logger.error(f"Failed to wipe swap: {e}")
		return False

def wipe_ram() -> bool:
	try:
		if CURRENT_PLATFORM.startswith("WIN"):
			return False
		with open("/proc/self/maps", "r") as f:
			for line in f:
				if "rw-p" in line:
					start, end = map(lambda x: int(x, 16), line.split()[0].split("-"))
					wipe_memory_region(start, end - start)
		return True
	except Exception as e:
		logger.error(f"Failed to wipe RAM: {e}")
		return False

async def loop(settings: Settings) -> None:
	last_devices = DeviceCountSet([])
	while True:
		try:
			current_devices = await lsusb()
			if current_devices != last_devices:
				if await security_checks(settings, current_devices):
					await kill_computer(settings)
				last_devices = current_devices
			await asyncio.sleep(settings.check_interval)
		except Exception as e:
			logger.error(f"Loop error: {e}")
			await asyncio.sleep(settings.check_interval)

def startup_checks() -> None:
	if not program_present('lsusb'):
		logger.error("lsusb not found")
		sys.exit(1)

	if not os.path.exists(SETTINGS_FILE):
		logger.error(f"Settings file {SETTINGS_FILE} not found")
		sys.exit(1)

async def main() -> None:
	"""Main entry point with proper error handling and resource management."""
	try:
		startup_checks()
		args = setup_argparse()
		config = load_config(args.config)
		settings = Settings.from_config(config)
		
		def exit_handler(signum: int, frame: Optional[object]) -> None:
			logger.info("Received exit signal. Shutting down...")
			sys.exit(0)
		
		signal.signal(signal.SIGINT, exit_handler)
		signal.signal(signal.SIGTERM, exit_handler)
		
		await loop(settings)
		
	except Exception as e:
		logger.error(f"Fatal error in main: {e}")
		sys.exit(1)

def setup_argparse() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description='USB Security Monitoring Tool')
	parser.add_argument('--config', type=str, help='Path to config file')
	parser.add_argument('--no-backup', action='store_true', help='Disable backups')
	parser.add_argument('--no-monitor', action='store_true', help='Disable monitoring')
	parser.add_argument('--interval', type=float, help='Check interval in seconds')
	parser.add_argument('--no-encrypt', action='store_true', help='Disable encryption')
	parser.add_argument('--no-notify', action='store_true', help='Disable notifications')
	parser.add_argument('--no-shred', action='store_true', help='Disable file shredding')
	parser.add_argument('--safe-mode', action='store_true', help='Enable safe mode (no destructive actions)')
	parser.add_argument('--full-mode', action='store_true', help='Disable safe mode (allow destructive actions)')
	parser.add_argument('--dry-run', action='store_true', help='Simulate all actions without making changes')
	parser.add_argument('--security-level', choices=['LOW', 'MEDIUM', 'HIGH'],
					  default='LOW', help='Security level (LOW, MEDIUM, HIGH)')
	parser.add_argument('--backup', action='store_true', help='Enable backups')
	parser.add_argument('--quarantine', action='store_true', help='Enable quarantine')
	parser.add_argument('--notify-only', action='store_true',
					  help='Only send notifications, no destructive actions')
	return parser.parse_args()

def load_config(config_path: str) -> Dict:
	try:
		with open(config_path, 'r') as f:
			config = json.load(f)
			if 'safe_mode' not in config:
				config['safe_mode'] = True
			if 'dry_run' not in config:
				config['dry_run'] = False
			return config
	except FileNotFoundError:
		logger.warning(f"Config file not found: {config_path}, using defaults")
		return {'safe_mode': True, 'dry_run': False}
	except json.JSONDecodeError:
		logger.error(f"Invalid config file: {config_path}")
		sys.exit(1)

def generate_encryption_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
	if salt is None:
		salt = os.urandom(ENCRYPTION_SETTINGS['salt_length'])
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=ENCRYPTION_SETTINGS['key_length'],
		salt=salt,
		iterations=ENCRYPTION_SETTINGS['iterations'],
		backend=default_backend()
	)
	key = kdf.derive(password.encode())
	return key, salt

def encrypt_data(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
	nonce = os.urandom(ENCRYPTION_SETTINGS['nonce_length'])
	cipher = Cipher(
		algorithms.AES(key),
		modes.GCM(nonce),
		backend=default_backend()
	)
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(data) + encryptor.finalize()
	return ciphertext, nonce, encryptor.tag

def decrypt_data(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
	cipher = Cipher(
		algorithms.AES(key),
		modes.GCM(nonce, tag),
		backend=default_backend()
	)
	decryptor = cipher.decryptor()
	return decryptor.update(ciphertext) + decryptor.finalize()

def secure_encrypt_file(file_path: Path, password: str) -> bool:
	try:
		with open(file_path, 'rb') as f:
			data = f.read()
		key, salt = generate_encryption_key(password)
		ciphertext, nonce, tag = encrypt_data(data, key)
		with open(file_path, 'wb') as f:
			f.write(salt + nonce + tag + ciphertext)
		return True
	except Exception as e:
		logger.error(f"Failed to encrypt file: {e}")
		return False

def secure_decrypt_file(file_path: Path, password: str) -> bool:
	try:
		with open(file_path, 'rb') as f:
			data = f.read()
		salt = data[:ENCRYPTION_SETTINGS['salt_length']]
		nonce = data[ENCRYPTION_SETTINGS['salt_length']:ENCRYPTION_SETTINGS['salt_length'] + ENCRYPTION_SETTINGS['nonce_length']]
		tag = data[ENCRYPTION_SETTINGS['salt_length'] + ENCRYPTION_SETTINGS['nonce_length']:ENCRYPTION_SETTINGS['salt_length'] + ENCRYPTION_SETTINGS['nonce_length'] + ENCRYPTION_SETTINGS['tag_length']]
		ciphertext = data[ENCRYPTION_SETTINGS['salt_length'] + ENCRYPTION_SETTINGS['nonce_length'] + ENCRYPTION_SETTINGS['tag_length']:]
		key, _ = generate_encryption_key(password, salt)
		plaintext = decrypt_data(ciphertext, key, nonce, tag)
		with open(file_path, 'wb') as f:
			f.write(plaintext)
		return True
	except Exception as e:
		logger.error(f"Failed to decrypt file: {e}")
		return False

def secure_shred_file(file_path: Path) -> bool:
	try:
		file_size = file_path.stat().st_size
		with open(file_path, 'wb') as f:
			for _ in range(SECURITY_SETTINGS['shred_passes']):
				f.seek(0)
				f.write(os.urandom(file_size))
		file_path.unlink()
		return True
	except Exception as e:
		logger.error(f"Failed to shred file: {e}")
		return False

def check_registry_keys(patterns: Dict) -> List[str]:
	suspicious = []
	if CURRENT_PLATFORM.startswith("WIN"):
		try:
			for key in patterns.get('registry_keys', []):
				result = subprocess.run(['reg', 'query', key], capture_output=True, text=True)
				if result.returncode == 0:
					suspicious.append(f"Found registry key: {key}")
		except Exception as e:
			logger.error(f"Registry check failed: {e}")
	return suspicious

def enhanced_check_cellebrite() -> Dict[str, List[str]]:
	suspicious = {
		'processes': [],
		'files': [],
		'ports': [],
		'registry': []
	}
	
	try:
		for proc in psutil.process_iter(['name', 'cmdline', 'open_files']):
			try:
				name = proc.info['name'] or ""
				cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
				
				if any(pattern.lower() in name.lower() for pattern in CELLEBRITE_PATTERNS['process_names']):
					suspicious['processes'].append(f"Cellebrite process: {name}")
				
				if any(keyword.lower() in cmdline.lower() for keyword in CELLEBRITE_PATTERNS['keywords']):
					suspicious['processes'].append(f"Cellebrite activity in process: {name}")
				
				for file in proc.info['open_files']:
					if any(ext in file.path.lower() for ext in CELLEBRITE_PATTERNS['file_extensions']):
						suspicious['files'].append(f"Cellebrite file access: {file.path}")
			except (psutil.NoSuchProcess, psutil.AccessDenied):
				continue
		
		for conn in psutil.net_connections():
			if conn.laddr.port in CELLEBRITE_PATTERNS['ports']:
				suspicious['ports'].append(f"Cellebrite port: {conn.laddr.port}")
		
		suspicious['registry'] = check_registry_keys(CELLEBRITE_PATTERNS)
		
	except Exception as e:
		logger.error(f"Enhanced Cellebrite check failed: {e}")
	
	return suspicious

def enhanced_check_jiggler() -> Dict[str, List[str]]:
	suspicious = {
		'processes': [],
		'files': [],
		'ports': [],
		'registry': []
	}
	
	try:
		for proc in psutil.process_iter(['name', 'cmdline']):
			try:
				name = proc.info['name'] or ""
				cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
				
				if any(pattern.lower() in name.lower() for pattern in JIGGLER_PATTERNS['suspicious_processes']):
					suspicious['processes'].append(f"Jiggler process: {name}")
				
				if any(keyword.lower() in cmdline.lower() for keyword in JIGGLER_PATTERNS['keywords']):
					suspicious['processes'].append(f"Jiggler activity in process: {name}")
			except (psutil.NoSuchProcess, psutil.AccessDenied):
				continue
		
		for conn in psutil.net_connections():
			if conn.laddr.port in JIGGLER_PATTERNS['suspicious_ports']:
				suspicious['ports'].append(f"Jiggler port: {conn.laddr.port}")
		
		suspicious['registry'] = check_registry_keys(JIGGLER_PATTERNS)
		
	except Exception as e:
		logger.error(f"Enhanced jiggler check failed: {e}")
	
	return suspicious

def should_perform_destructive(settings: Settings) -> bool:
	return not settings.safe_mode and not settings.dry_run

class RigmaidenProtocol(StingrayProtection):
	def __init__(self):
		super().__init__()
		self.base_station_profiles = {}
		self.signal_fingerprints = {}
		self.network_parameter_history = []
		self.max_parameter_history = 50
		self.suspicious_parameter_changes = 0
		self.parameter_change_threshold = 5
		self.force_encryption = True
		self.enable_countermeasures = True
		self.last_network_scan = 0.0
		self.network_scan_interval = 2.0
		self.traffic_patterns = {}
		self.anomaly_scores = {}
		self.geolocation_spoofing = False
		self.encryption_layers = []
		self.ml_model = None
		self.memory_protection = IMSEProtection()
		self.memory_protection.protect_critical_memory()
		
		# Initialize key manager with proper error handling
		try:
			self.key_manager = KeyManager('rigmaiden.ini')
			self.setup_encryption_layers()
		except Exception as e:
			logger.error(f"Failed to initialize key manager: {e}")
			self.key_manager = None
			self.encryption_layers = []
		
		self.initialize_ml_model()

	def setup_encryption_layers(self) -> None:
		"""Setup encryption layers with proper error handling."""
		if not self.key_manager:
			logger.error("Key manager not initialized")
			return
			
		try:
			# Generate master key
			master_key_id, master_key = self.key_manager.generate_key('master')
			
			# Setup encryption layers with hardware-backed keys
			self.encryption_layers = []
			
			# Layer 1: AES-256-GCM
			key_id, key = self.key_manager.generate_key('aes')
			self.encryption_layers.append({
				'id': key_id,
				'algorithm': 'AES-256-GCM',
				'key': key,
				'key_length': 32,
				'nonce_length': 12,
				'tag_length': 16
			})
			
			# Layer 2: ChaCha20-Poly1305
			key_id, key = self.key_manager.generate_key('chacha')
			self.encryption_layers.append({
				'id': key_id,
				'algorithm': 'ChaCha20-Poly1305',
				'key': key,
				'key_length': 32,
				'nonce_length': 12,
				'tag_length': 16
			})
			
			# Layer 3: XChaCha20-Poly1305
			key_id, key = self.key_manager.generate_key('xchacha')
			self.encryption_layers.append({
				'id': key_id,
				'algorithm': 'XChaCha20-Poly1305',
				'key': key,
				'key_length': 32,
				'nonce_length': 24,
				'tag_length': 16
			})
			
			# Store master key
			self.key_manager.store_key(master_key_id, master_key, {
				'key_id': master_key_id,
				'created_at': time.time(),
				'expires_at': time.time() + 86400,  # 24 hours
				'algorithm': 'master',
				'version': 1,
				'nonce_history': set()
			})
			
		except Exception as e:
			logger.error(f"Failed to setup encryption layers: {e}")
			self.encryption_layers = []

	async def apply_countermeasures(self) -> None:
		"""Apply security countermeasures with proper error handling."""
		try:
			if self.force_encryption and self.key_manager:
				# Rotate keys if needed
				self.key_manager.rotate_keys()
				
				# Apply each encryption layer
				for layer in self.encryption_layers:
					try:
						logger.info(f"Applying encryption layer: {layer['algorithm']}")
						
						# Validate nonce
						nonce = os.urandom(layer['nonce_length'])
						if not self.key_manager.validate_nonce(layer['id'], base64.b64encode(nonce).decode()):
							logger.error(f"Nonce validation failed for layer {layer['algorithm']}")
							continue
						
						# Apply encryption
						if layer['algorithm'] == 'AES-256-GCM':
							cipher = Cipher(
								algorithms.AES(layer['key']),
								modes.GCM(nonce),
								backend=default_backend()
							)
						elif layer['algorithm'] in ['ChaCha20-Poly1305', 'XChaCha20-Poly1305']:
							cipher = Cipher(
								algorithms.ChaCha20Poly1305(layer['key']),
								modes.GCM(nonce),
								backend=default_backend()
							)
						
						encryptor = cipher.encryptor()
						
						# Encrypt critical data
						critical_data = self._get_critical_data()
						if critical_data:
							ciphertext, nonce, tag = self.key_manager.encrypt_data(
								layer['id'],
								critical_data
							)
							self._store_encrypted_data(layer['id'], ciphertext, nonce, tag)
							
					except Exception as e:
						logger.error(f"Failed to apply encryption layer {layer['algorithm']}: {e}")
						continue
			
			if self.enable_countermeasures:
				await self.enable_airplane_mode()
				await self.apply_geolocation_spoofing()
				
				if CURRENT_PLATFORM.startswith('DARWIN'):
					commands = [
						['networksetup', '-setairportpower', 'en0', 'off'],
						['networksetup', '-setbluetoothpower', 'off'],
						['networksetup', '-setwwanpowerstate', 'off']
					]
					
					for cmd in commands:
						await run_secure_command(cmd)
			
		except Exception as e:
			logger.error(f"Failed to apply countermeasures: {e}")
			raise

	def _get_critical_data(self) -> Optional[bytes]:
		"""Get critical data that needs encryption."""
		try:
			data = {
				'base_station_profiles': self.base_station_profiles,
				'signal_fingerprints': self.signal_fingerprints,
				'network_parameter_history': self.network_parameter_history,
				'traffic_patterns': self.traffic_patterns,
				'anomaly_scores': self.anomaly_scores
			}
			return json.dumps(data).encode()
		except Exception as e:
			logger.error(f"Failed to get critical data: {e}")
			return None

	def _store_encrypted_data(self, key_id: str, ciphertext: bytes, nonce: bytes, tag: bytes) -> None:
		"""Store encrypted data securely."""
		try:
			data = {
				'ciphertext': base64.b64encode(ciphertext).decode(),
				'nonce': base64.b64encode(nonce).decode(),
				'tag': base64.b64encode(tag).decode(),
				'timestamp': time.time()
			}
			
			# Store in memory for now, could be extended to secure storage
			if not hasattr(self, '_encrypted_data'):
				self._encrypted_data = {}
			self._encrypted_data[key_id] = data
			
		except Exception as e:
			logger.error(f"Failed to store encrypted data: {e}")

	def initialize_ml_model(self):
		try:
			from sklearn.ensemble import IsolationForest
			self.ml_model = IsolationForest(
				contamination=0.1,
				random_state=42,
				n_estimators=100
			)
		except ImportError:
			logger.warning("scikit-learn not available. ML-based detection disabled.")
			self.ml_model = None

	def analyze_traffic_patterns(self) -> List[str]:
		suspicious_patterns = []
		try:
			for conn in psutil.net_connections():
				if conn.status == 'ESTABLISHED':
					key = f"{conn.laddr.ip}:{conn.laddr.port}"
					if key not in self.traffic_patterns:
						self.traffic_patterns[key] = {
							'first_seen': time.time(),
							'packet_count': 0,
							'data_transferred': 0,
							'connections': set()
						}
					
					pattern = self.traffic_patterns[key]
					pattern['packet_count'] += 1
					
					if pattern['packet_count'] > 1000:
						suspicious_patterns.append('Excessive packet traffic')
					
					if len(pattern['connections']) > 5:
						suspicious_patterns.append('Multiple suspicious connections')
					
					pattern['connections'].add(f"{conn.raddr.ip}:{conn.raddr.port}")
			
			return suspicious_patterns
		except Exception as e:
			logger.error(f"Traffic pattern analysis failed: {e}")
			return []

	def detect_anomalies(self, cell_info: CellularInfo) -> List[str]:
		if not self.ml_model:
			return []
		
		try:
			features = [
				cell_info.signal_strength,
				cell_info.frequency,
				len(self.network_parameter_history),
				self.suspicious_parameter_changes
			]
			
			score = self.ml_model.score_samples([features])[0]
			self.anomaly_scores[time.time()] = score
			
			anomalies = []
			if score < -0.5:
				anomalies.append('ML-detected anomaly in network behavior')
			
			return anomalies
		except Exception as e:
			logger.error(f"Anomaly detection failed: {e}")
			return []

	def apply_geolocation_spoofing(self) -> bool:
		try:
			if not CURRENT_PLATFORM.startswith('DARWIN'):
				return False
			
			subprocess.run([
				'defaults', 'write',
				'/Library/Preferences/com.apple.locationd',
				'LocationServicesEnabled',
				'-bool', 'false'
			], check=True)
			
			subprocess.run(['killall', 'locationd'], check=True)
			
			subprocess.run([
				'networksetup',
				'-setairportpower',
				'en0',
				'off'
			], check=True)
			
			self.geolocation_spoofing = True
			return True
			
		except Exception as e:
			logger.error(f"Geolocation spoofing failed: {e}")
			return False

class USBMonitor:
	def __init__(self, settings: Settings):
		self.settings = settings
		self.platform = get_platform_utils()
		self.command_executor = SecureCommandExecutor()
		self.resource_manager = ResourceManager(settings.resource_limits)
		self.device_count = 0
		self.last_check = 0.0

	async def check_usb_devices(self) -> None:
		"""Check USB devices with proper error handling."""
		try:
			devices = self.platform.get_usb_devices()
			current_count = len(devices)
			
			if current_count != self.device_count:
				logger.info(f"USB device count changed: {self.device_count} -> {current_count}")
				self.device_count = current_count
				
				if current_count < self.device_count:
					await self.handle_usb_disconnect()
					
		except Exception as e:
			logger.error(f"Failed to check USB devices: {e}")

	async def handle_usb_disconnect(self) -> None:
		"""Handle USB disconnect with proper cleanup."""
		try:
			logger.warning("USB device disconnected!")
			
			# Sync filesystem
			await self.command_executor.run_command("sync")
			
			# Clean up resources
			self.resource_manager.cleanup_temp_files()
			self.resource_manager.cleanup_processes()
			
			# Check memory integrity
			if not await self.check_memory_integrity():
				logger.error("Memory integrity check failed!")
				
			# Create backup if enabled
			if self.settings.enable_backup:
				await self.create_backup()
				
		except Exception as e:
			logger.error(f"Failed to handle USB disconnect: {e}")

	async def check_memory_integrity(self) -> bool:
		"""Check memory integrity with proper error handling."""
		try:
			memory_info = self.platform.get_memory_info()
			if memory_info['used'] > self.settings.resource_limits.max_memory_mb * 1024 * 1024:
				logger.error("Memory usage exceeds limit!")
				return False
			return True
		except Exception as e:
			logger.error(f"Failed to check memory integrity: {e}")
			return False

	async def create_backup(self) -> None:
		"""Create backup with proper error handling."""
		try:
			if not os.path.exists(self.settings.backup_location):
				os.makedirs(self.settings.backup_location)
				
			timestamp = time.strftime("%Y%m%d_%H%M%S")
			backup_file = os.path.join(self.settings.backup_location, f"backup_{timestamp}.tar.gz")
			
			async with self.resource_manager.secure_file_operation(backup_file, 'w') as f:
				await self.command_executor.run_command(f"tar -czf {backup_file} .")
				
		except Exception as e:
			logger.error(f"Failed to create backup: {e}")

	async def monitor(self) -> None:
		"""Main monitoring loop with proper error handling."""
		try:
			while True:
				await self.check_usb_devices()
				await self.resource_manager.check_resources()
				await asyncio.sleep(self.settings.monitor_interval)
		except Exception as e:
			logger.error(f"Monitoring failed: {e}")
			sys.exit(1)

if __name__ == "__main__":
	asyncio.run(main())