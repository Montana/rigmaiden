#!/usr/bin/env python3

from rigmaiden import Rigmaiden
import platform
import os
import logging
import ctypes
import subprocess
import re
from typing import List, Dict, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class PlatformUtils(ABC):
    """Abstract base class for platform-specific utilities."""
    
    @abstractmethod
    def get_usb_devices(self) -> List[str]:
        """Get list of connected USB devices."""
        pass
        
    @abstractmethod
    def get_network_info(self) -> Dict[str, str]:
        """Get network interface information."""
        pass
        
    @abstractmethod
    def get_process_info(self) -> List[Dict[str, str]]:
        """Get running process information."""
        pass
        
    @abstractmethod
    def get_memory_info(self) -> Dict[str, int]:
        """Get memory usage information."""
        pass

class WindowsUtils(PlatformUtils):
    def get_usb_devices(self) -> List[str]:
        try:
            output = subprocess.check_output(['wmic', 'path', 'Win32_USBHub', 'get', 'DeviceID']).decode()
            devices = []
            for line in output.split('\n')[1:]:
                if line.strip():
                    devices.append(line.strip())
            return devices
        except Exception as e:
            logger.error(f"Failed to get USB devices on Windows: {e}")
            return []
            
    def get_network_info(self) -> Dict[str, str]:
        try:
            output = subprocess.check_output(['ipconfig', '/all']).decode()
            info = {}
            current_adapter = None
            
            for line in output.split('\n'):
                if 'adapter' in line.lower():
                    current_adapter = line.split(':')[0].strip()
                    info[current_adapter] = {}
                elif current_adapter and ':' in line:
                    key, value = line.split(':', 1)
                    info[current_adapter][key.strip()] = value.strip()
                    
            return info
        except Exception as e:
            logger.error(f"Failed to get network info on Windows: {e}")
            return {}
            
    def get_process_info(self) -> List[Dict[str, str]]:
        try:
            output = subprocess.check_output(['tasklist', '/v', '/fo', 'csv']).decode()
            processes = []
            
            for line in output.split('\n')[1:]:
                if line.strip():
                    parts = line.strip('"').split('","')
                    if len(parts) >= 8:
                        processes.append({
                            'name': parts[0],
                            'pid': parts[1],
                            'memory': parts[4],
                            'cpu_time': parts[7]
                        })
                        
            return processes
        except Exception as e:
            logger.error(f"Failed to get process info on Windows: {e}")
            return []
            
    def get_memory_info(self) -> Dict[str, int]:
        try:
            output = subprocess.check_output(['wmic', 'OS', 'get', 'FreePhysicalMemory,TotalVisibleMemorySize']).decode()
            lines = output.split('\n')[1:3]
            if len(lines) >= 2:
                free, total = map(int, lines[0].split())
                return {
                    'total': total * 1024,  # Convert KB to bytes
                    'free': free * 1024,
                    'used': (total - free) * 1024
                }
            return {}
        except Exception as e:
            logger.error(f"Failed to get memory info on Windows: {e}")
            return {}

class UnixUtils(PlatformUtils):
    def get_usb_devices(self) -> List[str]:
        try:
            output = subprocess.check_output(['lsusb']).decode()
            devices = []
            for line in output.split('\n'):
                if line.strip():
                    devices.append(line.strip())
            return devices
        except Exception as e:
            logger.error(f"Failed to get USB devices on Unix: {e}")
            return []
            
    def get_network_info(self) -> Dict[str, str]:
        try:
            output = subprocess.check_output(['ifconfig']).decode()
            info = {}
            current_adapter = None
            
            for line in output.split('\n'):
                if line and not line.startswith(' '):
                    current_adapter = line.split(':')[0]
                    info[current_adapter] = {}
                elif current_adapter and ':' in line:
                    key, value = line.split(':', 1)
                    info[current_adapter][key.strip()] = value.strip()
                    
            return info
        except Exception as e:
            logger.error(f"Failed to get network info on Unix: {e}")
            return {}
            
    def get_process_info(self) -> List[Dict[str, str]]:
        try:
            output = subprocess.check_output(['ps', '-eo', 'pid,ppid,cmd,%mem,%cpu']).decode()
            processes = []
            
            for line in output.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        processes.append({
                            'pid': parts[0],
                            'ppid': parts[1],
                            'cmd': ' '.join(parts[2:-2]),
                            'memory': parts[-2],
                            'cpu': parts[-1]
                        })
                        
            return processes
        except Exception as e:
            logger.error(f"Failed to get process info on Unix: {e}")
            return []
            
    def get_memory_info(self) -> Dict[str, int]:
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                
            info = {}
            for line in lines:
                if ':' in line:
                    key, value = line.split(':')
                    value = int(value.split()[0]) * 1024  # Convert KB to bytes
                    info[key.strip().lower()] = value
                    
            return {
                'total': info.get('memtotal', 0),
                'free': info.get('memfree', 0),
                'used': info.get('memtotal', 0) - info.get('memfree', 0)
            }
        except Exception as e:
            logger.error(f"Failed to get memory info on Unix: {e}")
            return {}

def get_platform_utils() -> PlatformUtils:
    """Get platform-specific utilities instance."""
    system = platform.system().lower()
    if system == 'windows':
        return WindowsUtils()
    else:
        return UnixUtils() 
