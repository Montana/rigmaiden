#!/usr/bin/env python3

from rigmaiden import Rigmaiden
import os
import psutil
import logging
import asyncio
import tempfile
import shutil
from typing import Optional, Dict, List
from dataclasses import dataclass
from contextlib import contextmanager

logger = logging.getLogger(__name__)

@dataclass
class ResourceLimits:
    max_memory_mb: int = 1024  # 1GB
    max_cpu_percent: int = 80
    max_file_size_mb: int = 100
    max_open_files: int = 100
    max_processes: int = 1000

class ResourceLimitError(Exception):
    """Raised when resource limits are exceeded."""
    pass

class ResourceManager:
    def __init__(self, limits: Optional[ResourceLimits] = None):
        self.limits = limits or ResourceLimits()
        self.temp_files: List[str] = []
        self.active_processes: List[int] = []
        
    def check_resources(self) -> None:
        """Check if resource usage is within limits."""
        try:
            process = psutil.Process()
            
            # Check memory usage
            memory_mb = process.memory_info().rss / (1024 * 1024)
            if memory_mb > self.limits.max_memory_mb:
                raise ResourceLimitError(f"Memory usage exceeded limit: {memory_mb:.2f}MB")
                
            # Check CPU usage
            cpu_percent = process.cpu_percent()
            if cpu_percent > self.limits.max_cpu_percent:
                raise ResourceLimitError(f"CPU usage exceeded limit: {cpu_percent}%")
                
            # Check open files
            num_files = process.num_fds()
            if num_files > self.limits.max_open_files:
                raise ResourceLimitError(f"Too many open files: {num_files}")
                
            # Check total processes
            num_processes = len(psutil.pids())
            if num_processes > self.limits.max_processes:
                raise ResourceLimitError(f"Too many processes: {num_processes}")
                
        except Exception as e:
            logger.error(f"Resource check failed: {e}")
            raise ResourceLimitError(f"Resource check failed: {e}")
            
    @contextmanager
    def secure_file_operation(self, filepath: str, mode: str = 'a+'):
        """Secure file operation with proper cleanup."""
        file = None
        try:
            # Check file size if it exists
            if os.path.exists(filepath):
                size_mb = os.path.getsize(filepath) / (1024 * 1024)
                if size_mb > self.limits.max_file_size_mb:
                    raise ResourceLimitError(f"File too large: {size_mb:.2f}MB")
                    
            file = open(filepath, mode)
            yield file
            
        except Exception as e:
            logger.error(f"File operation failed: {e}")
            raise
            
        finally:
            if file:
                try:
                    file.close()
                except Exception as e:
                    logger.error(f"Failed to close file: {e}")
                    
    def cleanup_temp_files(self) -> None:
        """Clean up temporary files."""
        for filepath in self.temp_files:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception as e:
                logger.error(f"Failed to remove temp file {filepath}: {e}")
        self.temp_files.clear()
        
    def cleanup_processes(self) -> None:
        """Clean up active processes."""
        for pid in self.active_processes:
            try:
                process = psutil.Process(pid)
                process.terminate()
            except psutil.NoSuchProcess:
                pass
            except Exception as e:
                logger.error(f"Failed to terminate process {pid}: {e}")
        self.active_processes.clear()
        
    async def monitor_resources(self, interval: float = 1.0) -> None:
        """Monitor system resources continuously."""
        while True:
            try:
                self.check_resources()
                await asyncio.sleep(interval)
            except ResourceLimitError as e:
                logger.error(f"Resource limit exceeded: {e}")
                self.cleanup_temp_files()
                self.cleanup_processes()
            except Exception as e:
                logger.error(f"Resource monitoring failed: {e}")
                await asyncio.sleep(interval)
                
    def create_temp_file(self, prefix: str = 'rigmaiden_', suffix: str = '.tmp') -> str:
        """Create a temporary file with proper cleanup."""
        try:
            fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
            os.close(fd)
            self.temp_files.append(path)
            return path
        except Exception as e:
            logger.error(f"Failed to create temp file: {e}")
            raise
            
    def register_process(self, pid: int) -> None:
        """Register a process for cleanup."""
        self.active_processes.append(pid)
        
    def unregister_process(self, pid: int) -> None:
        """Unregister a process from cleanup."""
        if pid in self.active_processes:
            self.active_processes.remove(pid)
            
    def get_resource_usage(self) -> Dict[str, float]:
        """Get current resource usage statistics."""
        try:
            process = psutil.Process()
            return {
                'memory_mb': process.memory_info().rss / (1024 * 1024),
                'cpu_percent': process.cpu_percent(),
                'open_files': process.num_fds(),
                'threads': process.num_threads(),
                'total_processes': len(psutil.pids())
            }
        except Exception as e:
            logger.error(f"Failed to get resource usage: {e}")
            return {} 
