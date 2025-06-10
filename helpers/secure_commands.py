#!/usr/bin/env python3

import subprocess
import shlex
import re
import logging
import platform
from typing import List, Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class CommandResult:
    success: bool
    output: str
    error: str
    exit_code: int

class CommandInjectionError(Exception):
    """Raised when command injection is detected."""
    pass

class CommandExecutionError(Exception):
    """Raised when command execution fails."""
    pass

class ResourceLimitError(Exception):
    """Raised when resource limits are exceeded."""
    pass

class SecureCommandExecutor:
    def __init__(self):
        self.platform = platform.system().lower()
        self._init_command_patterns()
        
    def _init_command_patterns(self):
        """Initialize platform-specific command patterns."""
        if self.platform == 'darwin':
            self.allowed_commands = {
                'networksetup': r'^networksetup\s+(-setairportpower|-setbluetoothpower|-setwwanpowerstate)\s+[a-zA-Z0-9]+\s+(on|off)$',
                'defaults': r'^defaults\s+write\s+/Library/Preferences/com\.apple\.locationd\s+LocationServicesEnabled\s+-bool\s+(true|false)$',
                'killall': r'^killall\s+[a-zA-Z0-9]+$',
                'system_profiler': r'^system_profiler\s+(SPUSBDataType|SPCellularDataType)$',
                'sync': r'^sync$',
                'shutdown': r'^shutdown\s+-h\s+now$'
            }
        elif self.platform == 'linux':
            self.allowed_commands = {
                'lsusb': r'^lsusb$',
                'sync': r'^sync$',
                'shutdown': r'^shutdown\s+-h\s+now$',
                'swapoff': r'^swapoff\s+-a$',
                'swapon': r'^swapon\s+-a$',
                'loginctl': r'^loginctl\s+lock-session$'
            }
        else:  # Windows
            self.allowed_commands = {
                'netstat': r'^netstat\s+-an$',
                'tasklist': r'^tasklist$',
                'shutdown': r'^shutdown\s+/s\s+/t\s+0$',
                'rundll32': r'^rundll32\.exe\s+user32\.dll,LockWorkStation$'
            }
            
    def sanitize_command(self, cmd: str) -> str:
        """Sanitize command to prevent injection attacks."""
        if not cmd:
            raise CommandInjectionError("Empty command")
            
        # Split command into parts
        parts = shlex.split(cmd)
        if not parts:
            raise CommandInjectionError("Invalid command")
            
        # Check if command is allowed
        command = parts[0]
        if command not in self.allowed_commands:
            raise CommandInjectionError(f"Command not allowed: {command}")
            
        # Validate command pattern
        pattern = self.allowed_commands[command]
        if not re.match(pattern, cmd):
            raise CommandInjectionError(f"Command pattern mismatch: {cmd}")
            
        return cmd
        
    async def run_command(self, cmd: str, timeout: int = 30) -> CommandResult:
        """Run a command with proper sanitization and error handling."""
        try:
            sanitized_cmd = self.sanitize_command(cmd)
            
            process = await asyncio.create_subprocess_exec(
                *shlex.split(sanitized_cmd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                raise CommandExecutionError(f"Command timed out: {cmd}")
                
            return CommandResult(
                success=process.returncode == 0,
                output=stdout.decode().strip(),
                error=stderr.decode().strip(),
                exit_code=process.returncode
            )
            
        except CommandInjectionError as e:
            logger.error(f"Command injection detected: {e}")
            raise
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise CommandExecutionError(f"Failed to execute command: {e}")
            
    def check_resource_limits(self) -> None:
        """Check if resource usage is within limits."""
        try:
            import psutil
            process = psutil.Process()
            
            # Check memory usage
            if process.memory_info().rss > 1024 * 1024 * 1024:  # 1GB
                raise ResourceLimitError("Memory usage exceeded limit")
                
            # Check CPU usage
            if process.cpu_percent() > 80:  # 80%
                raise ResourceLimitError("CPU usage exceeded limit")
                
            # Check open files
            if process.num_fds() > 100:  # 100 files
                raise ResourceLimitError("Too many open files")
                
        except ImportError:
            logger.warning("psutil not available, resource checks disabled")
        except Exception as e:
            logger.error(f"Resource limit check failed: {e}")
            raise ResourceLimitError(f"Resource check failed: {e}")
            
    async def run_secure_command(self, cmd: str, timeout: int = 30) -> CommandResult:
        """Run a command with resource checks and proper error handling."""
        self.check_resource_limits()
        return await self.run_command(cmd, timeout) 