from __future__ import annotations

import argparse
import array
import asyncio
import base64
import binascii
import configparser
import ctypes
import hashlib
import json
import logging
import mmap
import os
import platform
import queue
import re
import secrets
import shlex
import shutil
import signal
import socket
import sqlite3
import ssl
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from time import sleep, time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import psutil
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from utils import (
    CommandResult,
    KeyManager,
    ML_AVAILABLE,
    PlatformUtils,
    ResourceLimits,
    ResourceManager,
    SecureCommandExecutor,
    get_platform_utils,
)

__version__ = "1.0.0"

CURRENT_PLATFORM = platform.system().upper()

if CURRENT_PLATFORM.startswith("DARWIN"):
    import plistlib

DEVICE_RE = [re.compile(r".+ID\s(?P<id>\w+:\w+)"), re.compile(r"0x([0-9a-z]{4})")]

IOS_DEVICE_IDS = {
    "05ac": "Apple",
    "05ac:12a8": "iPhone",
    "05ac:12ab": "iPad",
    "05ac:12a9": "iPod",
    "05ac:12aa": "Apple Watch",
    "05ac:12ac": "Apple TV",
}

CELLEBRITE_PATTERNS = {
    "process_names": [
        "cellebrite",
        "ufed",
        "physical",
        "logical",
        "ufed4pc",
        "ufedphysical",
        "ufedlogical",
        "ufedreader",
        "ufed4pc",
        "ufed4pc.exe",
        "physicalanalyzer",
        "logicalanalyzer",
        "ufedphysicalanalyzer",
        "ufedlogicalanalyzer",
    ],
    "keywords": [
        "cellebrite",
        "ufed",
        "extraction",
        "forensic",
        "physical",
        "logical",
        "backup",
        "analyzer",
        "reader",
        "extractor",
        "forensics",
        "evidence",
        "investigation",
        "acquisition",
        "extraction",
    ],
    "ports": [8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089],
    "file_extensions": [
        ".ufd",
        ".ufdr",
        ".ufdx",
        ".ufd4pc",
        ".ufdphysical",
        ".ufdlogical",
        ".ufdreader",
        ".ufdanalyzer",
        ".ufdbackup",
        ".ufdextraction",
    ],
    "registry_keys": [
        "SOFTWARE\\Cellebrite",
        "SOFTWARE\\UFED",
        "SOFTWARE\\Physical Analyzer",
        "SOFTWARE\\Logical Analyzer",
    ],
}

JIGGLER_PATTERNS = {
    "keywords": [
        "jiggler",
        "mouse mover",
        "wiggler",
        "mousejiggle",
        "caffeine",
        "nosleep",
        "stayawake",
        "mousejiggler",
        "mousejiggle",
        "mousejiggler",
        "mousejiggle.exe",
        "jiggler.exe",
        "wiggler.exe",
        "caffeine.exe",
        "nosleep.exe",
        "stayawake.exe",
    ],
    "suspicious_processes": [
        "mousejiggle",
        "jiggler",
        "wiggler",
        "caffeine",
        "nosleep",
        "stayawake",
        "jiggler.exe",
        "wiggler.exe",
        "caffeine.exe",
        "nosleep.exe",
        "stayawake.exe",
    ],
    "suspicious_ports": [8080, 8081, 8082, 8083, 8084, 8085],
    "file_extensions": [
        ".exe",
        ".dll",
        ".sys",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".wsf",
        ".msi",
        ".inf",
        ".reg",
    ],
    "registry_keys": [
        "SOFTWARE\\MouseJiggle",
        "SOFTWARE\\Jiggler",
        "SOFTWARE\\Wiggler",
        "SOFTWARE\\Caffeine",
        "SOFTWARE\\NoSleep",
        "SOFTWARE\\StayAwake",
    ],
}

USB_PATTERNS = {
    "blocked_vendors": {
        "05ac",
        "0483",
        "0781",
        "0951",
        "0bda",
        "0cf3",
        "04f3",
        "046d",
        "045e",
        "0461",
        "0451",
        "0457",
        "04e8",
        "04b4",
        "04b3",
        "04b0",
        "04a9",
        "04a5",
    },
    "blocked_products": {
        "8600",
        "5740",
        "5583",
        "1666",
        "8176",
        "8179",
        "8178",
        "8177",
        "8176",
        "8175",
        "8174",
        "8173",
        "8172",
        "8171",
        "8170",
        "8169",
        "8168",
        "8167",
    },
    "suspicious_ports": {8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089},
    "suspicious_files": {
        ".exe",
        ".dll",
        ".sys",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".wsf",
        ".msi",
        ".inf",
        ".reg",
        ".ufd",
        ".ufdr",
        ".ufdx",
        ".ufd4pc",
        ".ufdphysical",
        ".ufdlogical",
        ".ufdreader",
        ".ufdanalyzer",
        ".ufdbackup",
    },
}

CFURL_CACHE_PATTERNS = {
    "cache_directories": [
        "/Library/Caches/com.apple.Safari",
        "/Library/Caches/com.apple.WebKit",
        "/Library/Caches/com.apple.WebKit.WebContent",
        "/Library/Caches/com.apple.WebKit.PluginProcess",
        "/Library/Caches/com.apple.WebKit.Networking",
        "/Library/Caches/com.apple.WebKit.WebContent.Development",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/Index.db",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-shm",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-wal",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-journal",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-tmp",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-lock",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-summary",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-uri",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-meta",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-index",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-cache",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-data",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-meta",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-cache",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-data",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-meta",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-cache",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-data-meta",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-data-cache",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-data-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-meta-cache",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-meta-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-cache-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-data-meta",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-data-cache",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-data-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-meta-cache",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-meta-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-cache-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-data-meta-cache",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-data-meta-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-data-cache-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-meta-cache-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-data-meta-cache",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-data-meta-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-data-cache-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-meta-cache-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-data-meta-cache-storage",
        "/Library/Caches/com.apple.WebKit.WebContent.Development/WebKitCache/WebKitCache.db-blob-index-data-meta-cache-storage",
    ],
    "suspicious_processes": [
        "cfurl_cache_response",
        "cfurl_cache_response.exe",
        "WebKitCache",
        "WebKitCache.exe",
        "WebKitCache.db",
        "Safari",
        "Safari.exe",
        "WebKit",
        "WebKit.exe",
        "WebKit.WebContent",
        "WebKit.WebContent.exe",
        "WebKit.PluginProcess",
        "WebKit.PluginProcess.exe",
        "WebKit.Networking",
        "WebKit.Networking.exe",
        "WebKit.WebContent.Development",
        "WebKit.WebContent.Development.exe",
    ],
    "suspicious_keywords": [
        "cfurl_cache_response",
        "WebKitCache",
        "WebKitCache.db",
        "WebKitCache.db-shm",
        "WebKitCache.db-wal",
        "WebKitCache.db-journal",
        "WebKitCache.db-tmp",
        "WebKitCache.db-lock",
        "WebKitCache.db-summary",
        "WebKitCache.db-uri",
        "WebKitCache.db-blob",
        "WebKitCache.db-meta",
        "WebKitCache.db-index",
        "WebKitCache.db-cache",
        "WebKitCache.db-storage",
        "WebKitCache.db-blob-index",
        "WebKitCache.db-blob-data",
        "WebKitCache.db-blob-meta",
        "WebKitCache.db-blob-cache",
        "WebKitCache.db-blob-storage",
        "WebKitCache.db-blob-index-data",
        "WebKitCache.db-blob-index-meta",
        "WebKitCache.db-blob-index-cache",
        "WebKitCache.db-blob-index-storage",
        "WebKitCache.db-blob-data-meta",
        "WebKitCache.db-blob-data-cache",
        "WebKitCache.db-blob-data-storage",
        "WebKitCache.db-blob-meta-cache",
        "WebKitCache.db-blob-meta-storage",
        "WebKitCache.db-blob-cache-storage",
        "WebKitCache.db-blob-index-data-meta",
        "WebKitCache.db-blob-index-data-cache",
        "WebKitCache.db-blob-index-data-storage",
        "WebKitCache.db-blob-index-meta-cache",
        "WebKitCache.db-blob-index-meta-storage",
        "WebKitCache.db-blob-index-cache-storage",
        "WebKitCache.db-blob-data-meta-cache",
        "WebKitCache.db-blob-data-meta-storage",
        "WebKitCache.db-blob-data-cache-storage",
        "WebKitCache.db-blob-meta-cache-storage",
        "WebKitCache.db-blob-index-data-meta-cache",
        "WebKitCache.db-blob-index-data-meta-storage",
        "WebKitCache.db-blob-index-data-cache-storage",
        "WebKitCache.db-blob-index-meta-cache-storage",
        "WebKitCache.db-blob-data-meta-cache-storage",
        "WebKitCache.db-blob-index-data-meta-cache-storage",
    ],
    "suspicious_ports": {8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089},
    "suspicious_files": {
        ".db",
        ".db-shm",
        ".db-wal",
        ".db-journal",
        ".db-tmp",
        ".db-lock",
        ".db-summary",
        ".db-uri",
        ".db-blob",
        ".db-meta",
        ".db-index",
        ".db-cache",
        ".db-storage",
        ".db-blob-index",
        ".db-blob-data",
        ".db-blob-meta",
        ".db-blob-cache",
        ".db-blob-storage",
        ".db-blob-index-data",
        ".db-blob-index-meta",
        ".db-blob-index-cache",
        ".db-blob-index-storage",
        ".db-blob-data-meta",
        ".db-blob-data-cache",
        ".db-blob-data-storage",
        ".db-blob-meta-cache",
        ".db-blob-meta-storage",
        ".db-blob-cache-storage",
        ".db-blob-index-data-meta",
        ".db-blob-index-data-cache",
        ".db-blob-index-data-storage",
        ".db-blob-index-meta-cache",
        ".db-blob-index-meta-storage",
        ".db-blob-index-cache-storage",
        ".db-blob-data-meta-cache",
        ".db-blob-data-meta-storage",
        ".db-blob-data-cache-storage",
        ".db-blob-meta-cache-storage",
        ".db-blob-index-data-meta-cache",
        ".db-blob-index-data-meta-storage",
        ".db-blob-index-data-cache-storage",
        ".db-blob-index-meta-cache-storage",
        ".db-blob-data-meta-cache-storage",
        ".db-blob-index-data-meta-cache-storage",
    },
    "registry_keys": [
        "SOFTWARE\\Apple Inc.\\Safari",
        "SOFTWARE\\Apple Inc.\\WebKit",
        "SOFTWARE\\Apple Inc.\\WebKit.WebContent",
        "SOFTWARE\\Apple Inc.\\WebKit.PluginProcess",
        "SOFTWARE\\Apple Inc.\\WebKit.Networking",
        "SOFTWARE\\Apple Inc.\\WebKit.WebContent.Development",
    ],
    "plist_files": [
        "/Library/Preferences/com.apple.Safari.plist",
        "/Library/Preferences/com.apple.WebKit.plist",
        "/Library/Preferences/com.apple.WebKit.WebContent.plist",
        "/Library/Preferences/com.apple.WebKit.PluginProcess.plist",
        "/Library/Preferences/com.apple.WebKit.Networking.plist",
        "/Library/Preferences/com.apple.WebKit.WebContent.Development.plist",
    ],
}

FUZZY_MODEL_PATTERNS = {
    "process_names": [
        "fuzzy",
        "fuzzymodel",
        "fuzzy_model",
        "fuzzymodel.exe",
        "fuzzy_model.exe",
        "fuzzycarver",
        "fuzzy_carver",
        "fuzzycarver.exe",
        "fuzzy_carver.exe",
        "database_carver",
        "databasecarver",
        "database_carver.exe",
        "databasecarver.exe",
        "comm_carver",
        "commcarver",
        "comm_carver.exe",
        "commcarver.exe",
        "location_carver",
        "locationcarver",
        "location_carver.exe",
        "locationcarver.exe",
        "user_carver",
        "usercarver",
        "user_carver.exe",
        "usercarver.exe",
        "forensic_carver",
        "forensiccarver",
        "forensic_carver.exe",
        "forensiccarver.exe",
        "data_carver",
        "datacarver",
        "data_carver.exe",
        "datacarver.exe",
        "extraction_tool",
        "extractiontool",
        "extraction_tool.exe",
        "extractiontool.exe",
        "parsing_tool",
        "parsingtool",
        "parsing_tool.exe",
        "parsingtool.exe",
        "manual_examination",
        "manualexamination",
        "manual_examination.exe",
        "manualexamination.exe",
    ],
    "keywords": [
        "fuzzy model",
        "fuzzy_model",
        "fuzzymodel",
        "database carving",
        "database_carving",
        "databasecarving",
        "communications carving",
        "communications_carving",
        "comm_carving",
        "commcarving",
        "user information",
        "user_information",
        "userinformation",
        "location data",
        "location_data",
        "locationdata",
        "location carving",
        "location_carving",
        "locationcarving",
        "manual examination",
        "manual_examination",
        "manualexamination",
        "parsing tool",
        "parsing_tool",
        "parsingtool",
        "extraction tool",
        "extraction_tool",
        "extractiontool",
        "forensic carving",
        "forensic_carving",
        "forensiccarving",
        "data carving",
        "data_carving",
        "datacarving",
        "carve database",
        "carve_database",
        "carvedatabase",
        "carve communications",
        "carve_communications",
        "carvecommunications",
        "carve location",
        "carve_location",
        "carvelocation",
        "carve user",
        "carve_user",
        "carveuser",
        "identify parsed",
        "identify_parsed",
        "identifyparsed",
        "left for manual",
        "left_for_manual",
        "leftformanual",
    ],
    "suspicious_ports": {
        8080,
        8081,
        8082,
        8083,
        8084,
        8085,
        8086,
        8087,
        8088,
        8089,
        9000,
        9001,
        9002,
        9003,
        9004,
        9005,
    },
    "file_extensions": [
        ".db",
        ".sqlite",
        ".sqlite3",
        ".db-shm",
        ".db-wal",
        ".db-journal",
        ".db-tmp",
        ".db-lock",
        ".db-summary",
        ".db-uri",
        ".db-blob",
        ".db-meta",
        ".db-index",
        ".db-cache",
        ".db-storage",
        ".carved",
        ".extracted",
        ".parsed",
        ".forensic",
        ".evidence",
        ".dump",
        ".raw",
        ".bin",
        ".dat",
        ".log",
        ".txt",
        ".csv",
        ".json",
        ".xml",
        ".html",
        ".htm",
        ".sql",
        ".sqlite-wal",
        ".sqlite-shm",
        ".sqlite-journal",
        ".sqlite-tmp",
        ".sqlite-lock",
        ".sqlite-summary",
        ".sqlite-uri",
        ".sqlite-blob",
        ".sqlite-meta",
        ".sqlite-index",
        ".sqlite-cache",
        ".sqlite-storage",
    ],
    "registry_keys": [
        "SOFTWARE\\FuzzyModel",
        "SOFTWARE\\Fuzzy Model",
        "SOFTWARE\\Database Carver",
        "SOFTWARE\\Communications Carver",
        "SOFTWARE\\Location Carver",
        "SOFTWARE\\User Carver",
        "SOFTWARE\\Forensic Carver",
        "SOFTWARE\\Data Carver",
        "SOFTWARE\\Extraction Tool",
        "SOFTWARE\\Parsing Tool",
        "SOFTWARE\\Manual Examination",
        "SOFTWARE\\Carving Tools",
        "SOFTWARE\\Forensic Tools",
        "SOFTWARE\\Evidence Tools",
    ],
    "plist_files": [
        "/Library/Preferences/com.fuzzymodel.plist",
        "/Library/Preferences/com.fuzzymodel.FuzzyModel.plist",
        "/Library/Preferences/com.fuzzymodel.DatabaseCarver.plist",
        "/Library/Preferences/com.fuzzymodel.CommunicationsCarver.plist",
        "/Library/Preferences/com.fuzzymodel.LocationCarver.plist",
        "/Library/Preferences/com.fuzzymodel.UserCarver.plist",
        "/Library/Preferences/com.fuzzymodel.ForensicCarver.plist",
        "/Library/Preferences/com.fuzzymodel.DataCarver.plist",
        "/Library/Preferences/com.fuzzymodel.ExtractionTool.plist",
        "/Library/Preferences/com.fuzzymodel.ParsingTool.plist",
        "/Library/Preferences/com.fuzzymodel.ManualExamination.plist",
    ],
    "cache_directories": [
        "/Library/Caches/com.fuzzymodel",
        "/Library/Caches/com.fuzzymodel.FuzzyModel",
        "/Library/Caches/com.fuzzymodel.DatabaseCarver",
        "/Library/Caches/com.fuzzymodel.CommunicationsCarver",
        "/Library/Caches/com.fuzzymodel.LocationCarver",
        "/Library/Caches/com.fuzzymodel.UserCarver",
        "/Library/Caches/com.fuzzymodel.ForensicCarver",
        "/Library/Caches/com.fuzzymodel.DataCarver",
        "/Library/Caches/com.fuzzymodel.ExtractionTool",
        "/Library/Caches/com.fuzzymodel.ParsingTool",
        "/Library/Caches/com.fuzzymodel.ManualExamination",
        "/var/cache/fuzzymodel",
        "/var/cache/database_carver",
        "/var/cache/communications_carver",
        "/var/cache/location_carver",
        "/var/cache/user_carver",
        "/var/cache/forensic_carver",
        "/var/cache/data_carver",
        "/var/cache/extraction_tool",
        "/var/cache/parsing_tool",
        "/var/cache/manual_examination",
    ],
    "data_directories": [
        "/var/lib/fuzzymodel",
        "/var/lib/database_carver",
        "/var/lib/communications_carver",
        "/var/lib/location_carver",
        "/var/lib/user_carver",
        "/var/lib/forensic_carver",
        "/var/lib/data_carver",
        "/var/lib/extraction_tool",
        "/var/lib/parsing_tool",
        "/var/lib/manual_examination",
        "/opt/fuzzymodel",
        "/opt/database_carver",
        "/opt/communications_carver",
        "/opt/location_carver",
        "/opt/user_carver",
        "/opt/forensic_carver",
        "/opt/data_carver",
        "/opt/extraction_tool",
        "/opt/parsing_tool",
        "/opt/manual_examination",
        "/usr/local/fuzzymodel",
        "/usr/local/database_carver",
        "/usr/local/communications_carver",
        "/usr/local/location_carver",
        "/usr/local/user_carver",
        "/usr/local/forensic_carver",
        "/usr/local/data_carver",
        "/usr/local/extraction_tool",
        "/usr/local/parsing_tool",
        "/usr/local/manual_examination",
    ],
    "suspicious_patterns": [
        "communications",
        "user information",
        "location data",
        "database carving",
        "manual examination",
        "parsing tool",
        "extraction tool",
        "forensic carving",
        "data carving",
        "carve database",
        "carve communications",
        "carve location",
        "carve user",
        "identify parsed",
        "left for manual",
    ],
}

ENCRYPTION_SETTINGS = {
    "salt_length": 16,
    "key_length": 32,
    "iterations": 100000,
    "algorithm": "AES-256-GCM",
    "tag_length": 16,
    "nonce_length": 12,
}

SECURITY_SETTINGS = {
    "max_retries": 3,
    "retry_delay": 5,
    "alert_threshold": 2,
    "backup_interval": 1800,
    "max_backups": 48,
    "check_interval": 0.5,
    "shred_passes": 3,
    "encryption_enabled": True,
    "network_blocking": True,
    "file_shredding": True,
    "process_killing": True,
    "registry_monitoring": True,
}

SETTINGS_FILE = "/etc/rigmaiden.ini"

DEFAULT_LOG_FILE = "/var/log/rigmaiden/kills.log"

USERNAME = os.getlogin()

CELLEBRITE_DB_PATH = (
    f"/Users/{USERNAME}/Library/Application Support/Knowledge/knowledgeC.db"
)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("/var/log/rigmaiden/rigmaiden.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger(__name__)

ENCRYPTION_KEY = Fernet.generate_key()

MEMORY_PROTECTION = {
    "PAGE_EXECUTE": 0x10,
    "PAGE_EXECUTE_READ": 0x20,
    "PAGE_EXECUTE_READWRITE": 0x40,
    "PAGE_EXECUTE_WRITECOPY": 0x80,
    "PAGE_NOACCESS": 0x01,
    "PAGE_READONLY": 0x02,
    "PAGE_READWRITE": 0x04,
    "PAGE_WRITECOPY": 0x08,
    "PAGE_GUARD": 0x100,
    "PAGE_NOCACHE": 0x200,
    "PAGE_WRITECOMBINE": 0x400,
}


@dataclass
class MemoryRegion:

    start: int

    size: int

    protection: int

    hash: str = field(default="")

    last_check: float = field(default=0.0)


class IMSEProtection:

    def __init__(self):

        self.protected_regions: List[MemoryRegion] = []

        self.memory_hashes: Dict[int, str] = {}

        self.suspicious_patterns: Set[bytes] = {
            b"\x90" * 16,
            b"\xcc" * 16,
            b"\xeb\xff",
            b"\xe8\x00\x00\x00\x00",
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
                    ctypes.byref(old_protect),
                )

                if result:

                    region = MemoryRegion(start, size, protection)

                    region.hash = self._calculate_region_hash(start, size)

                    self.protected_regions.append(region)

                    return True

            else:

                libc = ctypes.CDLL("libc.so.6")

                result = libc.mprotect(
                    ctypes.c_void_p(start), ctypes.c_size_t(size), protection
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
                    ctypes.byref(bytes_read),
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

                    logger.warning(
                        f"Memory integrity violation detected at {hex(region.start)}"
                    )

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
                            ctypes.byref(bytes_read),
                        ):

                            for pattern in self.suspicious_patterns:

                                if pattern in buffer:

                                    suspicious_found.append(
                                        (address + buffer.index(pattern), pattern)
                                    )

                    except:

                        pass

                    address += 4096

            else:

                with open("/proc/self/maps", "r") as f:

                    for line in f:

                        if "r-xp" in line:

                            start, end = map(
                                lambda x: int(x, 16), line.split()[0].split("-")
                            )

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
                            ctypes.byref(bytes_read),
                        ):

                            self.protect_memory_region(
                                address, 4096, MEMORY_PROTECTION["PAGE_EXECUTE_READ"]
                            )

                    except:

                        pass

                    address += 4096

            else:

                with open("/proc/self/maps", "r") as f:

                    for line in f:

                        if "r-xp" in line:

                            start, end = map(
                                lambda x: int(x, 16), line.split()[0].split("-")
                            )

                            self.protect_memory_region(
                                start,
                                end - start,
                                MEMORY_PROTECTION["PAGE_EXECUTE_READ"],
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

            if not CURRENT_PLATFORM.startswith("DARWIN"):

                return None

            output = subprocess.check_output(
                ["system_profiler", "SPCellularDataType"]
            ).decode()

            if "Cellular" not in output:

                return None

            mcc = int(re.search(r"MCC:\s*(\d+)", output).group(1))

            mnc = int(re.search(r"MNC:\s*(\d+)", output).group(1))

            cell_id = int(re.search(r"Cell ID:\s*(\d+)", output).group(1))

            lac = int(re.search(r"LAC:\s*(\d+)", output).group(1))

            signal = int(re.search(r"Signal Strength:\s*([-\d]+)", output).group(1))

            band = re.search(r"Band:\s*(\w+)", output).group(1)

            freq = int(re.search(r"Frequency:\s*(\d+)", output).group(1))

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

            logger.error(f"Failed to get cellular info: {e}")

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

            reasons.append("Unusual signal variance")

        if any(s > -30 for s in signals):

            reasons.append("Abnormally strong signals detected")

        signal_changes = [
            abs(signals[i] - signals[i - 1]) for i in range(1, len(signals))
        ]

        if any(change > 20 for change in signal_changes):

            reasons.append("Rapid signal strength changes")

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

                reasons.append("Unusually strong signal")

            if cell_info.cell_id in [0, 1, 65535]:

                suspicious = True

                reasons.append("Suspicious cell ID")

            if cell_info.lac in [0, 65535]:

                suspicious = True

                reasons.append("Suspicious location area code")

            freq_hopping = self.detect_frequency_hopping()

            if freq_hopping:

                suspicious = True

                reasons.append("Frequency hopping detected")

                self.frequency_hopping_detected = True

            signal_suspicious, signal_reasons = self.analyze_signal_patterns()

            if signal_suspicious:

                suspicious = True

                reasons.extend(signal_reasons)

            operator_key = f"{cell_info.mcc}:{cell_info.mnc}"

            if operator_key not in self.known_operators:

                self.known_operators.add(operator_key)

                if len(self.known_operators) > 2:

                    suspicious = True

                    reasons.append("Multiple operator changes detected")

            cell_key = f"{cell_info.mcc}:{cell_info.mnc}:{cell_info.cell_id}"

            if cell_key in self.known_cells:

                old_cell = self.known_cells[cell_key]

                if abs(old_cell.signal_strength - cell_info.signal_strength) > 20:

                    suspicious = True

                    reasons.append("Rapid signal strength change")

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

            logger.error(f"Stingray check failed: {e}")

            return False

    def _handle_suspicious_activity(
        self,
        current_time,
        reasons,
        cell_info,
        freq_hopping,
        signal_reasons,
    ):

        self.suspicious_events.append(
            {
                "timestamp": current_time,
                "reasons": reasons,
                "cell_info": cell_info,
                "frequency_hopping": freq_hopping,
                "signal_analysis": signal_reasons,
            }
        )

        recent_events = [
            e for e in self.suspicious_events if current_time - e["timestamp"] < 60
        ]

        if len(recent_events) >= self.alert_threshold:

            logger.warning("Potential Stingray device detected!")

            logger.warning(f"Reasons: {reasons}")

            if freq_hopping:

                logger.warning("Frequency hopping pattern detected!")

            if signal_reasons:

                logger.warning("Suspicious signal patterns detected!")

    def enable_airplane_mode(self):

        try:

            if not CURRENT_PLATFORM.startswith("DARWIN"):

                return False

            commands = [
                ["networksetup", "-setairportpower", "en0", "off"],
                ["networksetup", "-setbluetoothpower", "off"],
                ["networksetup", "-setwwanpowerstate", "off"],
                [
                    "defaults",
                    "write",
                    "/Library/Preferences/com.apple.locationd",
                    "LocationServicesEnabled",
                    "-bool",
                    "false",
                ],
                ["killall", "locationd"],
            ]

            for cmd in commands:

                subprocess.run(cmd, check=True)

            return True

        except Exception as e:

            logger.error(f"Failed to enable airplane mode: {e}")

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
class CFURLCacheInfo:

    url: str

    response_data: bytes

    cache_key: str

    timestamp: float

    content_type: str

    content_length: int

    headers: Dict[str, str]

    metadata: Dict[str, Any] = field(default_factory=dict)


class CFURLCacheProtection:
    """Protection against cfurl_cache_response exploitation and monitoring."""

    def __init__(self):

        self.cache_entries: Dict[str, CFURLCacheInfo] = {}

        self.suspicious_patterns: Set[bytes] = {
            b"cfurl_cache_response",
            b"WebKitCache",
            b"WebKitCache.db",
            b"communications",
            b"user information",
            b"location data",
        }

        self.check_interval: float = 1.0

        self.last_check: float = 0.0

        self.alert_threshold: int = 2

        self.suspicious_events: List[Dict] = []

        self.cache_monitoring_enabled: bool = True

        self.encryption_enabled: bool = True

        self.quarantine_enabled: bool = True

        self.logger = logging.getLogger(__name__)

    def scan_cache_directories(self) -> List[str]:
        """Scan for suspicious cache directories."""

        suspicious_found = []

        try:

            for cache_dir in CFURL_CACHE_PATTERNS["cache_directories"]:

                if os.path.exists(cache_dir):

                    suspicious_found.append(f"Found CFURL cache directory: {cache_dir}")

                    for root, dirs, files in os.walk(cache_dir):

                        for file in files:

                            file_path = os.path.join(root, file)

                            if any(
                                ext in file.lower()
                                for ext in CFURL_CACHE_PATTERNS["suspicious_files"]
                            ):

                                suspicious_found.append(
                                    f"Found suspicious cache file: {file_path}"
                                )

                                try:

                                    with open(file_path, "rb") as f:

                                        content = f.read(2048)
                                        if any(
                                            pattern in content
                                            for pattern in self.suspicious_patterns
                                        ):

                                            suspicious_found.append(
                                                f"Suspicious content in cache file: {file_path}"
                                            )

                                except Exception as e:

                                    self.logger.error(
                                        f"Failed to read cache file {file_path}: {e}"
                                    )

        except Exception as e:

            self.logger.error(f"CFURL cache directory scan failed: {e}")

        return suspicious_found

    def check_cache_processes(self) -> List[str]:
        """Check for suspicious cache-related processes."""

        suspicious_found = []

        try:

            for proc in psutil.process_iter(["name", "cmdline", "open_files"]):

                try:

                    name = proc.info["name"] or ""

                    cmdline = (
                        " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""
                    )

                    if any(
                        pattern.lower() in name.lower()
                        for pattern in CFURL_CACHE_PATTERNS["suspicious_processes"]
                    ):

                        suspicious_found.append(
                            f"Suspicious cache process: {name} (PID: {proc.pid})"
                        )

                    if any(
                        keyword.lower() in cmdline.lower()
                        for keyword in CFURL_CACHE_PATTERNS["suspicious_keywords"]
                    ):

                        suspicious_found.append(
                            f"Suspicious cache activity in process: {name} (PID: {proc.pid})"
                        )

                    for file in proc.info["open_files"]:

                        if any(
                            ext in file.path.lower()
                            for ext in CFURL_CACHE_PATTERNS["suspicious_files"]
                        ):

                            suspicious_found.append(
                                f"Cache file access by process: {name} (PID: {proc.pid}) -> {file.path}"
                            )

                except (psutil.NoSuchProcess, psutil.AccessDenied):

                    continue

        except Exception as e:

            self.logger.error(f"CFURL cache process check failed: {e}")

        return suspicious_found

    def check_cache_network_activity(self) -> List[str]:
        """Check for suspicious network activity related to cache."""

        suspicious_found = []

        try:

            for conn in psutil.net_connections():

                if conn.laddr.port in CFURL_CACHE_PATTERNS["suspicious_ports"]:

                    suspicious_found.append(
                        f"Suspicious cache network activity on port: {conn.laddr.port}"
                    )

        except Exception as e:

            self.logger.error(f"CFURL cache network activity check failed: {e}")

        return suspicious_found

    def check_registry_cache_keys(self) -> List[str]:
        """Check for suspicious registry keys related to cache (Windows only)."""

        suspicious_found = []

        if CURRENT_PLATFORM.startswith("WIN"):

            try:

                for key in CFURL_CACHE_PATTERNS["registry_keys"]:

                    result = subprocess.run(
                        ["reg", "query", key], capture_output=True, text=True
                    )

                    if result.returncode == 0:

                        suspicious_found.append(f"Found cache registry key: {key}")

            except Exception as e:

                self.logger.error(f"CFURL cache registry check failed: {e}")

        return suspicious_found

    def check_plist_cache_files(self) -> List[str]:
        """Check for suspicious plist files related to cache (macOS only)."""

        suspicious_found = []

        if CURRENT_PLATFORM.startswith("DARWIN"):

            try:

                for plist_file in CFURL_CACHE_PATTERNS["plist_files"]:

                    if os.path.exists(plist_file):

                        suspicious_found.append(f"Found cache plist file: {plist_file}")

                        try:

                            with open(plist_file, "rb") as f:

                                plist_data = plistlib.load(f)

                                if self._analyze_plist_content(plist_data):

                                    suspicious_found.append(
                                        f"Suspicious content in cache plist: {plist_file}"
                                    )

                        except Exception as e:

                            self.logger.error(
                                f"Failed to parse cache plist {plist_file}: {e}"
                            )

            except Exception as e:

                self.logger.error(f"CFURL cache plist check failed: {e}")

        return suspicious_found

    def _analyze_plist_content(self, plist_data: Any) -> bool:
        """Analyze plist content for suspicious patterns."""

        try:

            plist_str = str(plist_data).lower()

            return any(
                keyword.lower() in plist_str
                for keyword in CFURL_CACHE_PATTERNS["suspicious_keywords"]
            )

        except Exception as e:

            self.logger.error(f"CFURL cache plist content analysis failed: {e}")

            return False

    def encrypt_cache_data(self, data: bytes) -> bytes:
        """Encrypt cache data to prevent unauthorized access."""

        try:

            if not self.encryption_enabled:

                return data

            key = os.urandom(32)

            nonce = os.urandom(12)

            cipher = Cipher(
                algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
            )

            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(data) + encryptor.finalize()

            metadata = {
                "key": base64.b64encode(key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "tag": base64.b64encode(encryptor.tag).decode(),
                "timestamp": time.time(),
                "type": "cache_data",
            }

            return json.dumps(metadata).encode() + b"|||" + ciphertext

        except Exception as e:

            self.logger.error(f"Cache data encryption failed: {e}")

            return data

    def decrypt_cache_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt cache data."""

        try:

            if not self.encryption_enabled:

                return encrypted_data

            if b"|||" not in encrypted_data:

                return encrypted_data

            metadata_str, ciphertext = encrypted_data.split(b"|||", 1)

            metadata = json.loads(metadata_str.decode())

            key = base64.b64decode(metadata["key"])

            nonce = base64.b64decode(metadata["nonce"])

            tag = base64.b64decode(metadata["tag"])

            cipher = Cipher(
                algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
            )

            decryptor = cipher.decryptor()

            return decryptor.update(ciphertext) + decryptor.finalize()

        except Exception as e:

            self.logger.error(f"Cache data decryption failed: {e}")

            return encrypted_data

    def quarantine_cache_file(self, file_path: str) -> bool:
        """Quarantine suspicious cache file."""

        try:

            if not self.quarantine_enabled:

                return False

            quarantine_dir = Path("./quarantine/cache")

            quarantine_dir.mkdir(parents=True, exist_ok=True)

            file_path_obj = Path(file_path)

            quarantine_path = (
                quarantine_dir / f"cache_{int(time.time())}_{file_path_obj.name}"
            )

            with open(file_path, "rb") as f:

                data = f.read()

            encrypted_data = self.encrypt_cache_data(data)

            with open(quarantine_path, "wb") as f:

                f.write(encrypted_data)

            file_path_obj.unlink()

            self.logger.info(
                f"Quarantined cache file: {file_path} -> {quarantine_path}"
            )

            return True

        except Exception as e:

            self.logger.error(f"Failed to quarantine cache file {file_path}: {e}")

            return False

    def clear_cache_directories(self) -> bool:
        """Clear all cache directories to prevent data exfiltration."""

        try:

            cleared_count = 0

            for cache_dir in CFURL_CACHE_PATTERNS["cache_directories"]:

                if os.path.exists(cache_dir):

                    try:

                        shutil.rmtree(cache_dir)

                        cleared_count += 1

                        self.logger.info(f"Cleared cache directory: {cache_dir}")

                    except Exception as e:

                        self.logger.error(
                            f"Failed to clear cache directory {cache_dir}: {e}"
                        )

            return cleared_count > 0

        except Exception as e:

            self.logger.error(f"Cache directory clearing failed: {e}")

            return False

    def check_for_cache_exploitation(self) -> Dict[str, List[str]]:
        """Comprehensive check for cache exploitation."""

        try:

            current_time = time.time()

            if current_time - self.last_check < self.check_interval:

                return {"suspicious": [], "warnings": []}

            suspicious_found = []

            warnings = []

            dir_suspicious = self.scan_cache_directories()

            suspicious_found.extend(dir_suspicious)

            process_suspicious = self.check_cache_processes()

            suspicious_found.extend(process_suspicious)

            network_suspicious = self.check_cache_network_activity()

            suspicious_found.extend(network_suspicious)

            registry_suspicious = self.check_registry_cache_keys()

            suspicious_found.extend(registry_suspicious)

            plist_suspicious = self.check_plist_cache_files()

            suspicious_found.extend(plist_suspicious)

            if suspicious_found:

                self._handle_suspicious_cache_activity(suspicious_found)

                if len(suspicious_found) >= self.alert_threshold:

                    warnings.append(
                        "High number of suspicious cache activities detected!"
                    )

            self.last_check = current_time

            return {"suspicious": suspicious_found, "warnings": warnings}

        except Exception as e:

            self.logger.error(f"Cache exploitation check failed: {e}")

            return {"suspicious": [], "warnings": [f"Cache check failed: {e}"]}

    def _handle_suspicious_cache_activity(self, suspicious_items: List[str]) -> None:
        """Handle suspicious cache activity."""

        try:

            current_time = time.time()

            for item in suspicious_items:

                self.logger.warning(f"Suspicious cache activity: {item}")

            self.suspicious_events.append(
                {
                    "timestamp": current_time,
                    "items": suspicious_items,
                    "count": len(suspicious_items),
                }
            )

            if len(self.suspicious_events) > 100:

                self.suspicious_events = self.suspicious_events[-100:]

            recent_events = [
                e for e in self.suspicious_events if current_time - e["timestamp"] < 300
            ]

            if len(recent_events) >= self.alert_threshold:

                self.logger.critical(
                    "Cache exploitation detected! Taking countermeasures..."
                )

                if self.clear_cache_directories():

                    self.logger.info("Cache directories cleared")

                for item in suspicious_items:

                    if (
                        "cache file:" in item
                        or "suspicious content in cache file:" in item
                    ):

                        file_path = item.split(": ")[1]

                        if self.quarantine_cache_file(file_path):

                            self.logger.info(
                                f"Quarantined suspicious cache file: {file_path}"
                            )

        except Exception as e:

            self.logger.error(f"Failed to handle suspicious cache activity: {e}")

    def get_cache_statistics(self) -> Dict[str, Any]:
        """Get cache protection statistics."""

        return {
            "cache_entries_count": len(self.cache_entries),
            "suspicious_events_count": len(self.suspicious_events),
            "last_check": self.last_check,
            "cache_monitoring_enabled": self.cache_monitoring_enabled,
            "encryption_enabled": self.encryption_enabled,
            "quarantine_enabled": self.quarantine_enabled,
            "recent_suspicious_events": [
                e for e in self.suspicious_events if time.time() - e["timestamp"] < 3600
            ],
        }


class FuzzyModelProtection:
    """Protection against The Fuzzy Model plug-in and database carving tools."""

    def __init__(self):

        self.carved_databases: Dict[str, Dict] = {}

        self.suspicious_patterns: Set[bytes] = {
            b"communications",
            b"user information",
            b"location data",
            b"database carving",
            b"manual examination",
            b"parsing tool",
            b"extraction tool",
            b"forensic carving",
            b"data carving",
            b"carve database",
            b"carve communications",
            b"carve location",
            b"carve user",
            b"identify parsed",
            b"left for manual",
            b"fuzzy model",
            b"fuzzy_model",
            b"fuzzymodel",
        }

        self.check_interval: float = 1.0

        self.last_check: float = 0.0

        self.alert_threshold: int = 2

        self.suspicious_events: List[Dict] = []

        self.carving_monitoring_enabled: bool = True

        self.encryption_enabled: bool = True

        self.quarantine_enabled: bool = True

        self.logger = logging.getLogger(__name__)

    def scan_fuzzy_model_directories(self) -> List[str]:
        """Scan for Fuzzy Model directories and files."""

        suspicious_found = []

        try:

            for cache_dir in FUZZY_MODEL_PATTERNS["cache_directories"]:

                if os.path.exists(cache_dir):

                    suspicious_found.append(
                        f"Found Fuzzy Model cache directory: {cache_dir}"
                    )

                    for root, dirs, files in os.walk(cache_dir):

                        for file in files:

                            file_path = os.path.join(root, file)

                            if any(
                                ext in file.lower()
                                for ext in FUZZY_MODEL_PATTERNS["file_extensions"]
                            ):

                                suspicious_found.append(
                                    f"Found suspicious carving file: {file_path}"
                                )
                                try:
                                    with open(file_path, "rb") as f:
                                        content = f.read(2048)
                                        if any(
                                            pattern in content
                                            for pattern in self.suspicious_patterns
                                        ):
                                            suspicious_found.append(
                                                f"Suspicious content in carving file: {file_path}"
                                            )
                                except Exception as e:
                                    self.logger.error(
                                        f"Failed to read carving file {file_path}: {e}"
                                    )
            for data_dir in FUZZY_MODEL_PATTERNS["data_directories"]:
                if os.path.exists(data_dir):
                    suspicious_found.append(
                        f"Found Fuzzy Model data directory: {data_dir}"
                    )
                    for root, dirs, files in os.walk(data_dir):
                        for file in files:
                            file_path = os.path.join(root, file)
                            if any(
                                ext in file.lower()
                                for ext in [".db", ".sqlite", ".sqlite3"]
                            ):

                                suspicious_found.append(
                                    f"Found database file: {file_path}"
                                )
                                if self._is_carved_database(file_path):
                                    suspicious_found.append(
                                        f"Found carved database: {file_path}"
                                    )
        except Exception as e:
            self.logger.error(f"Fuzzy Model directory scan failed: {e}")
        return suspicious_found

    def check_fuzzy_model_processes(self) -> List[str]:
        """Check for Fuzzy Model and carving processes."""
        suspicious_found = []
        try:
            for proc in psutil.process_iter(["name", "cmdline", "open_files"]):
                try:
                    name = proc.info["name"] or ""
                    cmdline = (
                        " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""
                    )
                    if any(
                        pattern.lower() in name.lower()
                        for pattern in FUZZY_MODEL_PATTERNS["process_names"]
                    ):
                        suspicious_found.append(
                            f"Suspicious carving process: {name} (PID: {proc.pid})"
                        )
                    if any(
                        keyword.lower() in cmdline.lower()
                        for keyword in FUZZY_MODEL_PATTERNS["keywords"]
                    ):
                        suspicious_found.append(
                            f"Suspicious carving activity in process: {name} (PID: {proc.pid})"
                        )
                    for file in proc.info["open_files"]:
                        if any(
                            ext in file.path.lower()
                            for ext in FUZZY_MODEL_PATTERNS["file_extensions"]
                        ):
                            suspicious_found.append(
                                f"Carving file access by process: {name} (PID: {proc.pid}) -> {file.path}"
                            )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.logger.error(f"Fuzzy Model process check failed: {e}")
        return suspicious_found

    def check_fuzzy_model_network_activity(self) -> List[str]:
        """Check for suspicious network activity related to carving."""
        suspicious_found = []
        try:
            for conn in psutil.net_connections():
                if conn.laddr.port in FUZZY_MODEL_PATTERNS["suspicious_ports"]:
                    suspicious_found.append(
                        f"Suspicious carving network activity on port: {conn.laddr.port}"
                    )
        except Exception as e:
            self.logger.error(f"Fuzzy Model network activity check failed: {e}")
        return suspicious_found

    def check_registry_fuzzy_model_keys(self) -> List[str]:
        """Check for suspicious registry keys related to Fuzzy Model (Windows only)."""
        suspicious_found = []
        if CURRENT_PLATFORM.startswith("WIN"):
            try:
                for key in FUZZY_MODEL_PATTERNS["registry_keys"]:
                    result = subprocess.run(
                        ["reg", "query", key], capture_output=True, text=True
                    )
                    if result.returncode == 0:
                        suspicious_found.append(
                            f"Found Fuzzy Model registry key: {key}"
                        )
            except Exception as e:
                self.logger.error(f"Fuzzy Model registry check failed: {e}")
        return suspicious_found

    def check_plist_fuzzy_model_files(self) -> List[str]:
        """Check for suspicious plist files related to Fuzzy Model (macOS only)."""
        suspicious_found = []
        if CURRENT_PLATFORM.startswith("DARWIN"):
            try:
                for plist_file in FUZZY_MODEL_PATTERNS["plist_files"]:
                    if os.path.exists(plist_file):
                        suspicious_found.append(
                            f"Found Fuzzy Model plist file: {plist_file}"
                        )
                        try:
                            with open(plist_file, "rb") as f:
                                plist_data = plistlib.load(f)
                                if self._analyze_plist_content(plist_data):
                                    suspicious_found.append(
                                        f"Suspicious content in Fuzzy Model plist: {plist_file}"
                                    )
                        except Exception as e:
                            self.logger.error(
                                f"Failed to parse Fuzzy Model plist {plist_file}: {e}"
                            )
            except Exception as e:
                self.logger.error(f"Fuzzy Model plist check failed: {e}")
        return suspicious_found

    def _analyze_plist_content(self, plist_data: Any) -> bool:
        """Analyze plist content for suspicious patterns."""
        try:
            plist_str = str(plist_data).lower()
            return any(
                keyword.lower() in plist_str
                for keyword in FUZZY_MODEL_PATTERNS["suspicious_keywords"]
            )
        except Exception as e:
            self.logger.error(f"Fuzzy Model plist content analysis failed: {e}")
            return False

    def _is_carved_database(self, file_path: str) -> bool:
        """Check if a database file appears to be carved."""
        try:
            if os.path.getsize(file_path) > 100 * 1024 * 1024:
                return True
            with open(file_path, "rb") as f:
                content = f.read(1024)
                if any(pattern in content for pattern in self.suspicious_patterns):
                    return True
            file_name = os.path.basename(file_path).lower()
            if any(
                indicator in file_name
                for indicator in [
                    "carved",
                    "extracted",
                    "parsed",
                    "forensic",
                    "evidence",
                ]
            ):

                return True

            return False

        except Exception as e:

            self.logger.error(f"Failed to check if database is carved: {e}")

            return False

    def encrypt_carved_data(self, data: bytes) -> bytes:
        """Encrypt carved data to prevent unauthorized access."""

        try:

            if not self.encryption_enabled:

                return data

            key = os.urandom(32)

            nonce = os.urandom(12)

            cipher = Cipher(
                algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
            )

            encryptor = cipher.encryptor()

            ciphertext = encryptor.update(data) + encryptor.finalize()

            metadata = {
                "key": base64.b64encode(key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "tag": base64.b64encode(encryptor.tag).decode(),
                "timestamp": time.time(),
                "type": "carved_data",
            }

            return json.dumps(metadata).encode() + b"|||" + ciphertext

        except Exception as e:

            self.logger.error(f"Carved data encryption failed: {e}")

            return data

    def decrypt_carved_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt carved data."""
        try:
            if not self.encryption_enabled:
                return encrypted_data
            if b"|||" not in encrypted_data:
                return encrypted_data
            metadata_str, ciphertext = encrypted_data.split(b"|||", 1)
            metadata = json.loads(metadata_str.decode())
            key = base64.b64decode(metadata["key"])
            nonce = base64.b64decode(metadata["nonce"])
            tag = base64.b64decode(metadata["tag"])
            cipher = Cipher(
                algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            self.logger.error(f"Carved data decryption failed: {e}")
            return encrypted_data

    def quarantine_carved_file(self, file_path: str) -> bool:
        """Quarantine suspicious carved file."""
        try:
            if not self.quarantine_enabled:
                return False
            quarantine_dir = Path("./quarantine/carved")
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            file_path_obj = Path(file_path)
            quarantine_path = (
                quarantine_dir / f"carved_{int(time.time())}_{file_path_obj.name}"
            )
            with open(file_path, "rb") as f:
                data = f.read()
            encrypted_data = self.encrypt_carved_data(data)
            with open(quarantine_path, "wb") as f:
                f.write(encrypted_data)
            file_path_obj.unlink()
            self.logger.info(
                f"Quarantined carved file: {file_path} -> {quarantine_path}"
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to quarantine carved file {file_path}: {e}")
            return False

    def clear_carving_directories(self) -> bool:
        """Clear all carving directories to prevent data exfiltration."""
        try:
            cleared_count = 0
            for cache_dir in FUZZY_MODEL_PATTERNS["cache_directories"]:
                if os.path.exists(cache_dir):
                    try:
                        shutil.rmtree(cache_dir)
                        cleared_count += 1
                        self.logger.info(
                            f"Cleared Fuzzy Model cache directory: {cache_dir}"
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Failed to clear cache directory {cache_dir}: {e}"
                        )
            for data_dir in FUZZY_MODEL_PATTERNS["data_directories"]:
                if os.path.exists(data_dir):
                    try:
                        shutil.rmtree(data_dir)
                        cleared_count += 1
                        self.logger.info(
                            f"Cleared Fuzzy Model data directory: {data_dir}"
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Failed to clear data directory {data_dir}: {e}"
                        )
            return cleared_count > 0
        except Exception as e:
            self.logger.error(f"Fuzzy Model directory clearing failed: {e}")
            return False

    def check_for_fuzzy_model_exploitation(self) -> Dict[str, List[str]]:
        """Comprehensive check for Fuzzy Model exploitation."""
        try:
            current_time = time.time()
            if current_time - self.last_check < self.check_interval:
                return {"suspicious": [], "warnings": []}
            suspicious_found = []
            warnings = []
            dir_suspicious = self.scan_fuzzy_model_directories()
            suspicious_found.extend(dir_suspicious)
            process_suspicious = self.check_fuzzy_model_processes()
            suspicious_found.extend(process_suspicious)
            network_suspicious = self.check_fuzzy_model_network_activity()
            suspicious_found.extend(network_suspicious)
            registry_suspicious = self.check_registry_fuzzy_model_keys()
            suspicious_found.extend(registry_suspicious)
            plist_suspicious = self.check_plist_fuzzy_model_files()
            suspicious_found.extend(plist_suspicious)
            if suspicious_found:
                self._handle_suspicious_carving_activity(suspicious_found)
                if len(suspicious_found) >= self.alert_threshold:
                    warnings.append(
                        "High number of suspicious carving activities detected!"
                    )
            self.last_check = current_time
            return {"suspicious": suspicious_found, "warnings": warnings}
        except Exception as e:
            self.logger.error(f"Fuzzy Model exploitation check failed: {e}")
            return {"suspicious": [], "warnings": [f"Fuzzy Model check failed: {e}"]}

    def _handle_suspicious_carving_activity(self, suspicious_items: List[str]) -> None:
        """Handle suspicious carving activity."""
        try:

            current_time = time.time()

            for item in suspicious_items:

                self.logger.warning(f"Suspicious carving activity: {item}")

            self.suspicious_events.append(
                {
                    "timestamp": current_time,
                    "items": suspicious_items,
                    "count": len(suspicious_items),
                }
            )

            if len(self.suspicious_events) > 100:

                self.suspicious_events = self.suspicious_events[-100:]

            recent_events = [
                e for e in self.suspicious_events if current_time - e["timestamp"] < 300
            ]

            if len(recent_events) >= self.alert_threshold:

                self.logger.critical(
                    "Fuzzy Model exploitation detected! Taking countermeasures..."
                )

                if self.clear_carving_directories():

                    self.logger.info("Carving directories cleared")

                for item in suspicious_items:

                    if (
                        "carving file:" in item
                        or "database file:" in item
                        or "carved database:" in item
                    ):

                        file_path = item.split(": ")[1]

                        if self.quarantine_carved_file(file_path):

                            self.logger.info(
                                f"Quarantined suspicious carved file: {file_path}"
                            )

        except Exception as e:

            self.logger.error(f"Failed to handle suspicious carving activity: {e}")

    def get_carving_statistics(self) -> Dict[str, Any]:
        """Get Fuzzy Model protection statistics."""

        return {
            "carved_databases_count": len(self.carved_databases),
            "suspicious_events_count": len(self.suspicious_events),
            "last_check": self.last_check,
            "carving_monitoring_enabled": self.carving_monitoring_enabled,
            "encryption_enabled": self.encryption_enabled,
            "quarantine_enabled": self.quarantine_enabled,
            "recent_suspicious_events": [
                e for e in self.suspicious_events if time.time() - e["timestamp"] < 3600
            ],
        }


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
    check_cfurl_cache: bool = True
    check_fuzzy_model: bool = True
    check_interval: float = 0.5
    backup_interval: int = 1800
    max_backups: int = 48
    alert_threshold: int = 2
    do_backup: bool = True
    do_monitor: bool = True
    do_cleanup: bool = True
    backup_location: str = "/var/backups/rigmaiden"
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
    security_level: str = "LOW"
    notify_only: bool = True
    backup_enabled: bool = True
    quarantine_enabled: bool = True
    quarantine_location: str = "./quarantine"
    system_lock_enabled: bool = True
    network_block_enabled: bool = True
    memory_protection_enabled: bool = True
    file_monitoring_enabled: bool = True
    process_monitoring_enabled: bool = True
    device_monitoring_enabled: bool = True
    suspicious_patterns: Dict = field(default_factory=dict)
    custom_actions: Dict = field(default_factory=dict)
    resource_limits: Dict = field(
        default_factory=lambda: {
            "max_memory_mb": 1024,
            "max_cpu_percent": 80,
            "max_disk_usage_mb": 10240,
            "max_open_files": 100,
            "max_processes": 1000,
        }
    )
    scan_intervals: Dict = field(
        default_factory=lambda: {
            "usb": 2.0,
            "cellular": 5.0,
            "process": 10.0,
            "resource": 30.0,
            "cache": 5.0,
        }
    )
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
        if not hasattr(self, "safe_mode"):
            self.safe_mode = True
        if not hasattr(self, "dry_run"):
            self.dry_run = False
        if self.security_level == "HIGH":
            self.safe_mode = False
            self.dry_run = False
            self.notify_only = False
            self.max_retries = 10
            self.retry_delay = 1
        elif self.security_level == "MEDIUM":
            self.safe_mode = True
            self.dry_run = False
            self.notify_only = False
            self.max_retries = 5
            self.retry_delay = 3
        else:
            self.safe_mode = True
            self.dry_run = True
            self.notify_only = True
            self.max_retries = 3
            self.retry_delay = 5

    @classmethod
    def from_config(cls, config: Dict) -> "Settings":
        """Create a Settings instance from a config dictionary."""
        return cls(
            sleep_time=config.get("sleep_time", 0.5),
            whitelist=set(config.get("whitelist", [])),
            log_file=config.get("log_file", DEFAULT_LOG_FILE),
            remove_file_cmd=config.get("remove_file_cmd", ""),
            melt_usbkill=config.get("melt_usbkill", False),
            folders_to_remove=config.get("folders_to_remove", []),
            files_to_remove=config.get("files_to_remove", []),
            kill_commands=config.get("kill_commands", []),
            do_sync=config.get("do_sync", True),
            do_wipe_ram=config.get("do_wipe_ram", True),
            do_wipe_swap=config.get("do_wipe_swap", True),
            wipe_ram_cmd=config.get("wipe_ram_cmd", ""),
            wipe_swap_cmd=config.get("wipe_swap_cmd", ""),
            shut_down=config.get("shut_down", False),
            check_jiggler=config.get("check_jiggler", True),
            check_cellebrite=config.get("check_cellebrite", True),
            block_ios_access=config.get("block_ios_access", True),
            safe_mode=config.get("safe_mode", True),
            dry_run=config.get("dry_run", False),
        )


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


MAX_MEMORY_USAGE = 1024 * 1024 * 1024
MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_PROCESS_COUNT = 1000

MAX_OPEN_FILES = 100


def sanitize_command(cmd: Union[str, List[str]]) -> List[str]:
    """Sanitize command to prevent injection attacks."""

    if isinstance(cmd, str):

        cmd = shlex.split(cmd)

    sanitized = []

    for arg in cmd:

        if any(
            c in arg for c in [";", "|", "&", ">", "<", "`", "$", "(", ")", "{", "}"]
        ):

            raise CommandInjectionError(
                f"Potentially dangerous command argument: {arg}"
            )

        sanitized.append(arg)

    return sanitized


def check_resource_limits() -> None:
    """Check if resource usage is within limits."""

    try:

        process = psutil.Process()

        if process.memory_info().rss > MAX_MEMORY_USAGE:

            raise ResourceLimitError(
                f"Memory usage exceeded limit: {process.memory_info().rss}"
            )

        if process.num_fds() > MAX_OPEN_FILES:

            raise ResourceLimitError(f"Too many open files: {process.num_fds()}")

        if len(psutil.pids()) > MAX_PROCESS_COUNT:

            raise ResourceLimitError(f"Too many processes: {len(psutil.pids())}")

    except Exception as e:

        logger.error(f"Resource limit check failed: {e}")

        raise


@contextmanager
def secure_file_operation(
    filepath: str, mode: str = "a+", max_size: int = MAX_FILE_SIZE
) -> Any:
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


async def run_secure_command(
    cmd: Union[str, List[str]], **kwargs
) -> Tuple[int, str, str]:
    """Run command with security checks and resource limits."""

    try:

        check_resource_limits()

        sanitized_cmd = sanitize_command(cmd)

        process = await asyncio.create_subprocess_exec(
            *sanitized_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **kwargs,
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

            subprocess.run(["rundll32.exe", "user32.dll,LockWorkStation"], check=True)

        else:

            subprocess.run(["loginctl", "lock-session"], check=True)

        return True

    except Exception as e:

        logger.error(f"Failed to lock system: {e}")

        return False


async def force_shutdown() -> bool:

    try:

        if CURRENT_PLATFORM.startswith("WIN"):

            subprocess.run(["shutdown", "/s", "/t", "0"], check=True)

        else:

            subprocess.run(["shutdown", "-h", "now"], check=True)

        return True

    except Exception as e:

        logger.error(f"Failed to force shutdown: {e}")

        return False


async def handle_usb_disconnect(settings: Settings) -> None:

    if settings.do_sync:

        subprocess.run(["sync"], check=True)

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

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    backup_file = backup_dir / f"backup_{timestamp}.tar.gz"

    subprocess.run(
        ["tar", "-czf", str(backup_file), *settings.folders_to_remove], check=True
    )

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

        await run_command("sync")

    if settings.do_wipe_ram:

        await run_command(settings.wipe_ram_cmd)

    if settings.do_wipe_swap:

        await run_command(settings.wipe_swap_cmd)

    if settings.shut_down:

        await run_command("shutdown -h now")


async def lsusb_darwin() -> List[str]:

    try:

        output = subprocess.check_output(["system_profiler", "SPUSBDataType"]).decode()

        devices = []

        for line in output.split("\n"):

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

            output = subprocess.check_output(["lsusb"]).decode()

            return DeviceCountSet(
                [line.split()[5] for line in output.split("\n") if line]
            )

    except Exception as e:

        logger.error(f"Failed to get USB devices: {e}")

        return DeviceCountSet([])


def program_present(program: str) -> bool:

    return shutil.which(program) is not None


def load_config(config_path: str) -> Dict:

    try:

        with open(config_path, "r") as f:

            config = json.load(f)

            if "safe_mode" not in config:

                config["safe_mode"] = True

            if "dry_run" not in config:

                config["dry_run"] = False

            return config

    except FileNotFoundError:

        logger.warning(f"Config file not found: {config_path}, using defaults")

        return {"safe_mode": True, "dry_run": False}

    except json.JSONDecodeError:

        logger.error(f"Invalid config file: {config_path}")

        sys.exit(1)


def generate_encryption_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:

    if salt is None:

        salt = os.urandom(ENCRYPTION_SETTINGS["salt_length"])

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=ENCRYPTION_SETTINGS["key_length"],
        salt=salt,
        iterations=ENCRYPTION_SETTINGS["iterations"],
        backend=default_backend(),
    )

    key = kdf.derive(password.encode())

    return key, salt


def encrypt_data(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:

    nonce = os.urandom(ENCRYPTION_SETTINGS["nonce_length"])

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())

    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(data) + encryptor.finalize()

    return ciphertext, nonce, encryptor.tag


def decrypt_data(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:

    cipher = Cipher(
        algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
    )

    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def secure_encrypt_file(file_path: Path, password: str) -> bool:

    try:

        with open(file_path, "rb") as f:

            data = f.read()

        key, salt = generate_encryption_key(password)

        ciphertext, nonce, tag = encrypt_data(data, key)

        with open(file_path, "wb") as f:

            f.write(salt + nonce + tag + ciphertext)

        return True

    except Exception as e:

        logger.error(f"Failed to encrypt file: {e}")

        return False


def secure_decrypt_file(file_path: Path, password: str) -> bool:

    try:

        with open(file_path, "rb") as f:

            data = f.read()

        salt = data[: ENCRYPTION_SETTINGS["salt_length"]]

        nonce = data[
            ENCRYPTION_SETTINGS["salt_length"] : ENCRYPTION_SETTINGS["salt_length"]
            + ENCRYPTION_SETTINGS["nonce_length"]
        ]

        tag = data[
            ENCRYPTION_SETTINGS["salt_length"]
            + ENCRYPTION_SETTINGS["nonce_length"] : ENCRYPTION_SETTINGS["salt_length"]
            + ENCRYPTION_SETTINGS["nonce_length"]
            + ENCRYPTION_SETTINGS["tag_length"]
        ]

        ciphertext = data[
            ENCRYPTION_SETTINGS["salt_length"]
            + ENCRYPTION_SETTINGS["nonce_length"]
            + ENCRYPTION_SETTINGS["tag_length"] :
        ]

        key, _ = generate_encryption_key(password, salt)

        plaintext = decrypt_data(ciphertext, key, nonce, tag)

        with open(file_path, "wb") as f:

            f.write(plaintext)

        return True

    except Exception as e:

        logger.error(f"Failed to decrypt file: {e}")

        return False


def secure_shred_file(file_path: Path) -> bool:

    try:

        file_size = file_path.stat().st_size

        with open(file_path, "wb") as f:

            for _ in range(SECURITY_SETTINGS["shred_passes"]):

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

            for key in patterns.get("registry_keys", []):

                result = subprocess.run(
                    ["reg", "query", key], capture_output=True, text=True
                )

                if result.returncode == 0:

                    suspicious.append(f"Found registry key: {key}")

        except Exception as e:

            logger.error(f"Registry check failed: {e}")

    return suspicious


def enhanced_check_cellebrite() -> Dict[str, List[str]]:

    suspicious = {"processes": [], "files": [], "ports": [], "registry": []}

    try:

        for proc in psutil.process_iter(["name", "cmdline", "open_files"]):

            try:

                name = proc.info["name"] or ""

                cmdline = " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""

                if any(
                    pattern.lower() in name.lower()
                    for pattern in CELLEBRITE_PATTERNS["process_names"]
                ):

                    suspicious["processes"].append(f"Cellebrite process: {name}")

                if any(
                    keyword.lower() in cmdline.lower()
                    for keyword in CELLEBRITE_PATTERNS["keywords"]
                ):

                    suspicious["processes"].append(
                        f"Cellebrite activity in process: {name}"
                    )

                for file in proc.info["open_files"]:

                    if any(
                        ext in file.path.lower()
                        for ext in CELLEBRITE_PATTERNS["file_extensions"]
                    ):

                        suspicious["files"].append(
                            f"Cellebrite file access: {file.path}"
                        )

            except (psutil.NoSuchProcess, psutil.AccessDenied):

                continue

        for conn in psutil.net_connections():

            if conn.laddr.port in CELLEBRITE_PATTERNS["ports"]:

                suspicious["ports"].append(f"Cellebrite port: {conn.laddr.port}")

        suspicious["registry"] = check_registry_keys(CELLEBRITE_PATTERNS)

    except Exception as e:

        logger.error(f"Enhanced Cellebrite check failed: {e}")

    return suspicious


def enhanced_check_jiggler() -> Dict[str, List[str]]:

    suspicious = {"processes": [], "files": [], "ports": [], "registry": []}

    try:

        for proc in psutil.process_iter(["name", "cmdline"]):

            try:

                name = proc.info["name"] or ""

                cmdline = " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""

                if any(
                    pattern.lower() in name.lower()
                    for pattern in JIGGLER_PATTERNS["suspicious_processes"]
                ):

                    suspicious["processes"].append(f"Jiggler process: {name}")

                if any(
                    keyword.lower() in cmdline.lower()
                    for keyword in JIGGLER_PATTERNS["keywords"]
                ):

                    suspicious["processes"].append(
                        f"Jiggler activity in process: {name}"
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied):

                continue

        for conn in psutil.net_connections():

            if conn.laddr.port in JIGGLER_PATTERNS["suspicious_ports"]:

                suspicious["ports"].append(f"Jiggler port: {conn.laddr.port}")

        suspicious["registry"] = check_registry_keys(JIGGLER_PATTERNS)

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

        try:

            self.key_manager = KeyManager("rigmaiden.ini")

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

            master_key_id, master_key = self.key_manager.generate_key("master")

            self.encryption_layers = []

            key_id, key = self.key_manager.generate_key("aes")

            self.encryption_layers.append(
                {
                    "id": key_id,
                    "algorithm": "AES-256-GCM",
                    "key": key,
                    "key_length": 32,
                    "nonce_length": 12,
                    "tag_length": 16,
                }
            )

            key_id, key = self.key_manager.generate_key("chacha")

            self.encryption_layers.append(
                {
                    "id": key_id,
                    "algorithm": "ChaCha20-Poly1305",
                    "key": key,
                    "key_length": 32,
                    "nonce_length": 12,
                    "tag_length": 16,
                }
            )

            key_id, key = self.key_manager.generate_key("xchacha")

            self.encryption_layers.append(
                {
                    "id": key_id,
                    "algorithm": "XChaCha20-Poly1305",
                    "key": key,
                    "key_length": 32,
                    "nonce_length": 24,
                    "tag_length": 16,
                }
            )

            self.key_manager.store_key(
                master_key_id,
                master_key,
                {
                    "key_id": master_key_id,
                    "created_at": time.time(),
                    "expires_at": time.time() + 86400,
                    "algorithm": "master",
                    "version": 1,
                    "nonce_history": set(),
                },
            )

        except Exception as e:

            logger.error(f"Failed to setup encryption layers: {e}")

            self.encryption_layers = []

    async def apply_countermeasures(self) -> None:
        """Apply security countermeasures with proper error handling."""

        try:

            if self.force_encryption and self.key_manager:

                self.key_manager.rotate_keys()

                for layer in self.encryption_layers:

                    try:

                        logger.info(f"Applying encryption layer: {layer['algorithm']}")

                        nonce = os.urandom(layer["nonce_length"])

                        if not self.key_manager.validate_nonce(
                            layer["id"], base64.b64encode(nonce).decode()
                        ):

                            logger.error(
                                f"Nonce validation failed for layer {layer['algorithm']}"
                            )

                            continue

                        if layer["algorithm"] == "AES-256-GCM":

                            cipher = Cipher(
                                algorithms.AES(layer["key"]),
                                modes.GCM(nonce),
                                backend=default_backend(),
                            )

                        elif layer["algorithm"] in [
                            "ChaCha20-Poly1305",
                            "XChaCha20-Poly1305",
                        ]:

                            cipher = Cipher(
                                algorithms.ChaCha20Poly1305(layer["key"]),
                                modes.GCM(nonce),
                                backend=default_backend(),
                            )

                        encryptor = cipher.encryptor()

                        critical_data = self._get_critical_data()

                        if critical_data:

                            ciphertext, nonce, tag = self.key_manager.encrypt_data(
                                layer["id"], critical_data
                            )

                            self._store_encrypted_data(
                                layer["id"], ciphertext, nonce, tag
                            )

                    except Exception as e:

                        logger.error(
                            f"Failed to apply encryption layer {layer['algorithm']}: {e}"
                        )

                        continue

            if self.enable_countermeasures:

                await self.enable_airplane_mode()

                await self.apply_geolocation_spoofing()

                if CURRENT_PLATFORM.startswith("DARWIN"):

                    commands = [
                        ["networksetup", "-setairportpower", "en0", "off"],
                        ["networksetup", "-setbluetoothpower", "off"],
                        ["networksetup", "-setwwanpowerstate", "off"],
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
                "base_station_profiles": self.base_station_profiles,
                "signal_fingerprints": self.signal_fingerprints,
                "network_parameter_history": self.network_parameter_history,
                "traffic_patterns": self.traffic_patterns,
                "anomaly_scores": self.anomaly_scores,
            }

            return json.dumps(data).encode()

        except Exception as e:

            logger.error(f"Failed to get critical data: {e}")

            return None

    def _store_encrypted_data(
        self, key_id: str, ciphertext: bytes, nonce: bytes, tag: bytes
    ) -> None:
        """Store encrypted data securely."""

        try:

            data = {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "tag": base64.b64encode(tag).decode(),
                "timestamp": time.time(),
            }

            if not hasattr(self, "_encrypted_data"):

                self._encrypted_data = {}

            self._encrypted_data[key_id] = data

        except Exception as e:

            logger.error(f"Failed to store encrypted data: {e}")

    def initialize_ml_model(self):

        try:

            from sklearn.ensemble import IsolationForest

            self.ml_model = IsolationForest(
                contamination=0.1, random_state=42, n_estimators=100
            )

        except ImportError:

            logger.warning("scikit-learn not available. ML-based detection disabled.")

            self.ml_model = None

    def analyze_traffic_patterns(self) -> List[str]:

        suspicious_patterns = []

        try:

            for conn in psutil.net_connections():

                if conn.status == "ESTABLISHED":

                    key = f"{conn.laddr.ip}:{conn.laddr.port}"

                    if key not in self.traffic_patterns:

                        self.traffic_patterns[key] = {
                            "first_seen": time.time(),
                            "packet_count": 0,
                            "data_transferred": 0,
                            "connections": set(),
                        }

                    pattern = self.traffic_patterns[key]

                    pattern["packet_count"] += 1

                    if pattern["packet_count"] > 1000:

                        suspicious_patterns.append("Excessive packet traffic")

                    if len(pattern["connections"]) > 5:

                        suspicious_patterns.append("Multiple suspicious connections")

                    pattern["connections"].add(f"{conn.raddr.ip}:{conn.raddr.port}")

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
                self.suspicious_parameter_changes,
            ]

            score = self.ml_model.score_samples([features])[0]

            self.anomaly_scores[time.time()] = score

            anomalies = []

            if score < -0.5:

                anomalies.append("ML-detected anomaly in network behavior")

            return anomalies

        except Exception as e:

            logger.error(f"Anomaly detection failed: {e}")

            return []

    def apply_geolocation_spoofing(self) -> bool:

        try:

            if not CURRENT_PLATFORM.startswith("DARWIN"):

                return False

            subprocess.run(
                [
                    "defaults",
                    "write",
                    "/Library/Preferences/com.apple.locationd",
                    "LocationServicesEnabled",
                    "-bool",
                    "false",
                ],
                check=True,
            )

            subprocess.run(["killall", "locationd"], check=True)

            subprocess.run(
                ["networksetup", "-setairportpower", "en0", "off"], check=True
            )

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

        self.resource_manager = ResourceManager(
            ResourceLimits(**settings.resource_limits)
        )

        self.device_count = 0

        self.last_check = 0.0

        self.monitoring = False

        self.monitor_thread = None

    async def start_monitoring(self) -> None:
        """Start USB device monitoring."""

        if self.monitoring:

            return

        self.monitoring = True

        self.monitor_thread = threading.Thread(target=self._monitor_devices)

        self.monitor_thread.start()

        logger.info("USB monitoring started")

    async def stop_monitoring(self) -> None:
        """Stop USB device monitoring."""

        if not self.monitoring:

            return

        self.monitoring = False

        if self.monitor_thread:

            self.monitor_thread.join()

        logger.info("USB monitoring stopped")

    def _monitor_devices(self) -> None:
        """Monitor USB devices in a separate thread."""

        while self.monitoring:

            try:

                asyncio.run(self.check_usb_devices())

                time.sleep(self.settings.scan_intervals["usb"])

            except Exception as e:

                logger.error(f"USB monitoring failed: {e}")

                time.sleep(self.settings.scan_intervals["usb"])

    async def check_usb_devices(self) -> None:
        """Check USB devices with proper error handling."""

        try:

            devices = self.platform.get_usb_devices()

            current_count = len(devices)

            if current_count != self.device_count:

                logger.info(
                    f"USB device count changed: {self.device_count} -> {current_count}"
                )

                self.device_count = current_count

                if current_count < self.device_count:

                    await self.handle_usb_disconnect()

        except Exception as e:

            logger.error(f"Failed to check USB devices: {e}")

    async def handle_usb_disconnect(self) -> None:
        """Handle USB disconnect with proper cleanup."""

        try:

            logger.warning("USB device disconnected!")

            await self.command_executor.run_command("sync")

            await self.resource_manager.cleanup_temp_files()

            await self.resource_manager.cleanup_processes()

            if not await self.check_memory_integrity():

                logger.error("Memory integrity check failed!")

            if self.settings.backup_enabled:

                await self.create_backup()

        except Exception as e:

            logger.error(f"Failed to handle USB disconnect: {e}")

    async def check_memory_integrity(self) -> bool:
        """Check memory integrity with proper error handling."""

        try:

            memory_info = self.platform.get_memory_info()

            if (
                memory_info["used"]
                > self.settings.resource_limits["max_memory_mb"] * 1024 * 1024
            ):

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

            backup_file = os.path.join(
                self.settings.backup_location, f"backup_{timestamp}.tar.gz"
            )

            async with self.resource_manager.secure_file_operation(
                backup_file, "w"
            ) as f:

                await self.command_executor.run_command(f"tar -czf {backup_file} .")

        except Exception as e:

            logger.error(f"Failed to create backup: {e}")


class KeyManager:
    """
    Secure key management for encryption keys. Supports in-memory and platform-specific secure storage.
    """

    def __init__(self, config_path: str = None):

        self.keys = {}

        self.nonce_history = {}

        self.config_path = config_path

        self.platform = platform.system().lower()

        self.logger = logging.getLogger(__name__)

        self.use_keychain = self.platform == "darwin"

        if self.use_keychain:

            try:

                import keyring

                self.keyring = keyring

            except ImportError:

                self.use_keychain = False

    def generate_key(
        self, key_type: str = "aes", length: int = 32
    ) -> tuple[str, bytes]:

        key_id = f"{key_type}_{secrets.token_hex(8)}"

        key = secrets.token_bytes(length)

        self.keys[key_id] = key

        return key_id, key

    def store_key(self, key_id: str, key: bytes, meta: dict = None) -> None:

        if self.use_keychain:

            try:

                self.keyring.set_password(
                    "rigmaiden", key_id, base64.b64encode(key).decode()
                )

            except Exception as e:

                self.logger.error(f"Failed to store key in Keychain: {e}")

        else:

            self.keys[key_id] = key

        if meta:

            self.nonce_history[key_id] = meta.get("nonce_history", set())

    def load_key(self, key_id: str) -> Optional[bytes]:

        if self.use_keychain:

            try:

                val = self.keyring.get_password("rigmaiden", key_id)

                if val:

                    return base64.b64decode(val)

            except Exception as e:

                self.logger.error(f"Failed to load key from Keychain: {e}")

        return self.keys.get(key_id)

    def rotate_keys(self):

        self.keys.clear()

        self.nonce_history.clear()

    def validate_nonce(self, key_id: str, nonce: str) -> bool:

        if key_id not in self.nonce_history:

            self.nonce_history[key_id] = set()

        if nonce in self.nonce_history[key_id]:

            return False

        self.nonce_history[key_id].add(nonce)

        return True

    def encrypt_data(self, key_id: str, data: bytes) -> tuple[bytes, bytes, bytes]:

        key = self.load_key(key_id)

        if not key:

            raise ValueError(f"Key {key_id} not found")

        nonce = os.urandom(12)

        cipher = Cipher(
            algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
        )

        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(data) + encryptor.finalize()

        return ciphertext, nonce, encryptor.tag

    def decrypt_data(
        self, key_id: str, ciphertext: bytes, nonce: bytes, tag: bytes
    ) -> bytes:

        key = self.load_key(key_id)

        if not key:

            raise ValueError(f"Key {key_id} not found")

        cipher = Cipher(
            algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
        )

        decryptor = cipher.decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()


async def main() -> None:
    """Main entry point with proper error handling and resource management."""

    try:

        parser = argparse.ArgumentParser(
            description="Rigmaiden - Security Monitoring Tool"
        )

        parser.add_argument("--config", help="Path to config file")

        parser.add_argument("--safe-mode", action="store_true", help="Run in safe mode")

        parser.add_argument(
            "--dry-run", action="store_true", help="Show actions without executing"
        )

        parser.add_argument("--debug", action="store_true", help="Enable debug logging")

        args = parser.parse_args()

        config = load_config(args.config)

        if args.safe_mode:

            config["safe_mode"] = True

        if args.dry_run:

            config["dry_run"] = True

        log_level = logging.DEBUG if args.debug else logging.INFO

        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(config["paths"]["log_dir"] / "rigmaiden.log"),
                logging.StreamHandler(sys.stdout),
            ],
        )

        settings = Settings.from_config(config)

        resource_manager = ResourceManager(ResourceLimits(**config["resource_limits"]))

        platform_utils = get_platform_utils()

        command_executor = SecureCommandExecutor()

        key_manager = KeyManager(config["paths"]["config"])

        if not await resource_manager.check_resources():

            logger.error("Insufficient system resources")

            sys.exit(1)

        usb_monitor = USBMonitor(settings)

        def handle_signal(signum, frame):

            logger.info(f"Received signal {signum}")

            asyncio.create_task(cleanup())

        signal.signal(signal.SIGINT, handle_signal)

        signal.signal(signal.SIGTERM, handle_signal)

        try:

            await usb_monitor.monitor()

        except Exception as e:

            logger.error(f"Monitoring failed: {e}")

            await cleanup()

    except Exception as e:

        logger.error(f"Application failed: {e}")

        sys.exit(1)


async def cleanup() -> None:
    """Cleanup resources before exit."""

    try:

        if "usb_monitor" in globals():

            await usb_monitor.stop_monitoring()

        if "resource_manager" in globals():

            await resource_manager.cleanup_temp_files()

            await resource_manager.cleanup_processes()

        sys.exit(0)

    except Exception as e:

        logger.error(f"Cleanup failed: {e}")

        sys.exit(1)


async def check_jiggler(settings: Settings) -> Dict[str, List[str]]:
    """Check for mouse jiggler software with proper error handling."""

    try:

        suspicious = {"processes": [], "files": [], "ports": [], "registry": []}

        for proc in psutil.process_iter(["name", "cmdline"]):

            try:

                name = proc.info["name"] or ""

                cmdline = " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""

                if any(
                    pattern.lower() in name.lower()
                    for pattern in JIGGLER_PATTERNS["suspicious_processes"]
                ):

                    suspicious["processes"].append(f"Jiggler process: {name}")

                if any(
                    keyword.lower() in cmdline.lower()
                    for keyword in JIGGLER_PATTERNS["keywords"]
                ):

                    suspicious["processes"].append(
                        f"Jiggler activity in process: {name}"
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied):

                continue

        for conn in psutil.net_connections():

            if conn.laddr.port in JIGGLER_PATTERNS["suspicious_ports"]:

                suspicious["ports"].append(f"Jiggler port: {conn.laddr.port}")

        if platform.system().lower() == "windows":

            suspicious["registry"] = check_registry_keys(JIGGLER_PATTERNS)

        return suspicious

    except Exception as e:

        logger.error(f"Jiggler check failed: {e}")

        return {"processes": [], "files": [], "ports": [], "registry": []}


async def check_cellebrite(settings: Settings) -> Dict[str, List[str]]:
    """Check for Cellebrite software with proper error handling."""

    try:

        suspicious = {"processes": [], "files": [], "ports": [], "registry": []}

        for proc in psutil.process_iter(["name", "cmdline", "open_files"]):

            try:

                name = proc.info["name"] or ""

                cmdline = " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""

                if any(
                    pattern.lower() in name.lower()
                    for pattern in CELLEBRITE_PATTERNS["process_names"]
                ):

                    suspicious["processes"].append(f"Cellebrite process: {name}")

                if any(
                    keyword.lower() in cmdline.lower()
                    for keyword in CELLEBRITE_PATTERNS["keywords"]
                ):

                    suspicious["processes"].append(
                        f"Cellebrite activity in process: {name}"
                    )

                for file in proc.info["open_files"]:

                    if any(
                        ext in file.path.lower()
                        for ext in CELLEBRITE_PATTERNS["file_extensions"]
                    ):

                        suspicious["files"].append(
                            f"Cellebrite file access: {file.path}"
                        )

            except (psutil.NoSuchProcess, psutil.AccessDenied):

                continue

        for conn in psutil.net_connections():

            if conn.laddr.port in CELLEBRITE_PATTERNS["ports"]:

                suspicious["ports"].append(f"Cellebrite port: {conn.laddr.port}")

        if platform.system().lower() == "windows":

            suspicious["registry"] = check_registry_keys(CELLEBRITE_PATTERNS)

        return suspicious

    except Exception as e:

        logger.error(f"Cellebrite check failed: {e}")

        return {"processes": [], "files": [], "ports": [], "registry": []}


async def check_ios_cellebrite_conflict(settings: Settings) -> bool:
    """Check for iOS device and Cellebrite software conflict."""

    try:

        if not settings.block_ios_access:

            return False

        ios_devices = []

        if platform.system().lower() == "darwin":

            output = subprocess.check_output(
                ["system_profiler", "SPUSBDataType"]
            ).decode()

            for line in output.split("\n"):

                for vendor_id, device_type in IOS_DEVICE_IDS.items():

                    if vendor_id in line:

                        ios_devices.append(device_type)

        cellebrite_detected = False

        for proc in psutil.process_iter(["name"]):

            try:

                name = proc.info["name"] or ""

                if any(
                    pattern.lower() in name.lower()
                    for pattern in CELLEBRITE_PATTERNS["process_names"]
                ):

                    cellebrite_detected = True

                    break

            except (psutil.NoSuchProcess, psutil.AccessDenied):

                continue

        return bool(ios_devices) and cellebrite_detected

    except Exception as e:

        logger.error(f"iOS-Cellebrite conflict check failed: {e}")

        return False


async def wipe_swap(settings: Settings) -> bool:
    """Securely wipe swap space with proper error handling."""

    try:

        if not settings.do_wipe_swap or settings.dry_run:

            return False

        if not settings.wipe_swap_cmd:

            logger.warning("No swap wipe command configured")

            return False

        if platform.system().lower() == "linux":

            with open("/proc/swaps", "r") as f:

                if not f.read().strip():

                    logger.info("No swap space enabled")

                    return True

        try:

            subprocess.run(settings.wipe_swap_cmd.split(), check=True)

            return True

        except subprocess.CalledProcessError as e:

            logger.error(f"Swap wipe command failed: {e}")

            return False

    except Exception as e:

        logger.error(f"Swap wipe failed: {e}")

        return False


async def startup_checks(settings: Settings) -> bool:
    """Perform startup checks with proper error handling."""

    try:

        if not await check_resource_limits():

            logger.error("Insufficient system resources")

            return False

        required_commands = ["lsusb", "sync"]

        if settings.do_wipe_swap:

            required_commands.append(settings.wipe_swap_cmd.split()[0])

        if settings.do_wipe_ram:

            required_commands.append(settings.wipe_ram_cmd.split()[0])

        for cmd in required_commands:

            if not program_present(cmd):

                logger.error(f"Required command not found: {cmd}")

                return False

        for path in [settings.log_file, settings.backup_location]:

            try:

                Path(path).parent.mkdir(parents=True, exist_ok=True)

                test_file = Path(path).parent / ".test"

                test_file.touch()

                test_file.unlink()

            except Exception as e:

                logger.error(f"Permission check failed for {path}: {e}")

                return False

        return True

    except Exception as e:

        logger.error(f"Startup checks failed: {e}")

        return False


async def kill_computer(settings: Settings) -> None:
    """Safely perform destructive actions with proper safeguards."""

    try:

        if settings.dry_run:

            logger.info("Dry run - would have performed destructive actions")

            return

        if not should_perform_destructive(settings):

            logger.warning("Destructive actions blocked by safe mode")

            return

        if settings.do_backup:

            await create_backup(settings)

        if settings.do_sync:

            try:

                subprocess.run(["sync"], check=True)

            except subprocess.CalledProcessError as e:

                logger.error(f"Sync failed: {e}")

                return

        if settings.do_wipe_ram and settings.wipe_ram_cmd:

            try:

                subprocess.run(settings.wipe_ram_cmd.split(), check=True)

            except subprocess.CalledProcessError as e:

                logger.error(f"RAM wipe failed: {e}")

                return

        if settings.do_wipe_swap:

            if not await wipe_swap(settings):

                logger.error("Swap wipe failed")

                return

        if settings.shut_down:

            try:

                if platform.system().lower() == "windows":

                    subprocess.run(["shutdown", "/s", "/t", "0"], check=True)

                else:

                    subprocess.run(["shutdown", "-h", "now"], check=True)

            except subprocess.CalledProcessError as e:

                logger.error(f"Shutdown failed: {e}")

                return

    except Exception as e:

        logger.error(f"Destructive actions failed: {e}")

        return


async def check_fuzzy_model(settings: Settings) -> Dict[str, List[str]]:
    """Check for The Fuzzy Model plug-in and database carving tools."""
    try:
        suspicious = {"processes": [], "files": [], "ports": [], "registry": []}
        for proc in psutil.process_iter(["name", "cmdline", "open_files"]):
            try:
                name = proc.info["name"] or ""
                cmdline = " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""
                if any(
                    pattern.lower() in name.lower()
                    for pattern in FUZZY_MODEL_PATTERNS["process_names"]
                ):
                    suspicious["processes"].append(f"Fuzzy Model process: {name}")
                if any(
                    keyword.lower() in cmdline.lower()
                    for keyword in FUZZY_MODEL_PATTERNS["keywords"]
                ):
                    suspicious["processes"].append(
                        f"Fuzzy Model activity in process: {name}"
                    )
                for file in proc.info["open_files"]:
                    if any(
                        ext in file.path.lower()
                        for ext in FUZZY_MODEL_PATTERNS["file_extensions"]
                    ):
                        suspicious["files"].append(
                            f"Fuzzy Model file access: {file.path}"
                        )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        for conn in psutil.net_connections():
            if conn.laddr.port in FUZZY_MODEL_PATTERNS["suspicious_ports"]:
                suspicious["ports"].append(f"Fuzzy Model port: {conn.laddr.port}")
        if platform.system().lower() == "windows":
            suspicious["registry"] = check_registry_keys(FUZZY_MODEL_PATTERNS)
        for cache_dir in FUZZY_MODEL_PATTERNS["cache_directories"]:
            if os.path.exists(cache_dir):
                for root, dirs, files in os.walk(cache_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if any(
                            ext in file.lower()
                            for ext in [
                                ".db",
                                ".sqlite",
                                ".sqlite3",
                                ".carved",
                                ".extracted",
                            ]
                        ):
                            suspicious["files"].append(
                                f"Potential carved database: {file_path}"
                            )
        return suspicious
    except Exception as e:
        logger.error(f"Fuzzy Model check failed: {e}")
        return {"processes": [], "files": [], "ports": [], "registry": []}


if __name__ == "__main__":

    asyncio.run(main())
