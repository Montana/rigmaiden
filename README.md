# Rigmaiden (For Educational Use Only) 

![Rigmaiden](https://freight.cargo.site/t/original/i/T2438503549000552213986019943579/Heading-12.png)

_Educational Use Only._

# Rigmaiden

Rigmaiden is a secure and efficient system management tool for handling USB devices, network interfaces, and system resources across multiple platforms.

## Contact
michael@rigmaiden.sh 

## How It Works 

![Untitled (13)](https://github.com/user-attachments/assets/e9dc240d-6133-44ca-b4e1-a05236d88b24)

## Features

- **Secure Device Management**
  - USB device detection and management
  - Network interface monitoring
  - Process tracking and control
  - Resource usage monitoring

- **Cross-Platform Support**
  - Windows and Unix-based systems
  - Platform-specific optimizations
  - Consistent interface across platforms

- **Security Features**
  - Hardware-backed key generation
  - Secure command execution
  - Resource limit enforcement
  - Memory protection

- **Resource Management**
  - Memory and CPU monitoring
  - File size restrictions
  - Process limits
  - Automatic cleanup

## Installation

```bash
git clone https://github.com/montana/rigmaiden.git
cd rigmaiden
pip install -r requirements.txt
```

## Usage

```python
from rigmaiden import Rigmaiden

rig = Rigmaiden()

rig.start_monitoring()

devices = rig.get_usb_devices()
network_info = rig.get_network_info()
processes = rig.get_process_info()
memory_info = rig.get_memory_info()
```

## Configuration

The system can be configured through environment variables or a configuration file:

```bash
export RIGMAIDEN_MAX_MEMORY=1024  
export RIGMAIDEN_MAX_CPU=80       
export RIGMAIDEN_MAX_FILES=100    
```

## Security

- All sensitive operations use hardware-backed encryption
- Command execution is sanitized and validated
- Resource limits are strictly enforced
- Memory is protected against unauthorized access

## Requirements

- Python 3.8+
- Platform-specific requirements:
  - Windows: TPM 2.0 support
  - macOS: Secure Enclave support
  - Linux: TPM 2.0 or hardware security module
 
## RMP (Rigmaiden Protocol) Features

- Cellular surveillance detection
  - Signal pattern analysis
  - Frequency hopping detection
  - IMSI catcher detection
  - Base station fingerprinting
- USB device monitoring
  - Cross-platform support (Linux, macOS, Windows)
  - Suspicious device detection
  - Automatic protection measures
- Resource management
  - Memory usage monitoring
  - CPU usage limits
  - Disk space management
  - Process control
- Security features
  - Secure command execution
  - Key management and rotation
  - Encrypted backups
  - Memory protection
- Fuzzy Model Protection
  - Database carving detection and prevention
  - Communications data extraction monitoring
  - User information and location data protection
  - Manual examination tool detection
  - Automatic quarantine of suspicious carved files
  - Directory clearing to prevent data exfiltration
- CFURL Cache Protection
  - WebKit cache exploitation monitoring
  - Safari cache directory protection
  - Suspicious cache process detection
  - Network activity monitoring for cache attacks
  - Registry and plist file monitoring
  - Encrypted quarantine of suspicious cache data

## The Rigmaiden Protocol

| Category              | Details | Reason |
|-----------------------|---------|--------|
| Detection             | - Monitors cellular network for suspicious patterns<br>- Detects frequency hopping (common with IMSI-catchers/Stingrays)<br>- Analyzes unusual signal strengths and rapid changes<br>- Uses machine learning to detect abnormal network behavior | To identify and flag the presence of surveillance tools like Stingrays before they compromise privacy |
| Device Protection     | - Enforces memory protection to prevent data extraction<br>- Implements multiple layers of encryption<br>- Monitors and protects critical system processes<br>- Tracks and verifies memory integrity<br>- Scans for suspicious patterns in system memory | To safeguard sensitive data and ensure the operating environment remains uncompromised |
| Automatic Response    | - Enables airplane mode upon threat detection<br>- Activates geolocation spoofing<br>- Adds additional layers of encryption<br>- Blocks suspicious network connections<br>- Isolates and protects sensitive memory regions | To quickly contain threats and minimize exposure with real-time protective actions |
| Continuous Monitoring | - Runs in the background silently<br>- Regularly checks cellular network parameters<br>- Analyzes signal patterns and anomalies<br>- Monitors network traffic and system behavior | To maintain constant vigilance without user intervention or disruption |
| Fuzzy Model Protection | - Scans for database carving tools and suspicious directories<br>- Monitors processes for communications data extraction<br>- Detects user information and location data carving attempts<br>- Identifies manual examination and parsing tools<br>- Automatically quarantines carved files with encryption<br>- Clears suspicious directories to prevent data exfiltration | To prevent unauthorized extraction of sensitive communications, user data, and location information through database carving techniques |
| CFURL Cache Protection | - Monitors WebKit cache directories for exploitation attempts<br>- Detects suspicious cache-related processes and network activity<br>- Scans registry and plist files for cache manipulation<br>- Protects Safari cache from unauthorized access<br>- Encrypts and quarantines suspicious cache data<br>- Prevents cache-based data extraction attacks | To protect against WebKit cache exploitation and prevent unauthorized access to cached sensitive data |
| Use Cases             | - Educational Only, but if it were theoretically in practice, defense against cellular surveillance (e.g., Stingrays, IMSI-catchers)<br>- Prevents unauthorized data extraction from the device<br>- Maintains privacy in sensitive or high-risk situations<br>- Secures devices against advanced persistent threats<br>- Protects against database carving and cache exploitation | Designed for users in high-risk environments who require reliable, autonomous security mechanisms |

## Requirements

- Python 3.8 or higher
- Root/Administrator privileges
- Linux or macOS system

## The `.ini` file

The main configuration file is `rigmaiden.ini`. Key settings include:

```ini
[General]
check_interval = 0.5
backup_interval = 1800
max_backups = 48
alert_threshold = 2

[USB]
monitor_interval = 0.5
block_unknown = true
allowed_vendors = 05ac,0483,0781,0951
allowed_products = 8600,5740,5583,1666

[Jiggler]
enabled = true
check_interval = 2.0
block_suspicious = true

[Cellebrite]
enabled = true
check_interval = 0.5
block_ios_access = true
```

## Usage

### Starting the Service

The service will start automatically after installation. To manually control:

Linux:
```bash
sudo systemctl start rigmaiden
sudo systemctl stop rigmaiden
sudo systemctl status rigmaiden
```

macOS:
```bash
launchctl load ~/Library/LaunchAgents/com.rigmaiden.plist
launchctl unload ~/Library/LaunchAgents/com.rigmaiden.plist
```

### Running Individual Tools

```bash
python3 rigmaiden.py    # USB monitoring
python3 cellebrite.py  # Cellebrite protection
python3 jiggler_block.py # Jiggler detection
```

## Logging

Logs are stored in `/var/log/rigmaiden/`:
- `rigmaiden.log`: Main application log
- `error.log`: Error messages
- `output.log`: Standard output

## Security Features

1. **USB Protection**
   - Whitelist-based device access
   - Automatic system shutdown on unauthorized access
   - Mass storage device blocking

2. **Cellebrite Protection**
   - Database access monitoring
   - iOS device access blocking
   - Encrypted backups
   - Forensic tool detection

3. **Jiggler Detection**
   - Process monitoring
   - Network analysis
   - Port scanning
   - Automatic blocking
     
## Author

Michael Mendy (c) 2025. **Educational Purposes Only**.
