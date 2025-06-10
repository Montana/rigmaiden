# USB Forensic Security Tools

A comprehensive security suite for monitoring and protecting against unauthorized USB device access, forensic tools, and mouse jiggler software.

## Features

- USB Device Monitoring
  - Real-time USB device detection
  - Whitelist-based access control
  - Automatic system shutdown on unauthorized access
  - Mass storage device blocking

- Cellebrite Protection
  - Database access monitoring
  - iOS device access blocking
  - Automatic backup and encryption
  - Forensic tool detection

- Mouse Jiggler Detection
  - Process monitoring
  - Network connection analysis
  - Port scanning
  - Automatic blocking of suspicious software

## Rigmaiden Protocol

The Rigmaiden Protocol is an advanced security system designed to detect and counter IMSI-catchers (Stingrays) and other cellular surveillance devices. It provides comprehensive protection through multiple layers of detection and countermeasures.

### Key Features

1. **Advanced Detection Methods**
   - Machine Learning-based anomaly detection using Isolation Forest
   - Signal fingerprinting and pattern analysis
   - Frequency hopping detection
   - Base station behavior analysis
   - Network parameter monitoring
   - Traffic pattern analysis

2. **Multi-Layer Protection**
   - Memory integrity protection
   - Multi-layer encryption (AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305)
   - Geolocation spoofing
   - Automatic countermeasures on detection

3. **Real-time Monitoring**
   - Continuous cellular network monitoring
   - Signal strength analysis
   - Network parameter tracking
   - Traffic pattern monitoring
   - Process and memory monitoring

4. **Countermeasures**
   - Automatic encryption layer activation
   - Geolocation spoofing
   - Airplane mode activation
   - Network interface control
   - Memory protection enforcement

### Detection Capabilities

- **Signal Analysis**
  - Unusual signal strength patterns
  - Rapid signal strength changes
  - Suspicious cell IDs and location area codes
  - Multiple operator changes
  - Frequency hopping patterns

- **Network Analysis**
  - Suspicious traffic patterns
  - Excessive packet traffic
  - Multiple suspicious connections
  - Network parameter anomalies
  - Base station behavior analysis

- **Machine Learning Detection**
  - Anomaly detection in network behavior
  - Pattern recognition in cellular parameters
  - Signal fingerprint matching
  - Traffic pattern classification

### Security Features

1. **Memory Protection**
   - Critical memory region protection
   - Memory integrity verification
   - Suspicious pattern scanning
   - Memory access monitoring

2. **Encryption**
   - Multi-layer encryption system
   - Automatic key rotation
   - Secure key storage
   - Encrypted communication channels

3. **Countermeasures**
   - Automatic response to threats
   - Geolocation spoofing
   - Network interface control
   - Process termination
   - System lockdown

### Usage

The Rigmaiden Protocol is automatically integrated into the USB Forensic Security Tools suite. It runs in the background, continuously monitoring for potential threats and applying countermeasures when necessary.

To enable/disable specific features, modify the configuration in `usbfstab.ini`:

```ini
[Rigmaiden]
enabled = true
ml_detection = true
geolocation_spoofing = true
force_encryption = true
countermeasures = true
check_interval = 2.0
alert_threshold = 3
```

### Requirements

- Python 3.8 or higher
- scikit-learn (for ML-based detection)
- Root/Administrator privileges
- Cellular modem access
- Network interface control capabilities

## Requirements

- Python 3.8 or higher
- Root/Administrator privileges
- Linux or macOS system

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Montana/usbfstab.git
cd usbfstab
```

2. Run the setup script:
```bash
sudo ./setup.sh
```

This will:
- Install required dependencies
- Create necessary directories
- Set up system services
- Configure logging

## Configuration

The main configuration file is `usbfstab.ini`. Key settings include:

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
sudo systemctl start usbfstab
sudo systemctl stop usbfstab
sudo systemctl status usbfstab
```

macOS:
```bash
launchctl load ~/Library/LaunchAgents/com.usbfstab.plist
launchctl unload ~/Library/LaunchAgents/com.usbfstab.plist
```

### Running Individual Tools

```bash
python3 usbfstab.py    # USB monitoring
python3 cellebrite.py  # Cellebrite protection
python3 jiggler_block.py # Jiggler detection
```

## Logging

Logs are stored in `/var/log/usbfstab/`:
- `usbfstab.log`: Main application log
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

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and feature requests, please use the GitHub issue tracker.

## Disclaimer

This tool is designed for security purposes. Use responsibly and in accordance with applicable laws and regulations.

