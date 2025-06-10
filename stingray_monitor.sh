#!/bin/bash

# Stingray Monitor Script
# Monitors for potential IMSI-catcher (Stingray) devices
# by analyzing cellular network parameters and system information

# Configuration
LOG_FILE="/var/log/stingray_monitor.log"
CHECK_INTERVAL=5  # seconds
ALERT_THRESHOLD=3
SUSPICIOUS_PATTERNS=0
LAST_CHECK=0

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Alert function
alert() {
    log "${RED}ALERT: $1${NC}"
    # You can add additional alert methods here (email, SMS, etc.)
}

# Check cellular network information
check_cellular_info() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        CELL_INFO=$(system_profiler SPCellularDataType 2>/dev/null)
        if [ -z "$CELL_INFO" ]; then
            return 1
        fi

        # Extract cellular parameters
        MCC=$(echo "$CELL_INFO" | grep "MCC:" | awk '{print $2}')
        MNC=$(echo "$CELL_INFO" | grep "MNC:" | awk '{print $2}')
        CELL_ID=$(echo "$CELL_INFO" | grep "Cell ID:" | awk '{print $3}')
        LAC=$(echo "$CELL_INFO" | grep "LAC:" | awk '{print $2}')
        SIGNAL=$(echo "$CELL_INFO" | grep "Signal Strength:" | awk '{print $3}')
        BAND=$(echo "$CELL_INFO" | grep "Band:" | awk '{print $2}')
        FREQ=$(echo "$CELL_INFO" | grep "Frequency:" | awk '{print $2}')

        # Check for suspicious patterns
        if [ "$CELL_ID" = "0" ] || [ "$CELL_ID" = "1" ] || [ "$CELL_ID" = "65535" ]; then
            alert "Suspicious Cell ID detected: $CELL_ID"
            return 1
        fi

        if [ "$LAC" = "0" ] || [ "$LAC" = "65535" ]; then
            alert "Suspicious Location Area Code detected: $LAC"
            return 1
        fi

        if [ "$SIGNAL" -gt -30 ]; then
            alert "Unusually strong signal detected: $SIGNAL dBm"
            return 1
        fi

    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v mmcli &>/dev/null; then
            # Using ModemManager
            MODEM=$(mmcli -L | grep -o "/[0-9]*" | head -1)
            if [ -z "$MODEM" ]; then
                return 1
            fi

            CELL_INFO=$(mmcli -m "$MODEM" 2>/dev/null)
            if [ -z "$CELL_INFO" ]; then
                return 1
            fi

            # Extract cellular parameters
            MCC=$(echo "$CELL_INFO" | grep "3gpp.mcc" | awk '{print $2}')
            MNC=$(echo "$CELL_INFO" | grep "3gpp.mnc" | awk '{print $2}')
            CELL_ID=$(echo "$CELL_INFO" | grep "3gpp.cell-id" | awk '{print $2}')
            LAC=$(echo "$CELL_INFO" | grep "3gpp.location-area-code" | awk '{print $2}')
            SIGNAL=$(echo "$CELL_INFO" | grep "signal.quality" | awk '{print $2}')

            # Check for suspicious patterns
            if [ "$CELL_ID" = "0" ] || [ "$CELL_ID" = "1" ] || [ "$CELL_ID" = "65535" ]; then
                alert "Suspicious Cell ID detected: $CELL_ID"
                return 1
            fi

            if [ "$LAC" = "0" ] || [ "$LAC" = "65535" ]; then
                alert "Suspicious Location Area Code detected: $LAC"
                return 1
            fi

            if [ "$SIGNAL" -gt 90 ]; then
                alert "Unusually strong signal detected: $SIGNAL%"
                return 1
            fi
        fi
    fi

    return 0
}

# Check for frequency hopping
check_frequency_hopping() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        FREQ_HISTORY=()
        for i in {1..5}; do
            FREQ=$(system_profiler SPCellularDataType 2>/dev/null | grep "Frequency:" | awk '{print $2}')
            FREQ_HISTORY+=("$FREQ")
            sleep 1
        done

        # Check for frequency changes
        CHANGES=0
        for i in {1..4}; do
            if [ "${FREQ_HISTORY[$i]}" != "${FREQ_HISTORY[$((i-1))]}" ]; then
                CHANGES=$((CHANGES + 1))
            fi
        done

        if [ "$CHANGES" -ge 3 ]; then
            alert "Frequency hopping detected"
            return 1
        fi
    fi

    return 0
}

# Check for suspicious network connections
check_network_connections() {
    # Check for common IMSI-catcher ports
    SUSPICIOUS_PORTS="8080 8081 8082 8083 8084 8085"
    for PORT in $SUSPICIOUS_PORTS; do
        if netstat -an | grep -q ":$PORT.*LISTEN"; then
            alert "Suspicious port $PORT in use"
            return 1
        fi
    done

    return 0
}

# Check for suspicious processes
check_suspicious_processes() {
    # List of known IMSI-catcher related processes
    SUSPICIOUS_PROCS="aircrack-ng kismet wireshark tcpdump"
    for PROC in $SUSPICIOUS_PROCS; do
        if pgrep -x "$PROC" >/dev/null; then
            alert "Suspicious process detected: $PROC"
            return 1
        fi
    done

    return 0
}

# Apply countermeasures
apply_countermeasures() {
    log "${YELLOW}Applying countermeasures...${NC}"
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        networksetup -setairportpower en0 off
        networksetup -setbluetoothpower off
        networksetup -setwwanpowerstate off
        defaults write /Library/Preferences/com.apple.locationd LocationServicesEnabled -bool false
        killall locationd
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v rfkill &>/dev/null; then
            rfkill block all
        fi
        if command -v nmcli &>/dev/null; then
            nmcli radio all off
        fi
    fi

    log "${GREEN}Countermeasures applied${NC}"
}

# Main monitoring loop
main() {
    log "${GREEN}Starting Stingray monitoring...${NC}"
    
    while true; do
        CURRENT_TIME=$(date +%s)
        if [ $((CURRENT_TIME - LAST_CHECK)) -ge $CHECK_INTERVAL ]; then
            SUSPICIOUS=0

            # Run all checks
            check_cellular_info || SUSPICIOUS=1
            check_frequency_hopping || SUSPICIOUS=1
            check_network_connections || SUSPICIOUS=1
            check_suspicious_processes || SUSPICIOUS=1

            if [ $SUSPICIOUS -eq 1 ]; then
                SUSPICIOUS_PATTERNS=$((SUSPICIOUS_PATTERNS + 1))
                if [ $SUSPICIOUS_PATTERNS -ge $ALERT_THRESHOLD ]; then
                    alert "Multiple suspicious patterns detected! Potential Stingray device in range."
                    apply_countermeasures
                    SUSPICIOUS_PATTERNS=0
                fi
            else
                SUSPICIOUS_PATTERNS=0
            fi

            LAST_CHECK=$CURRENT_TIME
        fi

        sleep 1
    done
}

# Handle script termination
trap 'log "${YELLOW}Monitoring stopped${NC}"; exit 0' INT TERM

# Start monitoring
main 