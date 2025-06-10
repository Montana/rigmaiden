#!/bin/bash
[ "$EUID" -ne 0 ] && echo "Please run as root" && exit 1
mkdir -p /var/log/rigmaiden /etc/rigmaiden
[ "$(uname)" == "Darwin" ] && brew install python3 && pip3 install -r requirements.txt || (apt-get update && apt-get install -y python3 python3-pip usbutils && pip3 install -r requirements.txt)
echo '{"enabled":true,"monitor":true,"do_cleanup":true}' > /etc/rigmaiden/config.json
echo '/var/log/rigmaiden/*.log {daily rotate 7 compress delaycompress missingok notifempty create 644 root root}' > /etc/logrotate.d/rigmaiden
chmod +x rigmaiden.py cellebrite.py jiggler_block.py
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    (echo '[Unit]\nDescription=Rigmaiden Security Service\nAfter=network.target\n\n[Service]\nType=simple\nUser=root\nExecStart=/usr/bin/python3 '"$(pwd)"'/rigmaiden.py\nRestart=always\nRestartSec=3\n\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/rigmaiden.service && systemctl daemon-reload && systemctl enable rigmaiden && systemctl start rigmaiden)
elif [[ "$OSTYPE" == "darwin"* ]]; then
    (echo '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n<key>Label</key>\n<string>com.rigmaiden</string>\n<key>ProgramArguments</key>\n<array>\n<string>/usr/bin/python3</string>\n<string>'"$(pwd)"'/rigmaiden.py</string>\n</array>\n<key>RunAtLoad</key>\n<true/>\n<key>KeepAlive</key>\n<true/>\n<key>StandardErrorPath</key>\n<string>/var/log/rigmaiden/error.log</string>\n<key>StandardOutPath</key>\n<string>/var/log/rigmaiden/output.log</string>\n</dict>\n</plist>' > ~/Library/LaunchAgents/com.rigmaiden.plist && launchctl load ~/Library/LaunchAgents/com.rigmaiden.plist)
fi
read -p "Run tools now? (y/n) " -n 1 -r && echo && [[ $REPLY =~ ^[Yy]$ ]] && (python3 rigmaiden.py & python3 cellebrite.py & python3 jiggler_block.py &) 