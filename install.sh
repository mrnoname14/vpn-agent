#!/bin/bash
# VPN Agent Installer
# Usage: curl -sSL https://raw.githubusercontent.com/mrnoname14/vpn-agent/main/install.sh | bash -s TOKEN

set -e

TOKEN="${1:-}"
AGENT_URL="https://raw.githubusercontent.com/mrnoname14/vpn-agent/main/vpn_agent.py"

echo "=== VPN Agent Installer ==="

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Run as root"
    exit 1
fi

# Generate token if not provided
if [ -z "$TOKEN" ]; then
    TOKEN=$(openssl rand -hex 32)
    echo "Generated token: $TOKEN"
fi

# Install Flask if needed
pip3 install flask -q 2>/dev/null || apt-get install -y python3-flask -qq

# Download agent
echo "Downloading agent..."
curl -sSL -o /opt/vpn_agent.py "$AGENT_URL"
chmod +x /opt/vpn_agent.py

# Create systemd service
echo "Creating systemd service..."
cat > /etc/systemd/system/vpn-agent.service << SVCEOF
[Unit]
Description=VPN Health Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/vpn_agent.py
Environment="VPN_AGENT_TOKEN=$TOKEN"
Environment="VPN_AGENT_UPDATE_URL=$AGENT_URL"
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

# Start service
systemctl daemon-reload
systemctl enable vpn-agent
systemctl restart vpn-agent

# Save token
echo "$TOKEN" > /opt/vpn_agent_token.txt
chmod 600 /opt/vpn_agent_token.txt

# Open firewall
ufw allow 8080/tcp 2>/dev/null || true

echo ""
echo "=== Installation Complete ==="
echo "Token: $TOKEN"
echo "Test:  curl http://localhost:8080/"
echo "============================"
