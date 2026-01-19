# 🌐 Network Monitor

A Python-based network sniffer and device discovery tool for home LAN and WiFi networks. Identifies devices by OUI (MAC address manufacturer lookup) without requiring any agents on target devices.

## Features

- **Network Sniffing** - Captures packets on both Ethernet and WiFi interfaces
- **Device Discovery** - ARP scanning and passive discovery to find all network devices  
- **OUI Lookup** - Identifies device manufacturers from MAC addresses (Apple, Samsung, Intel, etc.)
- **Real-time Dashboard** - Beautiful web interface with live traffic stats
- **Traffic Analysis** - Per-device bandwidth tracking and protocol distribution
- **No Agents Required** - All discovery is done passively without touching target devices

## Requirements

- Python 3.8+
- Root/sudo privileges (required for packet capture)
- Linux with working network interfaces

## Installation

```bash
# Clone or navigate to the project
cd net1

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Full Monitoring (with Dashboard)

```bash
# Start full monitoring with web dashboard
sudo python main.py

# Dashboard will be available at http://localhost:5000
```

### Discovery Only

```bash
# Just discover devices without continuous sniffing
sudo python main.py --discover
```

### Sniffer Only (CLI)

```bash
# Run packet sniffer with CLI output (no web dashboard)
sudo python main.py --sniff
```

### Command Line Options

```bash
sudo python main.py --help

Options:
  --discover          Only run device discovery, no sniffing
  --sniff            Only run packet sniffer, no dashboard
  --port PORT        Dashboard port (default: 5000)
  --host HOST        Dashboard host (default: 0.0.0.0)
  --debug            Enable debug mode
  --ethernet IFACE   Ethernet interface (default: enp2s0)
  --wifi IFACE       WiFi interface (default: wlp3s0)
```

## Project Structure

```
net1/
├── main.py                    # Main entry point
├── config.py                  # Configuration settings
├── oui_database.py            # OUI/MAC manufacturer lookup
├── device_discovery.py        # Device discovery (ARP scanning)
├── packet_sniffer.py          # Packet capture and analysis
├── data_store.py              # SQLite database for persistence
├── requirements.txt           # Python dependencies
├── dashboard/
│   ├── app.py                 # Flask web server
│   ├── static/
│   │   └── styles.css         # Dashboard styling
│   └── templates/
│       └── index.html         # Dashboard template
└── README.md
```

## How Device Identification Works

Devices are identified using multiple agentless techniques:

1. **OUI (Organizationally Unique Identifier)** - The first 3 bytes of a MAC address identify the manufacturer (e.g., `B8:27:EB` = Raspberry Pi)

2. **ARP Scanning** - Sends ARP requests to discover all devices on the local subnet

3. **Passive Sniffing** - Learns about devices by observing their network traffic

4. **Hostname Resolution** - Attempts reverse DNS lookup for discovered IP addresses

## Dashboard Features

- **Device Cards** - Visual representation of all discovered devices
- **Live Traffic Stats** - Real-time packets and bytes per device
- **Top Talkers** - Devices consuming the most bandwidth
- **Protocol Distribution** - What protocols each device is using (HTTP, DNS, etc.)
- **WebSocket Updates** - Live updates without page refresh

## Configuration

Edit `config.py` to customize:

```python
# Network interfaces
INTERFACES = {
    'ethernet': 'enp2s0',
    'wifi': 'wlp3s0'
}

# Dashboard settings
DASHBOARD_PORT = 5000
DASHBOARD_HOST = '0.0.0.0'

# Scanning intervals
ARP_SCAN_INTERVAL = 60  # seconds
DEVICE_TIMEOUT = 300    # mark inactive after this many seconds
```

## Security Notes

- Requires root privileges to capture packets
- Only monitors traffic visible to your network interface
- Does not decrypt encrypted traffic (HTTPS, etc.)
- For home/personal network monitoring only

## Troubleshooting

**Permission denied errors:**
```bash
# Run with sudo
sudo python main.py
```

**Interface not found:**
```bash
# List your network interfaces
ip link show

# Specify correct interfaces
sudo python main.py --ethernet eth0 --wifi wlan0
```

**No devices discovered:**
- Ensure you're connected to the network
- Check that the interface names are correct
- Some networks may block ARP scans

## License

MIT License - Feel free to use and modify for your own networks.
