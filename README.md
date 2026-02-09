# 🌐 Network Monitor

A Python-based network sniffer and device discovery tool for home LAN and WiFi networks. Identifies devices using multiple agentless techniques including OUI lookup, mDNS/Bonjour, SSDP/UPnP, DHCP fingerprinting, and more — all without requiring any agents on target devices.

## Features

### Discovery & Identification
- **OUI Lookup** - Identifies device manufacturers from MAC addresses (Apple, Samsung, Intel, etc.)
- **mDNS/Bonjour Listener** - Discovers Apple devices, Chromecasts, printers, and smart home devices
- **SSDP/UPnP Discovery** - Finds routers, smart TVs, gaming consoles, and IoT devices
- **DHCP Fingerprinting** - Identifies device OS from DHCP option patterns (Windows, iOS, Android, etc.)
- **NetBIOS Resolution** - Resolves Windows hostnames and workgroup info
- **Randomized MAC Detection** - Identifies phones/tablets using privacy-preserving random MACs

### Network Analysis  
- **Packet Sniffing** - Captures traffic on both Ethernet and WiFi interfaces simultaneously
- **SNI Extraction** - Reveals HTTPS destination hostnames from TLS handshakes
- **Traffic Analysis** - Per-device bandwidth tracking with protocol distribution
- **ARP Scanning** - Active network scanning to discover all devices on the subnet

### Dashboard
- **Real-time Web UI** - Beautiful dashboard with live traffic stats via WebSocket
- **Device Cards** - Visual representation of all discovered devices with metadata
- **Top Talkers** - Devices consuming the most bandwidth
- **Manual Rescan** - Trigger network discovery on-demand
- **MITM Monitoring** - Optional ARP spoofing for deep packet inspection (use responsibly)

## Requirements

- Python 3.8+
- Root/sudo privileges (required for packet capture)
- Linux with working network interfaces

## Installation

```bash
# Clone or navigate to the project
cd net1

# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Full Monitoring (with Dashboard)

```bash
# Using the wrapper script (recommended)
sudo ./run.sh

# Or directly with Python
sudo .venv/bin/python main.py

# Dashboard will be available at http://localhost:5000
```

### Discovery Only

```bash
# Just discover devices without continuous sniffing
sudo ./run.sh --discover
```

### Sniffer Only (CLI)

```bash
# Run packet sniffer with CLI output (no web dashboard)
sudo ./run.sh --sniff
```

### Command Line Options

```bash
sudo ./run.sh --help

Options:
  --discover          Only run device discovery, no sniffing
  --sniff             Only run packet sniffer, no dashboard
  --port PORT         Dashboard port (default: 5000)
  --host HOST         Dashboard host (default: 0.0.0.0)
  --debug             Enable debug mode
  --ethernet IFACE    Ethernet interface (default: enp2s0)
  --wifi IFACE        WiFi interface (default: wlp3s0)
```

## Project Structure

```
net1/
├── main.py                 # Entry point and CLI
├── network_monitor.py      # Core logic: config, data store, discovery, sniffer
├── device_fingerprint.py   # Device fingerprinting (mDNS, SSDP, DHCP, NetBIOS)
├── oui_database.py         # OUI/MAC manufacturer lookup
├── requirements.txt        # Python dependencies
├── run.sh                  # Wrapper script for sudo + venv
├── dashboard/
│   ├── app.py              # FastAPI web server
│   ├── static/
│   │   └── styles.css      # Dashboard styling
│   └── templates/
│       └── index.html      # Dashboard template
└── README.md
```

## How Device Identification Works

Devices are identified using multiple agentless techniques:

| Method | What It Detects | How |
|--------|-----------------|-----|
| **OUI Lookup** | Manufacturer | First 3 bytes of MAC identify vendor (e.g., `B8:27:EB` = Raspberry Pi) |
| **mDNS/Bonjour** | Device type, hostname | Listens on port 5353 for service announcements |
| **SSDP/UPnP** | Device model, services | Listens on port 1900 for NOTIFY messages |
| **DHCP Fingerprint** | Operating system | Analyzes DHCP option 55 patterns |
| **HTTP User-Agent** | Browser/app info | Parses User-Agent headers from HTTP traffic |
| **TLS SNI** | HTTPS destinations | Extracts hostnames from TLS Client Hello |
| **Passive Traffic** | Activity patterns | Learns devices by observing their network traffic |

## Configuration

Configuration is at the top of `network_monitor.py`:

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
ARP_SCAN_INTERVAL = 0       # 0 = disabled, rely on passive discovery
DEVICE_TIMEOUT = 300        # Mark inactive after this many seconds

# Host exclusion (e.g., SPAN port mirror host)
EXCLUDED_IPS = {'10.0.0.151'}
EXCLUDED_HOSTNAMES = {'crypto1', 'crypto1.local'}
```

## Dashboard Features

- **Device Cards** - Shows manufacturer, hostname, IP, MAC, device type, and discovery method
- **Live Traffic Stats** - Real-time packets and bytes per device
- **Top Talkers** - Devices consuming the most bandwidth (last hour)
- **WebSocket Updates** - Live updates every 5 seconds without page refresh
- **Rescan Button** - Trigger manual ARP scan to discover new devices
- **Shutdown Button** - Gracefully stop the monitor from the web UI

## API Endpoints

The dashboard exposes a REST API:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/summary` | GET | Dashboard summary stats |
| `/api/devices` | GET | All active devices |
| `/api/devices/all` | GET | All devices including inactive |
| `/api/top-talkers` | GET | Top bandwidth consumers |
| `/api/connections` | GET | Recent connection history |
| `/api/live-stats` | GET | Current sniffer statistics |
| `/api/rescan` | POST | Trigger network rescan |
| `/api/shutdown` | POST | Shutdown the application |
| `/ws` | WebSocket | Real-time stats stream |

## Security Notes

- ⚠️ **Requires root privileges** to capture packets
- Only monitors traffic visible to your network interface
- Does not decrypt encrypted traffic (but extracts SNI hostnames from HTTPS)
- MITM features use ARP spoofing — **use only on networks you own**
- For home/personal network monitoring only

## Troubleshooting

**Permission denied errors:**
```bash
# Run with sudo
sudo ./run.sh
```

**Interface not found:**
```bash
# List your network interfaces
ip link show

# Specify correct interfaces
sudo ./run.sh --ethernet eth0 --wifi wlan0
```

**No devices discovered:**
- Ensure you're connected to the network
- Check that the interface names are correct in the config
- Some networks may block ARP scans

**Dashboard not loading:**
- Check that port 5000 isn't already in use
- Try a different port: `sudo ./run.sh --port 8080`

## License

MIT License - Feel free to use and modify for your own networks.
