"""
Network Monitor - Core Logic
Combines configuration, data storage, device discovery, and packet sniffing into a single module.
"""
import os
import sys
import logging
import threading
import time
import socket
import sqlite3
import json
import signal
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Callable, Set
from contextlib import contextmanager
from functools import lru_cache

# Try to import scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, DNS, conf, srp, get_if_addr, get_if_hwaddr
    SCAPY_AVAILABLE = True
except Exception as e:
    # We will log the error after the logger is initialized
    _SCAPY_ERROR = e
    SCAPY_AVAILABLE = False
    # Define dummies to avoid NameError
    def sniff(*args, **kwargs): pass
    def get_if_addr(iface): return '0.0.0.0'
    def get_if_hwaddr(iface): return '00:00:00:00:00:00'
    class conf: verb = 0
    class IP: pass
    class TCP: pass
    class UDP: pass
    class ICMP: pass
    class ARP: pass
    class Ether: pass
    class DNS: pass
    def srp(*args, **kwargs): return ([], [])
    
# Import OUI database wrapper
try:
    from oui_database import OUIDatabase, get_device_info, lookup_manufacturer
except ImportError:
    # Fallback if separate file not found (though it should be there)
    class OUIDatabase:
        def lookup(self, mac): return "Unknown"
        def get_device_info(self, mac): return {'manufacturer': 'Unknown', 'is_virtual': False}
    def get_device_info(mac): return {'manufacturer': 'Unknown', 'is_virtual': False}
    def lookup_manufacturer(mac): return 'Unknown'

# Import device fingerprinter
try:
    from device_fingerprint import fingerprinter, DeviceFingerprinter
    FINGERPRINTING_AVAILABLE = True
except ImportError:
    FINGERPRINTING_AVAILABLE = False
    fingerprinter = None


logger = logging.getLogger('network_monitor')

# Log scapy error if it failed to import
if not SCAPY_AVAILABLE and '_SCAPY_ERROR' in globals():
    logger.error(f"Scapy import failed: {_SCAPY_ERROR}")
    logger.error("Sniffing and active scans will be disabled.")

# ==========================================
# CONFIGURATION
# ==========================================

# Network interfaces to monitor
INTERFACES = {
    'ethernet': 'enp2s0',
    'wifi': 'wlp3s0'
}

# Which interfaces to actively sniff (set to None to auto-detect active ones)
ACTIVE_INTERFACES = None

# Database settings
DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'network_data.db')

# Device discovery settings
ARP_SCAN_INTERVAL = 0  # 0 = disabled, rely on passive traffic discovery
DEVICE_TIMEOUT = 300

# Packet capture settings
PACKET_BUFFER_SIZE = 1000
STATS_UPDATE_INTERVAL = 5

# Dashboard settings
DASHBOARD_HOST = '0.0.0.0'
DASHBOARD_PORT = 5000
SECRET_KEY = os.environ.get('SECRET_KEY', 'network-monitor-secret-key-change-me')

# Host exclusion list (SPAN port, monitoring hosts, etc.)
# These hosts are completely ignored - no traffic stats, no database entries
EXCLUDED_IPS = {'10.0.0.151'}
EXCLUDED_HOSTNAMES = {'crypto1', 'crypto1.local'}
EXCLUDED_MACS = set()  # Add specific MACs if needed


def is_excluded_host(ip: str = None, hostname: str = None, mac: str = None) -> bool:
    """Check if a host should be excluded from monitoring"""
    if ip and ip in EXCLUDED_IPS:
        return True
    if hostname:
        hostname_lower = hostname.lower()
        if hostname_lower in EXCLUDED_HOSTNAMES or any(h in hostname_lower for h in EXCLUDED_HOSTNAMES):
            return True
    if mac and mac.upper() in EXCLUDED_MACS:
        return True
    return False

# Traffic categorization by port
KNOWN_PORTS = {
    80: 'HTTP',
    443: 'HTTPS',
    22: 'SSH',
    21: 'FTP',
    53: 'DNS',
    67: 'DHCP',
    68: 'DHCP',
    123: 'NTP',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    993: 'IMAPS',
    995: 'POP3S',
    3389: 'RDP',
    5353: 'mDNS',
    1900: 'SSDP/UPnP',
    137: 'NetBIOS',
    138: 'NetBIOS',
    139: 'NetBIOS',
    445: 'SMB',
    548: 'AFP',
    631: 'IPP/CUPS',
    5900: 'VNC',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
}


# ==========================================
# DATA STORE
# ==========================================

class DataStore:
    """Thread-safe SQLite data store for network monitoring data"""
    
    def __init__(self, db_path: str = DATABASE_PATH):
        self.db_path = db_path
        self._local = threading.local()
        self._init_schema()
    
    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection
    
    @contextmanager
    def _cursor(self):
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise
        finally:
            cursor.close()
    
    def _init_schema(self):
        with self._cursor() as cursor:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT, manufacturer TEXT,
                    device_type TEXT, custom_name TEXT, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_active BOOLEAN DEFAULT 1, metadata TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0, packets_sent INTEGER DEFAULT 0, packets_received INTEGER DEFAULT 0
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, protocol TEXT,
                    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER,
                    service TEXT, bytes_total INTEGER DEFAULT 0, packets INTEGER DEFAULT 0
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_mac ON traffic_stats(mac)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic_stats(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_conn_mac ON connections(mac)')
    
    def upsert_device(self, mac: str, ip: str = None, hostname: str = None,
                      manufacturer: str = None, device_type: str = None, metadata: dict = None):
        with self._cursor() as cursor:
            cursor.execute('''
                INSERT INTO devices (mac, ip, hostname, manufacturer, device_type, metadata, last_seen, is_active)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 1)
                ON CONFLICT(mac) DO UPDATE SET 
                    ip = COALESCE(excluded.ip, ip),
                    hostname = COALESCE(excluded.hostname, hostname),
                    manufacturer = COALESCE(excluded.manufacturer, manufacturer),
                    device_type = COALESCE(excluded.device_type, device_type),
                    metadata = COALESCE(excluded.metadata, metadata),
                    last_seen = CURRENT_TIMESTAMP, is_active = 1
            ''', (mac, ip, hostname, manufacturer, device_type, json.dumps(metadata) if metadata else None))
    
    def get_all_devices(self, active_only: bool = True) -> List[Dict]:
        with self._cursor() as cursor:
            if active_only:
                cursor.execute('SELECT * FROM devices WHERE is_active = 1 ORDER BY last_seen DESC')
            else:
                cursor.execute('SELECT * FROM devices ORDER BY last_seen DESC')
            return [dict(row) for row in cursor.fetchall()]

    def get_device(self, mac: str) -> Optional[Dict]:
        """Fetch a single device by MAC from database"""
        with self._cursor() as cursor:
            cursor.execute('SELECT * FROM devices WHERE mac = ?', (mac,))
            row = cursor.fetchone()
            return dict(row) if row else None

    
    def record_traffic(self, mac: str, bytes_sent: int = 0, bytes_received: int = 0,
                       packets_sent: int = 0, packets_received: int = 0):
        with self._cursor() as cursor:
            cursor.execute('''INSERT INTO traffic_stats (mac, bytes_sent, bytes_received, packets_sent, packets_received)
                VALUES (?, ?, ?, ?, ?)''', (mac, bytes_sent, bytes_received, packets_sent, packets_received))
    
    def get_top_talkers(self, hours: int = 1, limit: int = 10) -> List[Dict]:
        cutoff = datetime.now() - timedelta(hours=hours)
        with self._cursor() as cursor:
            cursor.execute('''
                SELECT d.mac, d.ip, d.hostname, d.manufacturer, d.custom_name,
                    COALESCE(SUM(t.bytes_sent), 0) + COALESCE(SUM(t.bytes_received), 0) as total_bytes,
                    COALESCE(SUM(t.bytes_sent), 0) as bytes_sent, COALESCE(SUM(t.bytes_received), 0) as bytes_received
                FROM devices d LEFT JOIN traffic_stats t ON d.mac = t.mac AND t.timestamp > ?
                WHERE d.is_active = 1 GROUP BY d.mac ORDER BY total_bytes DESC LIMIT ?
            ''', (cutoff, limit))
            return [dict(row) for row in cursor.fetchall()]
    
    def record_connection(self, mac: str, protocol: str, src_ip: str, src_port: int,
                          dst_ip: str, dst_port: int, service: str = None, bytes_total: int = 0, packets: int = 0):
        with self._cursor() as cursor:
            cursor.execute('''INSERT INTO connections (mac, protocol, src_ip, src_port, dst_ip, dst_port, service, bytes_total, packets)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', (mac, protocol, src_ip, src_port, dst_ip, dst_port, service, bytes_total, packets))
    
    def get_recent_connections(self, mac: str = None, limit: int = 100) -> List[Dict]:
        with self._cursor() as cursor:
            if mac:
                cursor.execute('SELECT * FROM connections WHERE mac = ? ORDER BY timestamp DESC LIMIT ?', (mac, limit))
            else:
                cursor.execute('SELECT * FROM connections ORDER BY timestamp DESC LIMIT ?', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_dashboard_summary(self) -> Dict:
        with self._cursor() as cursor:
            cursor.execute('SELECT COUNT(*) as count FROM devices WHERE is_active = 1')
            active_devices = cursor.fetchone()['count']
            cursor.execute('SELECT COUNT(*) as count FROM devices')
            total_devices = cursor.fetchone()['count']
            cutoff = datetime.now() - timedelta(hours=1)
            cursor.execute('SELECT COALESCE(SUM(bytes_sent), 0) as sent, COALESCE(SUM(bytes_received), 0) as received FROM traffic_stats WHERE timestamp > ?', (cutoff,))
            traffic = cursor.fetchone()
            return {'active_devices': active_devices, 'total_devices': total_devices,
                    'bytes_sent_hour': traffic['sent'], 'bytes_received_hour': traffic['received'],
                    'timestamp': datetime.now().isoformat()}
    
    def mark_inactive_devices(self, timeout_seconds: int = 300) -> int:
        cutoff = datetime.now() - timedelta(seconds=timeout_seconds)
        with self._cursor() as cursor:
            cursor.execute('UPDATE devices SET is_active = 0 WHERE last_seen < ? AND is_active = 1', (cutoff,))
            return cursor.rowcount

# Initialize singleton
db = DataStore()


# ==========================================
# DEVICE DISCOVERY
# ==========================================

@dataclass
class NetworkDevice:
    """Represents a discovered network device"""
    mac: str
    ip: str = None
    hostname: str = None
    manufacturer: str = None
    device_type: str = None
    last_seen: datetime = field(default_factory=datetime.now)
    discovery_method: str = 'unknown'
    metadata: Dict = field(default_factory=dict)


class DeviceDiscovery:
    """Discovers devices on the local network using agentless methods"""
    
    def __init__(self, interfaces: List[str] = None):
        self.interfaces = interfaces or [INTERFACES['ethernet'], INTERFACES['wifi']]
        self.devices: Dict[str, NetworkDevice] = {}
        self._running = False
        self._scan_thread = None
        self._callbacks: List[Callable] = []
        
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available - install with: pip install scapy")
    
    def add_callback(self, callback: Callable[[NetworkDevice], None]):
        """Add callback for new device discovery"""
        self._callbacks.append(callback)
    
    def _notify_callbacks(self, device: NetworkDevice):
        """Notify all callbacks of device discovery"""
        for callback in self._callbacks:
            try:
                callback(device)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    def get_local_network(self, interface: str) -> Optional[str]:
        """Get the local network CIDR for an interface"""
        if not SCAPY_AVAILABLE:
            return None
        try:
            ip = get_if_addr(interface)
            if ip and ip != '0.0.0.0':
                # Assume /24 network (common for home networks)
                parts = ip.split('.')
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception as e:
            logger.warning(f"Could not get network for {interface}: {e}")
        return None
    
    def arp_scan(self, network: str, interface: str = None, timeout: int = 3) -> List[NetworkDevice]:
        """Perform ARP scan to discover devices on the network"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy required for ARP scanning")
            return []
        
        discovered = []
        try:
            conf.verb = 0  # Suppress scapy output
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            logger.info(f"ARP scanning {network} on {interface or 'default'}...")
            result = srp(packet, timeout=timeout, iface=interface, verbose=False)[0]
            
            for sent, received in result:
                mac = received.hwsrc.upper()
                ip = received.psrc
                
                # Get manufacturer info
                device_info = get_device_info(mac)
                
                # Try to resolve hostname
                hostname = self._resolve_hostname(ip)
                
                # Skip excluded hosts (SPAN port, etc.)
                if is_excluded_host(ip=ip, hostname=hostname, mac=mac):
                    logger.debug(f"Skipping excluded host: {ip} ({mac})")
                    continue
                
                device = NetworkDevice(
                    mac=mac,
                    ip=ip,
                    hostname=hostname,
                    manufacturer=device_info['manufacturer'],
                    discovery_method='arp',
                    metadata={'is_virtual': device_info['is_virtual']}
                )
                
                discovered.append(device)
                self.devices[mac] = device
                
                # Store in database
                db.upsert_device(mac=mac, ip=ip, hostname=hostname,
                                manufacturer=device_info['manufacturer'],
                                metadata={'is_virtual': device_info['is_virtual']})
                
                # Register IP-MAC mapping and queue for active probing
                if FINGERPRINTING_AVAILABLE:
                    from device_fingerprint import is_randomized_mac
                    fingerprinter.register_ip_mac(ip, mac)
                    # Probe if manufacturer is Unknown (randomized MAC or missing OUI)
                    if device_info['manufacturer'] == 'Unknown':
                        fingerprinter.probe_ip(ip)
                        # Also label randomized MACs as likely mobile devices
                        if is_randomized_mac(mac):
                            db.upsert_device(mac=mac, ip=ip, device_type='Mobile Device')
                
                logger.info(f"Discovered: {ip} ({mac}) - {device_info['manufacturer']}")
                self._notify_callbacks(device)
                
        except PermissionError:
            logger.error("Permission denied. Run with sudo for ARP scanning.")
        except Exception as e:
            logger.error(f"ARP scan error: {e}")
        
        return discovered
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Try to resolve hostname from IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def scan_all_interfaces(self) -> List[NetworkDevice]:
        """Scan all configured interfaces"""
        all_devices = []
        for interface in self.interfaces:
            network = self.get_local_network(interface)
            if network:
                devices = self.arp_scan(network, interface)
                all_devices.extend(devices)
        return all_devices
    
    def start_background_scan(self, interval: int = ARP_SCAN_INTERVAL):
        """Start background scanning thread"""
        if self._running:
            return
        
        # Interval 0 means disabled - rely on passive discovery
        if interval == 0:
            logger.info("ARP scanning disabled - relying on passive traffic discovery")
            return
        
        self._running = True
        
        def scan_loop():
            while self._running:
                try:
                    self.scan_all_interfaces()
                    # Mark devices not seen recently as inactive
                    db.mark_inactive_devices()
                except Exception as e:
                    logger.error(f"Background scan error: {e}")
                time.sleep(interval)
        
        self._scan_thread = threading.Thread(target=scan_loop, daemon=True)
        self._scan_thread.start()
        logger.info(f"Background device scanning started (interval: {interval}s)")
    
    def stop_background_scan(self):
        """Stop background scanning"""
        self._running = False
        if self._scan_thread:
            self._scan_thread.join(timeout=5)
            self._scan_thread = None
        logger.info("Background device scanning stopped")
    
    def process_packet_device(self, mac: str, ip: str = None):
        """Process a device seen in packet capture"""
        if mac in self.devices:
            self.devices[mac].last_seen = datetime.now()
        else:
            device_info = get_device_info(mac)
            hostname = self._resolve_hostname(ip) if ip else None
            device = NetworkDevice(
                mac=mac, ip=ip, hostname=hostname,
                manufacturer=device_info['manufacturer'],
                discovery_method='passive',
                metadata={'is_virtual': device_info['is_virtual']}
            )
            self.devices[mac] = device
            self._notify_callbacks(device)
        
        # Update database
        db.upsert_device(mac=mac, ip=ip, manufacturer=lookup_manufacturer(mac))

# Initialize singleton
discovery = DeviceDiscovery()


# ==========================================
# PACKET SNIFFER
# ==========================================

@dataclass
class TrafficStats:
    """Traffic statistics for a device"""
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    protocols: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    services: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    last_activity: datetime = field(default_factory=datetime.now)


class PacketSniffer:
    """Captures and analyzes network packets"""
    
    def __init__(self, interfaces: List[str] = None):
        self.interfaces = interfaces or [INTERFACES['ethernet'], INTERFACES['wifi']]
        self._running = False
        self._sniff_threads: List[threading.Thread] = []
        self._stats: Dict[str, TrafficStats] = defaultdict(TrafficStats)
        self._stats_lock = threading.Lock()
        self._callbacks: List[Callable] = []
        self._local_macs: set = set()
        self._local_ips: set = set()
        self._last_flush = time.time()
        
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available - install with: pip install scapy")
        
        self._detect_local_addresses()
    
    def _detect_local_addresses(self):
        """Detect local MAC and IP addresses by interface"""
        if not SCAPY_AVAILABLE:
            return
        self._iface_info = {} # interface -> {'mac': mac, 'ip': ip}
        try:
            for iface in self.interfaces:
                if not os.path.exists(f"/sys/class/net/{iface}"):
                    continue
                try:
                    mac = get_if_hwaddr(iface)
                    ip = get_if_addr(iface)
                    if mac:
                        mac = mac.upper()
                        self._local_macs.add(mac)
                        if ip and ip != '0.0.0.0':
                            self._local_ips.add(ip)
                            self._iface_info[iface] = {'mac': mac, 'ip': ip}
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Could not detect local addresses: {e}")

    
    def add_callback(self, callback: Callable):
        """Add callback for packet events"""
        self._callbacks.append(callback)
    
    def _get_service(self, port: int) -> str:
        """Get service name from port number"""
        return KNOWN_PORTS.get(port, f'port-{port}')
    
    def _extract_sni(self, data: bytes) -> Optional[str]:
        """
        Extract SNI (Server Name Indication) from TLS Client Hello packet.
        SNI is sent in cleartext and reveals the hostname for HTTPS connections.
        """
        try:
            # Check if this is a TLS handshake
            if len(data) < 6:
                return None
            
            # TLS Record: ContentType=22 (Handshake), Version, Length
            if data[0] != 0x16:  # Not a handshake
                return None
            
            # Skip TLS record header (5 bytes)
            offset = 5
            
            # Handshake: Type=1 (ClientHello)
            if data[offset] != 0x01:
                return None
            
            # Skip handshake header
            offset += 4  # type (1) + length (3)
            
            # Skip client version (2) + random (32) 
            offset += 2 + 32
            
            # Skip session ID
            if offset >= len(data):
                return None
            session_id_len = data[offset]
            offset += 1 + session_id_len
            
            # Skip cipher suites
            if offset + 2 > len(data):
                return None
            cipher_len = (data[offset] << 8) + data[offset + 1]
            offset += 2 + cipher_len
            
            # Skip compression methods
            if offset >= len(data):
                return None
            comp_len = data[offset]
            offset += 1 + comp_len
            
            # Extensions length
            if offset + 2 > len(data):
                return None
            ext_len = (data[offset] << 8) + data[offset + 1]
            offset += 2
            
            # Parse extensions looking for SNI (type 0)
            ext_end = offset + ext_len
            while offset + 4 <= ext_end and offset + 4 <= len(data):
                ext_type = (data[offset] << 8) + data[offset + 1]
                ext_len_inner = (data[offset + 2] << 8) + data[offset + 3]
                offset += 4
                
                if ext_type == 0:  # SNI Extension
                    # SNI list length
                    if offset + 2 > len(data):
                        return None
                    offset += 2  # Skip list length
                    
                    # Name type (should be 0 for hostname)
                    if offset >= len(data) or data[offset] != 0:
                        return None
                    offset += 1
                    
                    # Name length
                    if offset + 2 > len(data):
                        return None
                    name_len = (data[offset] << 8) + data[offset + 1]
                    offset += 2
                    
                    # Extract hostname
                    if offset + name_len <= len(data):
                        return data[offset:offset + name_len].decode('ascii', errors='ignore')
                    return None
                
                offset += ext_len_inner
            
        except Exception:
            pass
        return None
    
    def _record_sni(self, ip: str, mac: str, sni: str):
        """Record SNI hostname for traffic analysis"""
        # Log first time we see this domain from this device
        key = f"{mac}:{sni}"
        if not hasattr(self, '_seen_sni'):
            self._seen_sni = set()
        if key not in self._seen_sni:
            self._seen_sni.add(key)
            logger.info(f"🔒 [HTTPS] {ip} -> {sni}")
    
    def _process_packet(self, packet):
        """Process a captured packet"""
        try:
            if not packet.haslayer(Ether):
                return
            
            src_mac = packet[Ether].src.upper()
            dst_mac = packet[Ether].dst.upper()
            
            # Skip IPv6 Multicast entirely
            if dst_mac.startswith('33:33'):
                return
                
            packet_len = len(packet)

            is_broadcast = dst_mac == 'FF:FF:FF:FF:FF:FF' or dst_mac.startswith('01:00:5E')
            
            # Determine direction based on local MACs
            is_outgoing = src_mac in self._local_macs
            is_incoming = dst_mac in self._local_macs
            
            # Prevent double-counting and manufacturer flapping during MITM:
            # Ignore packets WE are sending (forwarding)
            if is_outgoing:
                return
            
            # Extract protocol info
            protocol = 'other'
            src_ip = dst_ip = None
            src_port = dst_port = 0
            service = None
            
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                # Skip excluded hosts (SPAN port, etc.) - check early for performance
                if is_excluded_host(ip=src_ip) or is_excluded_host(ip=dst_ip):
                    return
                
                if packet.haslayer(TCP):
                    protocol = 'TCP'
                    tcp = packet[TCP]
                    src_port = tcp.sport
                    dst_port = tcp.dport
                    service = self._get_service(min(src_port, dst_port))
                    # Process HTTP for User-Agent fingerprinting
                    if (src_port == 80 or dst_port == 80) and FINGERPRINTING_AVAILABLE:
                        try:
                            fingerprinter.process_http(packet)
                        except Exception as e:
                            logger.debug(f"HTTP UA error: {e}")
                    # Extract SNI from HTTPS TLS handshakes
                    elif dst_port == 443 and tcp.payload:
                        sni = self._extract_sni(bytes(tcp.payload))
                        if sni:
                            service = f"HTTPS:{sni}"
                            self._record_sni(src_ip, src_mac, sni)
                elif packet.haslayer(UDP):
                    protocol = 'UDP'
                    udp = packet[UDP]
                    src_port = udp.sport
                    dst_port = udp.dport
                    service = self._get_service(min(src_port, dst_port))
                    if packet.haslayer(DNS):
                        service = 'DNS'
                    # Process DHCP for fingerprinting
                    if (src_port in (67, 68) or dst_port in (67, 68)) and FINGERPRINTING_AVAILABLE:
                        logger.info(f"💾 DHCP packet detected from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                        try:
                            res = fingerprinter.process_dhcp(packet)
                            if res:
                                logger.info(f"✅ DHCP Fingerprint: {res.get('mac')} -> {res.get('os_guess')} (Lease: {res.get('lease_time')}s)")
                        except Exception as e:
                            logger.error(f"DHCP fingerprint error: {e}")
                elif packet.haslayer(ICMP):
                    protocol = 'ICMP'
                    service = 'ICMP'
                else:
                    protocol = 'IP-other'
            elif packet.haslayer(ARP):
                protocol = 'ARP'
                service = 'ARP'
                arp = packet[ARP]
                src_ip = arp.psrc
                dst_ip = arp.pdst
            
            with self._stats_lock:
                # Track source device
                if src_mac and src_mac != 'FF:FF:FF:FF:FF:FF':
                    stats = self._stats[src_mac]
                    stats.bytes_sent += packet_len
                    stats.packets_sent += 1
                    stats.protocols[protocol] += 1
                    if service:
                        stats.services[service] += 1
                    stats.last_activity = datetime.now()
                    
                    # Notify device discovery
                    discovery.process_packet_device(src_mac, src_ip)
                    
                    # Register with fingerprinter for IP-MAC mapping
                    if FINGERPRINTING_AVAILABLE and src_ip:
                        fingerprinter.register_ip_mac(src_ip, src_mac)
                
                # Track destination device (if not broadcast)
                if dst_mac and not is_broadcast and dst_mac not in self._local_macs:
                    stats = self._stats[dst_mac]
                    stats.bytes_received += packet_len
                    stats.packets_received += 1
                    stats.last_activity = datetime.now()
                    discovery.process_packet_device(dst_mac, dst_ip)
            
            # Periodic flush to database
            if time.time() - self._last_flush > STATS_UPDATE_INTERVAL:
                self._flush_stats()
                
        except Exception as e:
            logger.debug(f"Packet processing error: {e}")
    
    def _flush_stats(self):
        """Flush accumulated stats to database"""
        with self._stats_lock:
            for mac, stats in self._stats.items():
                if stats.bytes_sent > 0 or stats.bytes_received > 0:
                    db.record_traffic(mac=mac, bytes_sent=stats.bytes_sent, bytes_received=stats.bytes_received,
                                     packets_sent=stats.packets_sent, packets_received=stats.packets_received)
            # Reset counters
            self._stats.clear()
            self._last_flush = time.time()
    
    def _sniff_interface(self, interface: str):
        """Sniff packets on a single interface"""
        logger.info(f"Starting packet capture on {interface}")
        try:
            sniff(iface=interface, prn=self._process_packet, store=False,
                  stop_filter=lambda x: not self._running)
        except PermissionError:
            logger.error(f"Permission denied for {interface}. Run with sudo.")
        except Exception as e:
            logger.error(f"Sniffing error on {interface}: {e}")
    
    def _is_interface_up(self, interface: str) -> bool:
        """Check if a network interface is actually usable and UP"""
        try:
            # Check operstate
            state_path = f"/sys/class/net/{interface}/operstate"
            if os.path.exists(state_path):
                with open(state_path, 'r') as f:
                    state = f.read().strip()
                    if state == 'down':
                        return False
            
            # Check flags (IFF_UP is bit 0)
            flags_path = f"/sys/class/net/{interface}/flags"
            if os.path.exists(flags_path):
                with open(flags_path, 'r') as f:
                    flags = int(f.read().strip(), 16)
                    if not (flags & 0x1): # IFF_UP
                        return False
            
            return True
        except Exception:
            return False

    def start(self):
        """Start packet capture on all usable interfaces"""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start sniffer - scapy not available")
            return
        
        if self._running:
            return
        
        self._running = True
        conf.verb = 0
        
        active_found = []
        for interface in self.interfaces:
            # Only start sniffing if interface exists and is UP
            if not os.path.exists(f"/sys/class/net/{interface}"):
                logger.debug(f"Interface {interface} does not exist, skipping.")
                continue
                
            if not self._is_interface_up(interface):
                logger.info(f"Interface {interface} is DOWN or RF-KILLED, skipping.")
                continue

            active_found.append(interface)
            thread = threading.Thread(target=self._sniff_interface, args=(interface,), daemon=True)
            thread.start()
            self._sniff_threads.append(thread)
        
        if active_found:
            logger.info(f"Packet sniffer started on: {', '.join(active_found)}")
            # Register only the host machine interfaces that are actually UP
            for iface in active_found:
                info = self._iface_info.get(iface)
                if info:
                    mac, ip = info['mac'], info['ip']
                    discovery.process_packet_device(mac, ip)
                    if FINGERPRINTING_AVAILABLE:
                        fingerprinter.register_ip_mac(ip, mac)
                        if mac in fingerprinter.devices:
                            fingerprinter.devices[mac].device_type = "Host Machine"
                            # Distinguish between interfaces
                            iface_type = "Eth" if "e" in iface.lower() else "WiFi"
                            fingerprinter.devices[mac].hostname = f"{socket.gethostname()} ({iface_type})"
                            fingerprinter.devices[mac].discovery_methods.append('local')
        else:
            logger.warning("No active network interfaces found to sniff!")



    
    def stop(self):
        """Stop packet capture"""
        self._running = False
        self._flush_stats()
        for thread in self._sniff_threads:
            thread.join(timeout=2)
        self._sniff_threads.clear()
        logger.info("Packet sniffer stopped")
    
    def get_live_stats(self) -> Dict[str, Dict]:
        """Get current live statistics"""
        # Needed to import dynamically or use singleton
        from oui_database import oui_db 
        
        with self._stats_lock:
            result = {}
            for mac, stats in self._stats.items():
                manufacturer = oui_db.lookup(mac) or 'Unknown'
                result[mac] = {
                    'mac': mac, 'manufacturer': manufacturer,
                    'bytes_sent': stats.bytes_sent, 'bytes_received': stats.bytes_received,
                    'packets_sent': stats.packets_sent, 'packets_received': stats.packets_received,
                    'protocols': dict(stats.protocols), 'services': dict(stats.services),
                    'last_activity': stats.last_activity.isoformat()
                }
            return result

# ==========================================
# ARP SPOOFER (MITM)
# ==========================================

class ArpSpoofer:
    """
    Performs ARP Spoofing to redirect traffic through this machine.
    WARNING: This is aggressive and can disrupt networks if not handled carefully.
    """
    def __init__(self):
        self._running = False
        self._spoof_thread = None
        self._gateway_ip = None
        self._gateway_mac = None
        self._targets: Dict[str, str] = {}  # IP -> MAC mapping of targets
        self._lock = threading.Lock()

    def get_gateway_info(self):
        """Find the default gateway IP and MAC"""
        if not SCAPY_AVAILABLE:
            return None, None
            
        try:
            # simple trick to get gateway ip
            gws = conf.route.route("0.0.0.0")
            gateway_ip = gws[2]
            
            # get gateway mac
            # We try a few times because sometimes it fails on first attempt
            gateway_mac = None
            for _ in range(3):
                packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=gateway_ip)
                result = srp(packet, timeout=2, verbose=False)[0]
                if result:
                    gateway_mac = result[0][1].hwsrc
                    break
                time.sleep(1)
                
            return gateway_ip, gateway_mac
        except Exception as e:
            logger.error(f"Error finding gateway: {e}")
            return None, None

    def add_target(self, ip: str, mac: str = None):
        """Add a target to spoof"""
        # Resolve MAC if not provided or invalid
        if not mac or mac == 'unknown':
            resolved_mac = self._resolve_mac(ip)
            if resolved_mac:
                mac = resolved_mac
            else:
                logger.warning(f"Cannot add target {ip}: MAC not resolvable")
                return
        
        with self._lock:
            self._targets[ip] = mac.upper()
            logger.info(f"Active monitoring target added: {ip} ({mac})")

    def remove_target(self, ip: str):
        """Stop spoofing a target"""
        with self._lock:
            if ip in self._targets:
                mac = self._targets[ip]
                del self._targets[ip]
                self._restore(self._gateway_ip, self._gateway_mac, ip, mac)
                logger.info(f"Active monitoring stopped for: {ip}")

    def start(self):
        """Start the spoofing thread"""
        if self._running or not SCAPY_AVAILABLE:
            return

        # Enable IP forwarding on Linux so we don't drop the packets!
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1')
        except Exception as e:
            logger.error(f"Could not enable IP forwarding: {e}")
            logger.error("Traffic will be dropped! Run: echo 1 > /proc/sys/net/ipv4/ip_forward")

        # Try to find default interface if multiple are active
        self._interface = None
        gateways = conf.route.routes
        if gateways:
            # Look for default route (destination 0.0.0.0)
            for r in gateways:
                if r[0] == 0:
                    self._interface = r[3]
                    break
        
        # Fallback to first sniffing interface if route extraction fails
        if not self._interface:
            self._interface = sniffer.interfaces[0]

        self._gateway_ip, self._gateway_mac = self.get_gateway_info()
        if not self._gateway_ip or not self._gateway_mac:
            logger.error(f"Could not find default gateway on {self._interface}. MITM failed.")
            return

        logger.info(f"Gateway found on {self._interface}: {self._gateway_ip} ({self._gateway_mac})")

        
        self._running = True
        self._spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._spoof_thread.start()
        logger.info("ARP Spoofing started")

    def stop(self):
        """Stop spoofing and restore network"""
        self._running = False
        if self._spoof_thread:
            self._spoof_thread.join(timeout=2)
            self._spoof_thread = None
        
        # Restore all targets
        with self._lock:
            for ip, mac in self._targets.items():
                self._restore(self._gateway_ip, self._gateway_mac, ip, mac)
            self._targets.clear()

    def _spoof_loop(self):
        """Main loop sending ARP packets"""
        while self._running:
            with self._lock:
                # Snapshot of targets to iterate safely
                current_targets = list(self._targets.items())

            for target_ip, target_mac in current_targets:
                try:
                    # Tell Target: I am the Gateway
                    self._send_spoof(target_ip, target_mac, self._gateway_ip)
                    # Tell Gateway: I am the Target
                    self._send_spoof(self._gateway_ip, self._gateway_mac, target_ip)
                except Exception as e:
                    logger.debug(f"Spoof error for {target_ip}: {e}")
            
            time.sleep(2)  # Send every 2 seconds

    def _send_spoof(self, dst_ip, dst_mac, src_ip):
        """Send a single spoofed ARP response on the specific interface"""
        # Validate we have the destination MAC
        if not dst_mac:
            # Try to resolve it
            dst_mac = self._resolve_mac(dst_ip)
            if not dst_mac:
                logger.debug(f"Cannot spoof {dst_ip}: MAC unknown")
                return
        
        # op=2 is 'is-at' (ARP Reply)
        # We must set both Ether dst AND ARP hwdst to the target's MAC
        packet = Ether(dst=dst_mac) / ARP(op=2, pdst=dst_ip, hwdst=dst_mac, psrc=src_ip)
        from scapy.all import sendp
        sendp(packet, iface=self._interface, verbose=False)
    
    def _resolve_mac(self, ip: str) -> Optional[str]:
        """Resolve MAC address for an IP using ARP"""
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip)
            result = srp(packet, timeout=2, iface=self._interface, verbose=False)[0]
            if result:
                return result[0][1].hwsrc
        except Exception as e:
            logger.debug(f"MAC resolution failed for {ip}: {e}")
        return None



    def _restore(self, gateway_ip, gateway_mac, target_ip, target_mac):
        """Restore ARP tables to correct values"""
        try:
            # Validate we have all required MACs
            if not all([gateway_ip, gateway_mac, target_ip, target_mac]):
                logger.debug(f"Cannot restore ARP - missing info: gw={gateway_mac}, target={target_mac}")
                return
                
            logger.info(f"Restoring ARP table for {target_ip}...")
            from scapy.all import sendp
            
            # Send correct info to target (gateway's real MAC)
            packet1 = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
            # Send correct info to gateway (target's real MAC)
            packet2 = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)
            
            sendp(packet1, iface=self._interface, count=5, verbose=False)
            sendp(packet2, iface=self._interface, count=5, verbose=False)
        except Exception as e:
            logger.debug(f"ARP restore error: {e}")

# Initialize singletons
sniffer = PacketSniffer()
arp_spoofer = ArpSpoofer()

# Start fingerprinting if available
if FINGERPRINTING_AVAILABLE:
    def _on_fingerprint_update(mac: str, info: dict):
        """Callback when fingerprinter updates device info"""
        device_type = info.get('device_type') or info.get('os_type')
        hostname = info.get('hostname')
        if device_type or hostname:
            db.upsert_device(
                mac=mac,
                ip=info.get('ip'),
                hostname=hostname,
                device_type=device_type,
                metadata={
                    'services': info.get('services', []),
                    'discovery_methods': info.get('discovery_methods', []),
                    'dhcp_lease_time': info.get('dhcp_lease_time'),
                }
            )
            logger.info(f"Fingerprint update: {mac} -> {device_type or 'Unknown'} ({hostname or 'no hostname'})")
    
    fingerprinter.device_callback = _on_fingerprint_update
    fingerprinter.start()
    logger.info("Device fingerprinting enabled (mDNS, SSDP, DHCP)")
