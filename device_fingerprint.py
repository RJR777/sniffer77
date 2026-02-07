"""
Device Fingerprinting Module
Provides multiple agentless methods to identify devices on the network:
- mDNS/Bonjour listener
- SSDP/UPnP discovery
- DHCP fingerprinting
- NetBIOS name resolution
"""
import socket
import struct
import threading
import logging
import re
import time
from typing import Dict, Optional, Callable, List
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger('device_fingerprint')

# ==========================================
# MDNS LISTENER (Bonjour/Zeroconf)
# ==========================================

# Common mDNS service types and their device mappings
MDNS_SERVICE_TYPES = {
    '_airplay._tcp': ('Apple TV', 'streaming'),
    '_raop._tcp': ('AirPlay Speaker', 'audio'),
    '_spotify-connect._tcp': ('Spotify Device', 'audio'),
    '_googlecast._tcp': ('Chromecast', 'streaming'),
    '_ipp._tcp': ('Printer (IPP)', 'printer'),
    '_printer._tcp': ('Printer', 'printer'),
    '_pdl-datastream._tcp': ('Printer (PDL)', 'printer'),
    '_scanner._tcp': ('Scanner', 'scanner'),
    '_http._tcp': ('Web Server', 'server'),
    '_https._tcp': ('Secure Web Server', 'server'),
    '_smb._tcp': ('SMB Share', 'storage'),
    '_afpovertcp._tcp': ('AFP Share (Mac)', 'storage'),
    '_nfs._tcp': ('NFS Share', 'storage'),
    '_ssh._tcp': ('SSH Server', 'server'),
    '_sftp-ssh._tcp': ('SFTP Server', 'server'),
    '_homekit._tcp': ('HomeKit Device', 'iot'),
    '_hap._tcp': ('HomeKit Accessory', 'iot'),
    '_matter._tcp': ('Matter Device', 'iot'),
    '_hue._tcp': ('Philips Hue', 'iot'),
    '_sonos._tcp': ('Sonos Speaker', 'audio'),
    '_daap._tcp': ('iTunes/DAAP', 'audio'),
    '_apple-mobdev2._tcp': ('iPhone/iPad', 'mobile'),
    '_companion-link._tcp': ('Apple Device', 'mobile'),
    '_rdlink._tcp': ('Remote Desktop', 'workstation'),
    '_nvstream._tcp': ('NVIDIA Shield', 'streaming'),
    '_xbox._tcp': ('Xbox', 'gaming'),
    '_psn._tcp': ('PlayStation', 'gaming'),
    '_sleep-proxy._udp': ('Sleep Proxy (Mac)', 'workstation'),
    '_workstation._tcp': ('Workstation', 'workstation'),
}


@dataclass
class DeviceFingerprint:
    """Stores fingerprint data for a device"""
    mac: str
    ip: str = None
    hostname: str = None
    device_type: str = None
    device_model: str = None
    os_type: str = None
    services: List[str] = field(default_factory=list)
    dhcp_fingerprint: str = None
    dhcp_lease_time: int = None  # in seconds
    user_agents: List[str] = field(default_factory=list)
    discovery_methods: List[str] = field(default_factory=list)
    last_updated: datetime = field(default_factory=datetime.now)
    raw_data: Dict = field(default_factory=dict)


class MDNSListener:
    """Listens for mDNS/Bonjour announcements on port 5353"""
    
    MDNS_ADDR = '224.0.0.251'
    MDNS_PORT = 5353
    
    def __init__(self, callback: Callable[[str, str, Dict], None] = None):
        """
        callback: function(ip, hostname, info_dict) called when a device is discovered
        """
        self.callback = callback
        self._running = False
        self._thread = None
        self._sock = None
    
    def start(self):
        """Start listening for mDNS announcements"""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()
        logger.info("mDNS listener started")
    
    def stop(self):
        """Stop the mDNS listener"""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except:
                pass
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("mDNS listener stopped")
    
    def _listen_loop(self):
        """Main listening loop"""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Try SO_REUSEPORT if available
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass
            
            self._sock.bind(('', self.MDNS_PORT))
            
            # Join multicast group
            mreq = struct.pack('4sl', socket.inet_aton(self.MDNS_ADDR), socket.INADDR_ANY)
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            self._sock.settimeout(1.0)
            
            while self._running:
                try:
                    data, addr = self._sock.recvfrom(4096)
                    self._parse_mdns(data, addr[0])
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        logger.debug(f"mDNS receive error: {e}")
                        
        except Exception as e:
            logger.error(f"mDNS listener error: {e}")
        finally:
            if self._sock:
                try:
                    self._sock.close()
                except:
                    pass
    
    def _parse_mdns(self, data: bytes, source_ip: str):
        """Parse mDNS packet and extract device info"""
        try:
            # Very basic mDNS parsing - look for PTR, SRV, TXT records
            # Full parsing would require a DNS library, but we can extract useful info
            
            info = {
                'services': [],
                'hostname': None,
                'device_type': None,
                'model': None,
            }
            
            # Convert to string for pattern matching (lossy but works for discovery)
            text = data.decode('utf-8', errors='ignore')
            
            # Look for service types
            for service_type, (device_type, category) in MDNS_SERVICE_TYPES.items():
                if service_type in text:
                    info['services'].append(service_type)
                    if not info['device_type']:
                        info['device_type'] = device_type
            
            # Try to extract hostname (often appears as name.local)
            hostname_match = re.search(r'([a-zA-Z0-9\-_]+)\.local', text)
            if hostname_match:
                info['hostname'] = hostname_match.group(1)
            
            # Look for model info in TXT records
            model_match = re.search(r'model=([^\x00]+)', text)
            if model_match:
                info['model'] = model_match.group(1)
            
            if info['services'] or info['hostname']:
                if self.callback:
                    self.callback(source_ip, info.get('hostname'), info)
                logger.debug(f"mDNS: {source_ip} - {info}")
                
        except Exception as e:
            logger.debug(f"mDNS parse error: {e}")


# ==========================================
# SSDP/UPnP DISCOVERY
# ==========================================

class SSDPDiscovery:
    """Discovers devices using SSDP (Simple Service Discovery Protocol)"""
    
    SSDP_ADDR = '239.255.255.250'
    SSDP_PORT = 1900
    
    # M-SEARCH request
    MSEARCH = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 3\r\n'
        'ST: ssdp:all\r\n'
        '\r\n'
    )
    
    def __init__(self, callback: Callable[[str, Dict], None] = None):
        """
        callback: function(ip, info_dict) called when a device responds
        """
        self.callback = callback
        self._running = False
        self._thread = None
        self._discovered = {}  # Cache to avoid duplicates
    
    def start(self):
        """Start SSDP discovery (passive listening + periodic active scans)"""
        if self._running:
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._discovery_loop, daemon=True)
        self._thread.start()
        logger.info("SSDP discovery started")
    
    def stop(self):
        """Stop SSDP discovery"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("SSDP discovery stopped")
    
    def scan_once(self) -> Dict[str, Dict]:
        """Perform a single SSDP scan and return results"""
        results = {}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(4)
            
            # Send M-SEARCH
            sock.sendto(self.MSEARCH.encode(), (self.SSDP_ADDR, self.SSDP_PORT))
            
            # Collect responses
            end_time = time.time() + 3
            while time.time() < end_time:
                try:
                    data, addr = sock.recvfrom(4096)
                    info = self._parse_response(data.decode('utf-8', errors='ignore'))
                    if info:
                        results[addr[0]] = info
                        if self.callback:
                            self.callback(addr[0], info)
                except socket.timeout:
                    break
                except Exception as e:
                    logger.debug(f"SSDP response error: {e}")
                    
        except Exception as e:
            logger.error(f"SSDP scan error: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
        
        return results
    
    def _discovery_loop(self):
        """Background loop that listens for SSDP notifications and periodic scans"""
        try:
            # Set up multicast listener
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass
            
            sock.bind(('', self.SSDP_PORT))
            
            # Join multicast
            mreq = struct.pack('4sl', socket.inet_aton(self.SSDP_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(1.0)
            
            last_scan = 0
            
            while self._running:
                # Periodic active scan every 5 minutes
                if time.time() - last_scan > 300:
                    self.scan_once()
                    last_scan = time.time()
                
                # Passive listen for NOTIFY messages
                try:
                    data, addr = sock.recvfrom(4096)
                    info = self._parse_response(data.decode('utf-8', errors='ignore'))
                    if info and addr[0] not in self._discovered:
                        self._discovered[addr[0]] = info
                        if self.callback:
                            self.callback(addr[0], info)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self._running:
                        logger.debug(f"SSDP listen error: {e}")
                        
        except Exception as e:
            logger.error(f"SSDP discovery loop error: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
    
    def _parse_response(self, response: str) -> Optional[Dict]:
        """Parse SSDP response headers"""
        info = {}
        
        lines = response.split('\r\n')
        for line in lines:
            if ':' in line:
                key, _, value = line.partition(':')
                key = key.strip().upper()
                value = value.strip()
                
                if key == 'SERVER':
                    info['server'] = value
                    # Try to extract OS/device info
                    if 'Linux' in value:
                        info['os'] = 'Linux'
                    elif 'Windows' in value:
                        info['os'] = 'Windows'
                    elif 'Mac' in value or 'Darwin' in value:
                        info['os'] = 'macOS'
                        
                elif key == 'ST' or key == 'NT':
                    info['service_type'] = value
                    # Device type hints
                    if 'MediaRenderer' in value:
                        info['device_type'] = 'Media Renderer'
                    elif 'MediaServer' in value:
                        info['device_type'] = 'Media Server'
                    elif 'InternetGateway' in value:
                        info['device_type'] = 'Router'
                    elif 'Printer' in value:
                        info['device_type'] = 'Printer'
                    elif 'roku' in value.lower():
                        info['device_type'] = 'Roku'
                        
                elif key == 'LOCATION':
                    info['location'] = value
                    
                elif key == 'USN':
                    info['usn'] = value
                    # Extract UUID
                    if 'uuid:' in value:
                        uuid_match = re.search(r'uuid:([a-f0-9\-]+)', value, re.I)
                        if uuid_match:
                            info['uuid'] = uuid_match.group(1)
        
        return info if info else None


# ==========================================
# DHCP FINGERPRINTING
# ==========================================

# Common DHCP option 55 fingerprints (Parameter Request List)
# These are subsets - full database at fingerbank.org
DHCP_FINGERPRINTS = {
    '1,3,6,15,119,252': 'macOS',
    '1,3,6,15,119,95,252': 'macOS',
    '1,121,3,6,15,119,252': 'macOS',
    '1,3,6,15,31,33,43,44,46,47,119,121,249,252': 'Windows 10/11',
    '1,3,6,15,31,33,43,44,46,47,119,121,249,252,255': 'Windows 10/11',
    '1,15,3,6,44,46,47,31,33,121,249,252': 'Windows 7/8',
    '1,3,6,15,26,28,51,58,59': 'Linux',
    '1,28,2,3,15,6,119,12,44,47,26,121,42': 'Linux (NetworkManager)',
    '1,3,6,12,15,17,28,40,41,42': 'Android',
    '1,3,6,15,112,113,78,79,95': 'iPhone/iPad',
    '1,3,6,15,119,78,79,95,252': 'iPhone/iPad',
    '6,3,1,15,66,67,13,44': 'Printer',
    '1,3,6,15,44,46,47': 'Smart TV',
    '1,3,6': 'IoT Device (minimal)',
}


class DHCPFingerprinter:
    """Captures and analyzes DHCP packets for device fingerprinting"""
    
    def __init__(self, callback: Callable[[str, str, Dict], None] = None):
        """
        callback: function(mac, ip, info_dict) called when DHCP info is captured
        """
        self.callback = callback
        self.fingerprints: Dict[str, Dict] = {}  # MAC -> fingerprint data
    
    def process_dhcp_packet(self, packet) -> Optional[Dict]:
        """
        Process a DHCP packet captured by scapy.
        Call this from your packet sniffer when UDP port 67/68 is detected.
        """
        try:
            from scapy.all import DHCP, BOOTP
            
            if not packet.haslayer(DHCP):
                return None
            
            bootp = packet[BOOTP]
            dhcp = packet[DHCP]
            
            mac = self._format_mac(bootp.chaddr[:6])
            info = {
                'mac': mac,
                'requested_ip': None,
                'hostname': None,
                'vendor_class': None,
                'fingerprint': None,
                'os_guess': None,
                'lease_time': None,
                'message_type': None,
            }
            
            # If server is assigning IP
            if bootp.yiaddr and bootp.yiaddr != '0.0.0.0':
                info['assigned_ip'] = bootp.yiaddr
            
            # Parse DHCP options
            option_55 = []
            for opt in dhcp.options:
                if isinstance(opt, tuple):
                    opt_type, opt_value = opt[0], opt[1] if len(opt) > 1 else None
                    
                    if opt_type == 'message-type':
                        msg_types = {1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE',
                                    5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM'}
                        info['message_type'] = msg_types.get(opt_value, str(opt_value))
                        
                    elif opt_type == 'requested_addr':
                        info['requested_ip'] = opt_value
                        
                    elif opt_type == 'hostname':
                        info['hostname'] = opt_value.decode() if isinstance(opt_value, bytes) else opt_value
                        
                    elif opt_type == 'vendor_class_id':
                        info['vendor_class'] = opt_value.decode() if isinstance(opt_value, bytes) else opt_value
                        
                    elif opt_type == 'param_req_list':
                        # Option 55 - the fingerprint
                        if isinstance(opt_value, (list, tuple)):
                            option_55 = list(opt_value)
                        elif isinstance(opt_value, bytes):
                            option_55 = list(opt_value)
                            
                    elif opt_type == 'lease_time':
                        info['lease_time'] = opt_value
            
            # Create fingerprint string
            if option_55:
                fingerprint = ','.join(str(o) for o in option_55)
                info['fingerprint'] = fingerprint
                
                # Try to match known fingerprints
                for fp, os_name in DHCP_FINGERPRINTS.items():
                    if fingerprint.startswith(fp) or fp in fingerprint:
                        info['os_guess'] = os_name
                        break
            
            # Vendor class often contains useful info
            if info['vendor_class']:
                vc = info['vendor_class'].lower()
                if 'android' in vc:
                    info['os_guess'] = 'Android'
                elif 'dhcpcd' in vc:
                    info['os_guess'] = 'Linux'
                elif 'msft' in vc:
                    info['os_guess'] = 'Windows'
            
            self.fingerprints[mac] = info
            
            if self.callback:
                ip = info.get('assigned_ip') or info.get('requested_ip')
                self.callback(mac, ip, info)
            
            logger.debug(f"DHCP: {mac} - {info}")
            return info
            
        except Exception as e:
            logger.debug(f"DHCP parse error: {e}")
            return None
    
    def _format_mac(self, mac_bytes: bytes) -> str:
        """Format MAC bytes as string"""
        return ':'.join(f'{b:02X}' for b in mac_bytes)
    
    def get_fingerprint(self, mac: str) -> Optional[Dict]:
        """Get stored fingerprint for a MAC address"""
        return self.fingerprints.get(mac.upper())


# ==========================================
# NETBIOS NAME RESOLUTION
# ==========================================

class NetBIOSResolver:
    """Resolves NetBIOS names for Windows devices"""
    
    NETBIOS_PORT = 137
    
    def __init__(self, callback: Callable[[str, str], None] = None):
        """
        callback: function(ip, netbios_name) called when name is resolved
        """
        self.callback = callback
        self.names: Dict[str, str] = {}  # IP -> NetBIOS name
    
    def query_name(self, ip: str, timeout: float = 2.0) -> Optional[str]:
        """Query a specific IP for its NetBIOS name"""
        try:
            # NetBIOS Name Query packet
            # Transaction ID + Flags + Questions + Answers + Authority + Additional
            query = (
                b'\x00\x01'  # Transaction ID
                b'\x00\x00'  # Flags (query)
                b'\x00\x01'  # Questions: 1
                b'\x00\x00'  # Answer RRs: 0
                b'\x00\x00'  # Authority RRs: 0
                b'\x00\x00'  # Additional RRs: 0
                # Query for *<00> (workstation service)
                b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
                b'\x00\x21'  # Type: NBSTAT
                b'\x00\x01'  # Class: IN
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query, (ip, self.NETBIOS_PORT))
            
            data, _ = sock.recvfrom(1024)
            sock.close()
            
            # Parse response - name is in the answer section
            if len(data) > 57:
                # Skip header and query, find answer
                num_names = data[56]
                if num_names > 0:
                    # First name starts at offset 57
                    name_bytes = data[57:57+15]
                    name = name_bytes.decode('ascii', errors='ignore').strip()
                    
                    self.names[ip] = name
                    if self.callback:
                        self.callback(ip, name)
                    
                    return name
                    
        except socket.timeout:
            pass
        except Exception as e:
            logger.debug(f"NetBIOS query error for {ip}: {e}")
        
        return None
    
    def scan_network(self, ips: List[str]) -> Dict[str, str]:
        """Scan multiple IPs for NetBIOS names"""
        results = {}
        for ip in ips:
            name = self.query_name(ip, timeout=1.0)
            if name:
                results[ip] = name
        return results


# ==========================================
# UNIFIED DEVICE FINGERPRINTER
# ==========================================

class DeviceFingerprinter:
    """
    Unified device fingerprinting that combines all methods.
    Integrates with the main network monitor.
    """
    
    def __init__(self, device_callback: Callable[[str, Dict], None] = None):
        """
        device_callback: function(mac, info_dict) called when device info is updated
        """
        self.device_callback = device_callback
        self.devices: Dict[str, DeviceFingerprint] = {}  # MAC -> fingerprint
        self.ip_to_mac: Dict[str, str] = {}  # IP -> MAC mapping
        
        # Initialize sub-components
        self.mdns = MDNSListener(callback=self._on_mdns)
        self.ssdp = SSDPDiscovery(callback=self._on_ssdp)
        self.dhcp = DHCPFingerprinter(callback=self._on_dhcp)
        self.netbios = NetBIOSResolver(callback=self._on_netbios)
        
        self._running = False
    
    def start(self):
        """Start all fingerprinting services"""
        if self._running:
            return
        
        self._running = True
        self.mdns.start()
        self.ssdp.start()
        # DHCP and NetBIOS are called from packet processing, not background threads
        
        logger.info("📡 Device fingerprinting background discovery services started (mDNS, SSDP)")

    
    def stop(self):
        """Stop all fingerprinting services"""
        self._running = False
        self.mdns.stop()
        self.ssdp.stop()
        logger.info("Device fingerprinting stopped")
    
    def process_dhcp(self, packet):
        """Process a DHCP packet from the sniffer"""
        return self.dhcp.process_dhcp_packet(packet)

    
    def resolve_netbios(self, ip: str) -> Optional[str]:
        """Resolve NetBIOS name for an IP"""
        return self.netbios.query_name(ip)
    
    def get_device_info(self, mac: str) -> Optional[DeviceFingerprint]:
        """Get all collected info for a device"""
        return self.devices.get(mac.upper())
    
    def register_ip_mac(self, ip: str, mac: str):
        """Register IP to MAC mapping (called from ARP/packet processing)"""
        mac = mac.upper()
        self.ip_to_mac[ip] = mac
        
        if mac not in self.devices:
            self.devices[mac] = DeviceFingerprint(mac=mac, ip=ip)
        else:
            self.devices[mac].ip = ip
            self.devices[mac].last_updated = datetime.now()
    
    def _on_mdns(self, ip: str, hostname: str, info: Dict):
        """Handle mDNS discovery"""
        mac = self.ip_to_mac.get(ip)
        if not mac:
            return
        
        if mac not in self.devices:
            self.devices[mac] = DeviceFingerprint(mac=mac, ip=ip)
        
        fp = self.devices[mac]
        if hostname:
            fp.hostname = hostname
        if info.get('device_type'):
            fp.device_type = info['device_type']
        if info.get('model'):
            fp.device_model = info['model']
        if info.get('services'):
            fp.services = list(set(fp.services + info['services']))
        if 'mdns' not in fp.discovery_methods:
            fp.discovery_methods.append('mdns')
        fp.last_updated = datetime.now()
        
        self._notify(mac, fp)
    
    def _on_ssdp(self, ip: str, info: Dict):
        """Handle SSDP discovery"""
        mac = self.ip_to_mac.get(ip)
        if not mac:
            return
        
        if mac not in self.devices:
            self.devices[mac] = DeviceFingerprint(mac=mac, ip=ip)
        
        fp = self.devices[mac]
        if info.get('device_type'):
            fp.device_type = info['device_type']
        if info.get('os'):
            fp.os_type = info['os']
        if info.get('server'):
            fp.raw_data['ssdp_server'] = info['server']
        if 'ssdp' not in fp.discovery_methods:
            fp.discovery_methods.append('ssdp')
        fp.last_updated = datetime.now()
        
        self._notify(mac, fp)
    
    def _on_dhcp(self, mac: str, ip: str, info: Dict):
        """Handle DHCP fingerprint"""
        mac = mac.upper()
        if ip:
            self.ip_to_mac[ip] = mac
        
        if mac not in self.devices:
            self.devices[mac] = DeviceFingerprint(mac=mac, ip=ip)
        
        fp = self.devices[mac]
        if info.get('hostname'):
            fp.hostname = info['hostname']
        if info.get('os_guess'):
            fp.os_type = info['os_guess']
        if info.get('fingerprint'):
            fp.dhcp_fingerprint = info['fingerprint']
        if info.get('lease_time'):
            fp.dhcp_lease_time = info['lease_time']
        if 'dhcp' not in fp.discovery_methods:
            fp.discovery_methods.append('dhcp')
        fp.last_updated = datetime.now()
        
        self._notify(mac, fp)
    
    def _on_netbios(self, ip: str, name: str):
        """Handle NetBIOS name resolution"""
        mac = self.ip_to_mac.get(ip)
        if not mac:
            return
        
        if mac not in self.devices:
            self.devices[mac] = DeviceFingerprint(mac=mac, ip=ip)
        
        fp = self.devices[mac]
        fp.hostname = name
        if 'netbios' not in fp.discovery_methods:
            fp.discovery_methods.append('netbios')
        fp.last_updated = datetime.now()
        
        self._notify(mac, fp)
    
    def _notify(self, mac: str, fingerprint: DeviceFingerprint):
        """Notify callback of device update"""
        if self.device_callback:
            info = {
                'mac': fingerprint.mac,
                'ip': fingerprint.ip,
                'hostname': fingerprint.hostname,
                'device_type': fingerprint.device_type,
                'device_model': fingerprint.device_model,
                'os_type': fingerprint.os_type,
                'services': fingerprint.services,
                'dhcp_lease_time': fingerprint.dhcp_lease_time,
                'discovery_methods': fingerprint.discovery_methods,
            }
            self.device_callback(mac, info)


# Singleton instance
fingerprinter = DeviceFingerprinter()
