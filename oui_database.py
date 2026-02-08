"""
OUI (Organizationally Unique Identifier) lookup for MAC addresses
Identifies device manufacturers without requiring any agent on the device
"""
import os
import re
import logging
import threading
from typing import Optional, Dict
from functools import lru_cache

logger = logging.getLogger(__name__)

# Cache file for OUI database
OUI_CACHE_FILE = os.path.join(os.path.dirname(__file__), '.oui_cache.txt')


class OUIDatabase:
    """
    Lookup MAC address manufacturer using OUI (first 3 bytes of MAC)
    """
    
    # Common OUI prefixes (fallback if mac-vendor-lookup fails)
    COMMON_OUIS: Dict[str, str] = {
        # Apple
        '00:03:93': 'Apple',
        '00:0A:27': 'Apple',
        '00:0A:95': 'Apple',
        '00:0D:93': 'Apple',
        '00:11:24': 'Apple',
        '00:14:51': 'Apple',
        '00:16:CB': 'Apple',
        '00:17:F2': 'Apple',
        '00:19:E3': 'Apple',
        '00:1B:63': 'Apple',
        '00:1C:B3': 'Apple',
        '00:1D:4F': 'Apple',
        '00:1E:52': 'Apple',
        '00:1E:C2': 'Apple',
        '00:1F:5B': 'Apple',
        '00:1F:F3': 'Apple',
        '00:21:E9': 'Apple',
        '00:22:41': 'Apple',
        '00:23:12': 'Apple',
        '00:23:32': 'Apple',
        '00:23:6C': 'Apple',
        '00:23:DF': 'Apple',
        '00:24:36': 'Apple',
        '00:25:00': 'Apple',
        '00:25:4B': 'Apple',
        '00:25:BC': 'Apple',
        '00:26:08': 'Apple',
        '00:26:4A': 'Apple',
        '00:26:B0': 'Apple',
        '00:26:BB': 'Apple',
        
        # Samsung
        '00:00:F0': 'Samsung',
        '00:02:78': 'Samsung',
        '00:07:AB': 'Samsung',
        '00:09:18': 'Samsung',
        '00:0D:AE': 'Samsung',
        '00:0D:E5': 'Samsung',
        '00:12:47': 'Samsung',
        '00:12:FB': 'Samsung',
        '00:13:77': 'Samsung',
        '00:15:99': 'Samsung',
        '00:15:B9': 'Samsung',
        '00:16:32': 'Samsung',
        '00:16:6B': 'Samsung',
        '00:16:6C': 'Samsung',
        '00:17:C9': 'Samsung',
        '00:17:D5': 'Samsung',
        '00:18:AF': 'Samsung',
        
        # Google
        '00:1A:11': 'Google',
        '3C:5A:B4': 'Google',
        '54:60:09': 'Google',
        '94:EB:2C': 'Google',
        'F4:F5:D8': 'Google',
        'F4:F5:E8': 'Google',
        
        # Amazon
        '00:FC:8B': 'Amazon',
        '0C:47:C9': 'Amazon',
        '10:CE:A9': 'Amazon',
        '18:74:2E': 'Amazon',
        '34:D2:70': 'Amazon',
        '38:F7:3D': 'Amazon',
        '40:B4:CD': 'Amazon',
        '44:65:0D': 'Amazon',
        '4C:EF:C0': 'Amazon',
        '50:DC:E7': 'Amazon',
        '68:37:E9': 'Amazon',
        '68:54:FD': 'Amazon',
        '74:C2:46': 'Amazon',
        '78:E1:03': 'Amazon',
        '84:D6:D0': 'Amazon',
        
        # Intel
        '00:02:B3': 'Intel',
        '00:03:47': 'Intel',
        '00:04:23': 'Intel',
        '00:07:E9': 'Intel',
        '00:0C:F1': 'Intel',
        '00:0E:0C': 'Intel',
        '00:0E:35': 'Intel',
        '00:11:11': 'Intel',
        '00:12:F0': 'Intel',
        '00:13:02': 'Intel',
        '00:13:20': 'Intel',
        '00:13:CE': 'Intel',
        '00:13:E8': 'Intel',
        '00:15:00': 'Intel',
        '00:15:17': 'Intel',
        '00:16:6F': 'Intel',
        '00:16:76': 'Intel',
        '00:16:EA': 'Intel',
        '00:16:EB': 'Intel',
        '00:17:35': 'Intel',
        '00:18:DE': 'Intel',
        '00:19:D1': 'Intel',
        '00:19:D2': 'Intel',
        '00:1B:21': 'Intel',
        '00:1B:77': 'Intel',
        '00:1C:BF': 'Intel',
        '00:1C:C0': 'Intel',
        '00:1D:E0': 'Intel',
        '00:1D:E1': 'Intel',
        '00:1E:64': 'Intel',
        '00:1E:65': 'Intel',
        '00:1E:67': 'Intel',
        '00:1F:3B': 'Intel',
        '00:1F:3C': 'Intel',
        '00:20:E0': 'Intel',
        '00:21:5C': 'Intel',
        '00:21:5D': 'Intel',
        '00:21:6A': 'Intel',
        '00:21:6B': 'Intel',
        '00:22:FA': 'Intel',
        '00:22:FB': 'Intel',
        '00:24:D6': 'Intel',
        '00:24:D7': 'Intel',
        'D0:57:7E': 'Intel',
        
        # Cisco
        '00:00:0C': 'Cisco',
        '00:01:42': 'Cisco',
        '00:01:43': 'Cisco',
        '00:01:63': 'Cisco',
        '00:01:64': 'Cisco',
        '00:01:96': 'Cisco',
        '00:01:97': 'Cisco',
        '00:01:C7': 'Cisco',
        '00:01:C9': 'Cisco',
        '00:02:16': 'Cisco',
        '00:02:17': 'Cisco',
        '00:02:3D': 'Cisco',
        '00:02:4A': 'Cisco',
        '00:02:4B': 'Cisco',
        '00:02:7D': 'Cisco',
        '00:02:7E': 'Cisco',
        '00:02:B9': 'Cisco',
        '00:02:BA': 'Cisco',
        '00:02:FC': 'Cisco',
        '00:02:FD': 'Cisco',
        
        # TP-Link
        '00:1D:0F': 'TP-Link',
        '00:23:CD': 'TP-Link',
        '00:27:19': 'TP-Link',
        '14:CC:20': 'TP-Link',
        '14:CF:92': 'TP-Link',
        '18:A6:F7': 'TP-Link',
        '1C:3B:F3': 'TP-Link',
        '30:B5:C2': 'TP-Link',
        '50:C7:BF': 'TP-Link',
        '54:C8:0F': 'TP-Link',
        '5C:89:9A': 'TP-Link',
        '60:E3:27': 'TP-Link',
        '64:56:01': 'TP-Link',
        '64:70:02': 'TP-Link',
        '6C:B0:CE': 'TP-Link',
        '74:DA:38': 'TP-Link',
        '78:44:76': 'TP-Link',
        '84:16:F9': 'TP-Link',
        '90:F6:52': 'TP-Link',
        '94:0C:6D': 'TP-Link',
        '98:DA:C4': 'TP-Link',
        'A0:F3:C1': 'TP-Link',
        'AC:84:C6': 'TP-Link',
        'B0:4E:26': 'TP-Link',
        'B0:95:75': 'TP-Link',
        'BC:46:99': 'TP-Link',
        'C0:25:E9': 'TP-Link',
        'C4:6E:1F': 'TP-Link',
        'C8:3A:35': 'TP-Link',
        'CC:34:29': 'TP-Link',
        'D4:6E:0E': 'TP-Link',
        'D8:07:B6': 'TP-Link',
        'E4:D3:32': 'TP-Link',
        'E8:94:F6': 'TP-Link',
        'EC:08:6B': 'TP-Link',
        'EC:17:2F': 'TP-Link',
        'F0:F3:36': 'TP-Link',
        'F4:F2:6D': 'TP-Link',
        'F8:1A:67': 'TP-Link',
        
        # Netgear
        '00:09:5B': 'Netgear',
        '00:0F:B5': 'Netgear',
        '00:14:6C': 'Netgear',
        '00:18:4D': 'Netgear',
        '00:1B:2F': 'Netgear',
        '00:1E:2A': 'Netgear',
        '00:1F:33': 'Netgear',
        '00:22:3F': 'Netgear',
        '00:24:B2': 'Netgear',
        '00:26:F2': 'Netgear',
        '04:A1:51': 'Netgear',
        '20:0C:C8': 'Netgear',
        '20:E5:2A': 'Netgear',
        '28:C6:8E': 'Netgear',
        '2C:B0:5D': 'Netgear',
        '30:46:9A': 'Netgear',
        '44:94:FC': 'Netgear',
        '4C:60:DE': 'Netgear',
        '6C:B0:CE': 'Netgear',
        '84:1B:5E': 'Netgear',
        '9C:3D:CF': 'Netgear',
        'A0:04:60': 'Netgear',
        'A0:21:B7': 'Netgear',
        'A4:2B:8C': 'Netgear',
        'B0:7F:B9': 'Netgear',
        'C0:3F:0E': 'Netgear',
        'C4:04:15': 'Netgear',
        'C4:3D:C7': 'Netgear',
        'CC:40:D0': 'Netgear',
        'D4:B9:2F': 'Netgear',
        'E0:46:9A': 'Netgear',
        'E0:91:F5': 'Netgear',
        'E4:F4:C6': 'Netgear',
        
        # Raspberry Pi Foundation
        'B8:27:EB': 'Raspberry Pi',
        'DC:A6:32': 'Raspberry Pi',
        'E4:5F:01': 'Raspberry Pi',
        
        # Microsoft
        '00:0D:3A': 'Microsoft',
        '00:12:5A': 'Microsoft',
        '00:15:5D': 'Microsoft',
        '00:17:FA': 'Microsoft',
        '00:1D:D8': 'Microsoft',
        '00:22:48': 'Microsoft',
        '00:25:AE': 'Microsoft',
        '00:50:F2': 'Microsoft',
        '28:18:78': 'Microsoft',
        '7C:1E:52': 'Microsoft',
        'C8:3F:26': 'Microsoft',
        
        # Dell
        '00:06:5B': 'Dell',
        '00:08:74': 'Dell',
        '00:0B:DB': 'Dell',
        '00:0D:56': 'Dell',
        '00:0F:1F': 'Dell',
        '00:11:43': 'Dell',
        '00:12:3F': 'Dell',
        '00:13:72': 'Dell',
        '00:14:22': 'Dell',
        '00:15:C5': 'Dell',
        '00:16:F0': 'Dell',
        '00:18:8B': 'Dell',
        '00:19:B9': 'Dell',
        '00:1A:A0': 'Dell',
        '00:1C:23': 'Dell',
        '00:1D:09': 'Dell',
        '00:1E:4F': 'Dell',
        '00:1E:C9': 'Dell',
        '00:21:70': 'Dell',
        '00:21:9B': 'Dell',
        '00:22:19': 'Dell',
        '00:23:AE': 'Dell',
        '00:24:E8': 'Dell',
        '00:25:64': 'Dell',
        '00:26:B9': 'Dell',
        '14:18:77': 'Dell',
        '14:9E:CF': 'Dell',
        '14:B3:1F': 'Dell',
        '14:FE:B5': 'Dell',
        '18:03:73': 'Dell',
        '18:66:DA': 'Dell',
        '18:A9:9B': 'Dell',
        '18:DB:F2': 'Dell',
        
        # HP
        '00:01:E6': 'HP',
        '00:01:E7': 'HP',
        '00:02:A5': 'HP',
        '00:04:EA': 'HP',
        '00:08:02': 'HP',
        '00:08:83': 'HP',
        '00:0A:57': 'HP',
        '00:0B:CD': 'HP',
        '00:0D:9D': 'HP',
        '00:0E:7F': 'HP',
        '00:0F:20': 'HP',
        '00:0F:61': 'HP',
        '00:10:83': 'HP',
        '00:10:E3': 'HP',
        '00:11:0A': 'HP',
        '00:11:85': 'HP',
        '00:12:79': 'HP',
        '00:13:21': 'HP',
        '00:14:38': 'HP',
        '00:14:C2': 'HP',
        '00:15:60': 'HP',
        '00:16:35': 'HP',
        '00:17:08': 'HP',
        '00:17:A4': 'HP',
        '00:18:71': 'HP',
        '00:18:FE': 'HP',
        '00:19:BB': 'HP',
        '00:1A:4B': 'HP',
        '00:1B:78': 'HP',
        '00:1C:2E': 'HP',
        '00:1C:C4': 'HP',
        '00:1D:31': 'HP',
        '00:1D:73': 'HP',
        '00:1E:0B': 'HP',
        '00:1F:29': 'HP',
        '00:1F:FE': 'HP',
        '00:21:5A': 'HP',
        '00:22:64': 'HP',
        '00:23:7D': 'HP',
        '00:24:81': 'HP',
        '00:25:B3': 'HP',
        '00:26:55': 'HP',
        '00:26:5E': 'HP',
        '00:50:8B': 'HP',
        '00:60:B0': 'HP',
        '00:80:A0': 'HP',
        '08:00:09': 'HP',
        
        # Lenovo
        '00:06:1B': 'Lenovo',
        '00:09:2D': 'Lenovo',
        '00:0A:E4': 'Lenovo',
        '00:12:FE': 'Lenovo',
        '00:1A:6B': 'Lenovo',
        '00:1E:4C': 'Lenovo',
        '00:21:5E': 'Lenovo',
        '00:22:68': 'Lenovo',
        '00:24:7E': 'Lenovo',
        '00:26:6C': 'Lenovo',
        '28:D2:44': 'Lenovo',
        '40:B0:34': 'Lenovo',
        '54:EE:75': 'Lenovo',
        '6C:C2:17': 'Lenovo',
        '70:72:0D': 'Lenovo',
        '70:F1:A1': 'Lenovo',
        '74:E5:0B': 'Lenovo',
        '7C:7A:91': 'Lenovo',
        '8C:EC:4B': 'Lenovo',
        'AC:16:2D': 'Lenovo',
        'C4:34:6B': 'Lenovo',
        'E8:40:F2': 'Lenovo',
        'F0:DE:F1': 'Lenovo',
        'F4:8C:50': 'Lenovo',
        'F8:B1:56': 'Lenovo',
        
        # ASUS
        '00:0C:6E': 'ASUS',
        '00:0E:A6': 'ASUS',
        '00:11:2F': 'ASUS',
        '00:11:D8': 'ASUS',
        '00:13:D4': 'ASUS',
        '00:15:F2': 'ASUS',
        '00:17:31': 'ASUS',
        '00:18:F3': 'ASUS',
        '00:1A:92': 'ASUS',
        '00:1B:FC': 'ASUS',
        '00:1D:60': 'ASUS',
        '00:1E:8C': 'ASUS',
        '00:1F:C6': 'ASUS',
        '00:22:15': 'ASUS',
        '00:23:54': 'ASUS',
        '00:24:8C': 'ASUS',
        '00:25:22': 'ASUS',
        '00:26:18': 'ASUS',
        '04:92:26': 'ASUS',
        '08:60:6E': 'ASUS',
        '10:BF:48': 'ASUS',
        '10:C3:7B': 'ASUS',
        '14:DA:E9': 'ASUS',
        '14:DD:A9': 'ASUS',
        '1C:87:2C': 'ASUS',
        '1C:B7:2C': 'ASUS',
        '20:CF:30': 'ASUS',
        '24:4B:FE': 'ASUS',
        '2C:4D:54': 'ASUS',
        '2C:56:DC': 'ASUS',
        '30:5A:3A': 'ASUS',
        '30:85:A9': 'ASUS',
        '38:2C:4A': 'ASUS',
        '38:D5:47': 'ASUS',
        '40:16:7E': 'ASUS',
        '40:B0:76': 'ASUS',
        '48:5B:39': 'ASUS',
        '4C:ED:FB': 'ASUS',
        '50:46:5D': 'ASUS',
        '50:46:5D': 'ASUS',
        '54:04:A6': 'ASUS',
        '54:A0:50': 'ASUS',
        '60:45:CB': 'ASUS',
        '60:A4:4C': 'ASUS',
        '6C:B3:11': 'ASUS',
        '70:8B:CD': 'ASUS',
        '74:D0:2B': 'ASUS',
        '78:24:AF': 'ASUS',
        '88:D7:F6': 'ASUS',
        '90:E6:BA': 'ASUS',
        'AC:22:0B': 'ASUS',
        'AC:9E:17': 'ASUS',
        'B0:6E:BF': 'ASUS',
        'BC:AE:C5': 'ASUS',
        'BC:EE:7B': 'ASUS',
        'C8:60:00': 'ASUS',
        'D8:50:E6': 'ASUS',
        'E0:3F:49': 'ASUS',
        'E0:CB:4E': 'ASUS',
        'F0:79:59': 'ASUS',
        'F4:6D:04': 'ASUS',
        'FC:C2:33': 'ASUS',
        
        # Sony
        '00:00:0E': 'Sony',
        '00:01:4A': 'Sony',
        '00:04:1F': 'Sony',
        '00:0A:D9': 'Sony',
        '00:0B:0D': 'Sony',
        '00:0D:F0': 'Sony',
        '00:0E:07': 'Sony',
        '00:0F:DE': 'Sony',
        '00:13:15': 'Sony',
        '00:13:A9': 'Sony',
        '00:15:C1': 'Sony',
        '00:16:20': 'Sony',
        '00:18:13': 'Sony',
        '00:19:63': 'Sony',
        '00:1A:80': 'Sony',
        '00:1B:59': 'Sony',
        '00:1C:A4': 'Sony',
        '00:1D:0D': 'Sony',
        '00:1D:BA': 'Sony',
        '00:1E:A4': 'Sony',
        '00:1F:E4': 'Sony',
        '00:21:4C': 'Sony',
        '00:22:69': 'Sony',
        '00:23:45': 'Sony',
        '00:24:8D': 'Sony',
        '00:25:E7': 'Sony',
        '00:26:43': 'Sony',
        '00:8A:76': 'Sony',
        '04:5D:4B': 'Sony',
        '08:A9:5A': 'Sony',
        '0C:FE:45': 'Sony',
        '10:A5:D0': 'Sony',
        '28:0D:FC': 'Sony',
        '28:3F:69': 'Sony',
        '30:39:26': 'Sony',
        '30:EB:25': 'Sony',
        '40:B8:37': 'Sony',
        '48:C1:AC': 'Sony',
        '4C:B1:99': 'Sony',
        '54:42:49': 'Sony',
        '58:48:22': 'Sony',
        '70:9E:29': 'Sony',
        '78:84:3C': 'Sony',
        '84:00:D2': 'Sony',
        '94:DB:C9': 'Sony',
        'A4:5E:60': 'Sony',
        'AC:E4:B5': 'Sony',
        'B4:52:7E': 'Sony',
        'BC:60:A7': 'Sony',
        'C8:63:F1': 'Sony',
        'D8:D4:3C': 'Sony',
        'E8:B4:C8': 'Sony',
        'F8:D0:AC': 'Sony',
        'FC:0F:E6': 'Sony',
        
        # LG
        '00:05:C9': 'LG',
        '00:0F:B8': 'LG',
        '00:1C:62': 'LG',
        '00:1E:75': 'LG',
        '00:1F:6B': 'LG',
        '00:1F:E3': 'LG',
        '00:22:CF': 'LG',
        '00:24:83': 'LG',
        '00:25:E5': 'LG',
        '00:26:E2': 'LG',
        '00:34:DA': 'LG',
        '00:AA:70': 'LG',
        '00:E0:91': 'LG',
        '08:D4:2B': 'LG',
        '10:68:3F': 'LG',
        '10:F9:6F': 'LG',
        '14:C9:13': 'LG',
        '20:21:A5': 'LG',
        '20:3D:BD': 'LG',
        '28:CF:DA': 'LG',
        '30:8C:FB': 'LG',
        '34:4D:F7': 'LG',
        '38:8C:50': 'LG',
        '40:B0:FA': 'LG',
        '44:07:4F': 'LG',
        '48:59:29': 'LG',
        '4C:BC:A5': 'LG',
        '50:55:27': 'LG',
        '54:A5:1B': 'LG',
        '58:3F:54': 'LG',
        '5C:70:A3': 'LG',
        '60:E3:AC': 'LG',
        '64:99:5C': 'LG',
        '6C:D6:8A': 'LG',
        '74:40:BE': 'LG',
        '78:00:9E': 'LG',
        '78:5D:C8': 'LG',
        '7C:1C:4E': 'LG',
        '80:7A:BF': 'LG',
        '88:07:4B': 'LG',
        '88:C9:D0': 'LG',
        '8C:3A:E3': 'LG',
        '90:EE:C7': 'LG',
        '94:44:52': 'LG',
        '98:93:CC': 'LG',
        '9C:02:98': 'LG',
        'A0:07:98': 'LG',
        'A8:23:FE': 'LG',
        'AC:0D:1B': 'LG',
        'B4:E6:2A': 'LG',
        'B8:1D:AA': 'LG',
        'BC:8C:CD': 'LG',
        'C4:36:55': 'LG',
        'C4:9A:02': 'LG',
        'CC:FA:00': 'LG',
        'D0:37:45': 'LG',
        'DC:0B:1A': 'LG',
        'E8:5B:5B': 'LG',
        'EC:A9:40': 'LG',
        'F4:9F:F3': 'LG',
        'FC:87:43': 'LG',
        
        # Huawei
        '00:09:4F': 'Huawei',
        '00:12:D1': 'Huawei',
        '00:18:82': 'Huawei',
        '00:1E:10': 'Huawei',
        '00:21:E8': 'Huawei',
        '00:22:A1': 'Huawei',
        '00:25:68': 'Huawei',
        '00:25:9E': 'Huawei',
        '00:25:9E': 'Huawei',
        '00:46:4B': 'Huawei',
        '00:66:4B': 'Huawei',
        '00:9A:CD': 'Huawei',
        '00:E0:FC': 'Huawei',
        '00:F8:1C': 'Huawei',
        '04:02:1F': 'Huawei',
        '04:25:C5': 'Huawei',
        '04:33:C2': 'Huawei',
        '04:4F:4C': 'Huawei',
        '04:9F:81': 'Huawei',
        '04:B0:E7': 'Huawei',
        '04:BD:70': 'Huawei',
        '04:C0:6F': 'Huawei',
        '04:F9:38': 'Huawei',
        '04:FE:8C': 'Huawei',
        '08:19:A6': 'Huawei',
        '08:4F:0A': 'Huawei',
        '08:63:61': 'Huawei',
        '08:7A:4C': 'Huawei',
        '08:E8:4F': 'Huawei',
        '0C:37:DC': 'Huawei',
        '0C:45:BA': 'Huawei',
        '0C:96:BF': 'Huawei',
        '0C:D6:BD': 'Huawei',
        '10:1B:54': 'Huawei',
        '10:44:00': 'Huawei',
        '10:47:80': 'Huawei',
        '10:C6:1F': 'Huawei',
        '14:30:04': 'Huawei',
        '14:A0:F8': 'Huawei',
        '14:A5:1A': 'Huawei',
        '14:B9:68': 'Huawei',
        '18:C5:8A': 'Huawei',
        '18:DE:D7': 'Huawei',
        '1C:15:1F': 'Huawei',
        '1C:1D:67': 'Huawei',
        '1C:8E:5C': 'Huawei',
        '20:0B:C7': 'Huawei',
        '20:2B:C1': 'Huawei',
        '20:54:76': 'Huawei',
        '20:A6:80': 'Huawei',
        '20:F1:7C': 'Huawei',
        '24:69:A5': 'Huawei',
        '24:7F:3C': 'Huawei',
        '24:9E:AB': 'Huawei',
        '24:DB:AC': 'Huawei',
        '28:31:52': 'Huawei',
        '28:3C:E4': 'Huawei',
        '28:5F:DB': 'Huawei',
        '28:6E:D4': 'Huawei',
        
        # Virtual/Docker
        '00:15:5D': 'Hyper-V',
        '00:50:56': 'VMware',
        '00:0C:29': 'VMware',
        '00:1C:42': 'Parallels',
        '08:00:27': 'VirtualBox',
        '52:54:00': 'QEMU/KVM',
        '02:42': 'Docker',
    }
    
    def __init__(self):
        self._vendor_lookup = None
        self._local_db: Dict[str, str] = self.COMMON_OUIS.copy()
        self._init_vendor_lookup()
        self._load_cached_oui()
        
    def _init_vendor_lookup(self):
        """Initialize the mac-vendor-lookup library"""
        try:
            from mac_vendor_lookup import MacLookup
            self._vendor_lookup = MacLookup()
            # Try to update, but don't block if it fails
            threading.Thread(target=self._async_update, daemon=True).start()
        except ImportError:
            logger.warning("mac-vendor-lookup not installed, using built-in OUI database")
            
    def _async_update(self):
        """Update vendors in the background"""
        try:
            self._vendor_lookup.update_vendors()
            logger.info("OUI vendor database updated successfully")
        except Exception as e:
            logger.debug(f"Background OUI update skipped: {e}")
            # Try to download wireshark manuf file as fallback
            self.download_wireshark_manuf()

    def download_wireshark_manuf(self):
        """Download Wireshark's manuf file as a comprehensive fallback"""
        url = "https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf;hb=HEAD"
        # Since we might not have 'requests' installed, try using urllib
        import urllib.request
        try:
            logger.info("Downloading Wireshark manuf file for enhanced OUI lookup...")
            response = urllib.request.urlopen(url, timeout=10)
            content = response.read().decode('utf-8', errors='ignore')
            
            count = 0
            for line in content.splitlines():
                if line.startswith('#') or not line.strip():
                    continue
                parts = line.split('\t')
                if len(parts) >= 2:
                    oui = parts[0].strip().upper()
                    # Convert AA:BB:CC/24 or AA:BB:CC formats
                    if '/' in oui:
                        oui = oui.split('/')[0]
                    
                    if len(oui) == 8: # XX:XX:XX
                        vendor = parts[1].strip()
                        self._local_db[oui] = vendor
                        count += 1
            
            logger.info(f"Loaded {count} additional vendors from Wireshark database")
            self._save_cached_oui()
        except Exception as e:
            logger.warning(f"Could not download Wireshark OUI data: {e}")

    def _save_cached_oui(self):
        """Save the combined OUI database to a local cache file"""
        try:
            with open(OUI_CACHE_FILE, 'w') as f:
                for oui, vendor in self._local_db.items():
                    f.write(f"{oui}\t{vendor}\n")
        except Exception as e:
            logger.debug(f"Could not save OUI cache: {e}")

    def _load_cached_oui(self):
        """Load OUI from local cache file"""
        if os.path.exists(OUI_CACHE_FILE):
            try:
                with open(OUI_CACHE_FILE, 'r') as f:
                    for line in f:
                        parts = line.strip().split('\t')
                        if len(parts) == 2:
                            self._local_db[parts[0]] = parts[1]
                logger.info(f"Loaded {len(self._local_db)} OUI entries from cache")
            except Exception as e:
                logger.debug(f"Could not load OUI cache: {e}")

    @staticmethod
    def normalize_mac(mac: str) -> str:
        """Normalize MAC address to XX:XX:XX:XX:XX:XX format"""
        # Remove common separators and convert to uppercase
        mac_clean = re.sub(r'[.:-]', '', mac.upper())
        if len(mac_clean) != 12:
            return mac.upper()
        # Format as XX:XX:XX:XX:XX:XX
        return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
    
    @staticmethod
    def get_oui(mac: str) -> str:
        """Extract OUI (first 3 bytes) from MAC address"""
        normalized = OUIDatabase.normalize_mac(mac)
        return normalized[:8]  # XX:XX:XX
    
    @lru_cache(maxsize=1000)
    def lookup(self, mac: str) -> Optional[str]:
        """
        Look up manufacturer from MAC address.
        """
        normalized = self.normalize_mac(mac)
        oui = self.get_oui(normalized)
        
        # Try mac-vendor-lookup library first
        if self._vendor_lookup:
            try:
                return self._vendor_lookup.lookup(normalized)
            except Exception:
                pass
        
        # Fall back to combined local/cached database
        if oui in self._local_db:
            return self._local_db[oui]
        
        # Check partial matches for docker (first 2 bytes)
        partial = normalized[:5]
        if partial in self._local_db:
            return self._local_db[partial]
        
        return None
    
    def get_device_info(self, mac: str) -> dict:
        """
        Get detailed device info from MAC address
        """
        normalized = self.normalize_mac(mac)
        manufacturer = self.lookup(mac)
        
        # Detect if likely virtual
        is_virtual = False
        virtual_types = ['VMware', 'VirtualBox', 'Hyper-V', 'Parallels', 'QEMU/KVM', 'Docker']
        if manufacturer and any(vt in manufacturer for vt in virtual_types):
            is_virtual = True
        
        # Detect locally administered MAC (bit 1 of first octet set)
        first_byte = int(normalized[:2], 16)
        is_local = bool(first_byte & 0x02)
        
        return {
            'mac': normalized,
            'oui': self.get_oui(normalized),
            'manufacturer': manufacturer or 'Unknown',
            'is_virtual': is_virtual,
            'is_local_admin': is_local,  # Random/spoofed MAC addresses
        }


# Singleton instance
oui_db = OUIDatabase()


def lookup_manufacturer(mac: str) -> str:
    """Convenience function to lookup manufacturer"""
    return oui_db.lookup(mac) or 'Unknown'


def get_device_info(mac: str) -> dict:
    """Convenience function to get device info"""
    return oui_db.get_device_info(mac)


if __name__ == '__main__':
    # Test the OUI database
    test_macs = [
        'B8:27:EB:12:34:56',  # Raspberry Pi
        '00:50:56:AA:BB:CC',  # VMware
        '00:1A:11:12:34:56',  # Google
        'AC:84:C6:12:34:56',  # TP-Link
        'FF:FF:FF:FF:FF:FF',  # Broadcast (unknown)
    ]
    
    for mac in test_macs:
        info = get_device_info(mac)
        print(f"{mac}:")
        print(f"  Manufacturer: {info['manufacturer']}")
        print(f"  Virtual: {info['is_virtual']}")
        print(f"  Local Admin: {info['is_local_admin']}")
        print()
