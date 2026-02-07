#!/usr/bin/env python3
"""
Network Monitor - Main Entry Point

A network sniffer and device discovery tool for home LAN and WiFi
that identifies devices by OUI and displays activity on a web dashboard.

Requires root/sudo privileges for packet capture.
"""
import argparse
import logging
import signal
import sys
import time
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from network_monitor import INTERFACES, DASHBOARD_PORT, DASHBOARD_HOST, discovery, sniffer, db, arp_spoofer

# Setup logging
log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network_monitor.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_path, mode='a')
    ]
)
# Ensure logger flushes immediately
for handler in logging.root.handlers:
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    if hasattr(handler, 'flush'):
        handler.flush()

logger = logging.getLogger('network_monitor')
logger.info(f"📝 Logging to: {log_path}")



def check_root():
    """Check if running with root privileges"""
    if os.geteuid() != 0:
        logger.warning("⚠️  Not running as root. Packet capture may not work.")
        logger.warning("    Run with: sudo python main.py")
        return False
    return True


def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    logger.info("\n🛑 Shutting down...")
    sniffer.stop()
    discovery.stop_background_scan()
    logger.info("✅ Cleanup complete. Goodbye!")
    sys.exit(0)


def print_banner():
    """Print startup banner"""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   🌐 Network Monitor v1.0                                     ║
    ║                                                               ║
    ║   Features:                                                   ║
    ║   • Network sniffing on LAN & WiFi                            ║
    ║   • Device identification via OUI (MAC vendor lookup)         ║
    ║   • Real-time web dashboard                                   ║
    ║   • Traffic analysis by device                                ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def run_discovery_only(args):
    """Run device discovery without sniffing"""
    logger.info("🔍 Running device discovery...")
    devices = discovery.scan_all_interfaces()
    
    print(f"\n📱 Found {len(devices)} devices:\n")
    print(f"{'IP Address':<16} {'MAC Address':<18} {'Manufacturer':<20} {'Hostname'}")
    print("-" * 80)
    
    for device in devices:
        print(f"{device.ip or 'N/A':<16} {device.mac:<18} {device.manufacturer or 'Unknown':<20} {device.hostname or ''}")
    
    print()


def run_sniffer_only(args):
    """Run packet sniffer without dashboard"""
    logger.info("📡 Starting packet sniffer...")
    sniffer.start()
    
    print("\n📊 Live traffic stats (Ctrl+C to stop):\n")
    
    try:
        while True:
            time.sleep(5)
            stats = sniffer.get_live_stats()

            if stats:
                print(f"\n--- {time.strftime('%H:%M:%S')} ({len(stats)} active devices) ---")

                sorted_stats = sorted(
                    stats.items(),
                    key=lambda x: x[1]['bytes_sent'] + x[1]['bytes_received'],
                    reverse=True
                )[:10]

                for mac, s in sorted_stats:
                    sent = s['bytes_sent']
                    recv = s['bytes_received']
                    mfr = s.get('manufacturer', 'Unknown')[:15]
                    print(f"  {mac} ({mfr:<15}): ↑{sent:>10,} B  ↓{recv:>10,} B")
            else:
                print(".", end="", flush=True)

    except KeyboardInterrupt:
        pass


def run_full(args):
    """Run full monitoring with dashboard"""
    # Start device discovery
    logger.info("🔍 Starting device discovery...")
    discovery.start_background_scan()
    
    # Do initial scan
    logger.info("📡 Performing initial network scan...")
    devices = discovery.scan_all_interfaces()
    logger.info(f"   Found {len(devices)} devices on initial scan")
    
    # Start packet sniffer
    logger.info("📡 Starting packet sniffer...")
    sniffer.start()
    
    # Start dashboard
    logger.info(f"🌐 Starting dashboard at http://{args.host}:{args.port}")
    
    from dashboard.app import start_dashboard
    start_dashboard(host=args.host, port=args.port, debug=args.debug)


def main():
    parser = argparse.ArgumentParser(
        description='Network Monitor - Sniff and analyze network traffic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py                    # Run full monitoring with dashboard
  sudo python main.py --discover         # Only discover devices
  sudo python main.py --sniff            # Only sniff traffic (no dashboard)
  sudo python main.py --port 8080        # Run dashboard on port 8080
        """
    )
    
    parser.add_argument('--discover', action='store_true',
                        help='Only run device discovery, no sniffing')
    parser.add_argument('--sniff', action='store_true',
                        help='Only run packet sniffer, no dashboard')
    parser.add_argument('--port', type=int, default=DASHBOARD_PORT,
                        help=f'Dashboard port (default: {DASHBOARD_PORT})')
    parser.add_argument('--host', default=DASHBOARD_HOST,
                        help=f'Dashboard host (default: {DASHBOARD_HOST})')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug mode')
    parser.add_argument('--ethernet', default=INTERFACES['ethernet'],
                        help=f'Ethernet interface (default: {INTERFACES["ethernet"]})')
    parser.add_argument('--wifi', default=INTERFACES['wifi'],
                        help=f'WiFi interface (default: {INTERFACES["wifi"]})')
    
    args = parser.parse_args()
    
    # Update interfaces if specified
    INTERFACES['ethernet'] = args.ethernet
    INTERFACES['wifi'] = args.wifi
    
    # Print banner
    print_banner()
    
    # Check privileges
    check_root()
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Print configuration
    logger.info("📋 Configuration:")
    logger.info(f"   Ethernet: {INTERFACES['ethernet']}")
    logger.info(f"   WiFi: {INTERFACES['wifi']}")
    
    # Run appropriate mode
    if args.discover:
        run_discovery_only(args)
    elif args.sniff:
        run_sniffer_only(args)
    else:
        run_full(args)


if __name__ == '__main__':
    main()
