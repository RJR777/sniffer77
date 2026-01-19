"""
Flask web dashboard for network monitoring
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time
import logging

from network_monitor import DASHBOARD_HOST, DASHBOARD_PORT, SECRET_KEY, db, discovery, sniffer, arp_spoofer

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/summary')
def api_summary():
    """Get dashboard summary"""
    summary = db.get_dashboard_summary()
    summary['bytes_sent_formatted'] = format_bytes(summary['bytes_sent_hour'])
    summary['bytes_received_formatted'] = format_bytes(summary['bytes_received_hour'])
    return jsonify(summary)


@app.route('/api/devices')
def api_devices():
    """Get all active devices"""
    devices = db.get_all_devices(active_only=True)
    for d in devices:
        d['bytes_display'] = format_bytes(0)  # Will be updated via live stats
    return jsonify(devices)


@app.route('/api/devices/all')
def api_all_devices():
    """Get all devices including inactive"""
    devices = db.get_all_devices(active_only=False)
    return jsonify(devices)


@app.route('/api/top-talkers')
def api_top_talkers():
    """Get top bandwidth consumers"""
    hours = request.args.get('hours', 1, type=int)
    limit = request.args.get('limit', 10, type=int)
    talkers = db.get_top_talkers(hours=hours, limit=limit)
    for t in talkers:
        t['total_formatted'] = format_bytes(t['total_bytes'])
        t['sent_formatted'] = format_bytes(t['bytes_sent'])
        t['received_formatted'] = format_bytes(t['bytes_received'])
    return jsonify(talkers)


@app.route('/api/connections')
def api_connections():
    """Get recent connections"""
    mac = request.args.get('mac')
    limit = request.args.get('limit', 100, type=int)
    connections = db.get_recent_connections(mac=mac, limit=limit)
    return jsonify(connections)


@app.route('/api/live-stats')
def api_live_stats():
    """Get live traffic stats from sniffer"""
    stats = sniffer.get_live_stats()
    for mac, s in stats.items():
        s['total_bytes'] = s['bytes_sent'] + s['bytes_received']
        s['total_formatted'] = format_bytes(s['total_bytes'])
    return jsonify(stats)


@app.route('/api/device/<mac>/name', methods=['POST'])
def set_device_name(mac):
    """Set custom name for a device"""
    data = request.get_json()
    name = data.get('name', '')
    # Would need to add this method to db
    return jsonify({'success': True, 'mac': mac, 'name': name})


@app.route('/api/device/<mac>/monitor', methods=['POST'])
def toggle_monitoring(mac):
    """Toggle active monitoring (MITM) for a device"""
    data = request.get_json()
    action = data.get('action') # 'start' or 'stop'
    
    # Get IP for this MAC
    # For now, just searching our discovered devices
    device = discovery.devices.get(mac)
    if not device or not device.ip:
        return jsonify({'success': False, 'error': 'Device IP not found'})
        
    if action == 'start':
        try:
            # properly initialize if not running
            if not arp_spoofer._running:
                arp_spoofer.start()
            
            arp_spoofer.add_target(device.ip, mac)
            return jsonify({'success': True, 'status': 'monitoring', 'ip': device.ip})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)})
            
    elif action == 'stop':
        arp_spoofer.remove_target(device.ip)
        return jsonify({'success': True, 'status': 'stopped'})
        
    return jsonify({'success': False, 'error': 'Invalid action'})


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'status': 'ok'})
    logger.info("Dashboard client connected")


@socketio.on('request_update')
def handle_update_request():
    """Send current stats to client"""
    summary = db.get_dashboard_summary()
    talkers = db.get_top_talkers(hours=1, limit=10)
    live_stats = sniffer.get_live_stats()
    emit('stats_update', {'summary': summary, 'top_talkers': talkers, 'live_stats': live_stats})


def background_emitter():
    """Background thread to emit periodic updates"""
    while True:
        time.sleep(5)
        try:
            summary = db.get_dashboard_summary()
            talkers = db.get_top_talkers(hours=1, limit=10)
            live_stats = sniffer.get_live_stats()
            socketio.emit('stats_update', {'summary': summary, 'top_talkers': talkers, 'live_stats': live_stats})
        except Exception as e:
            logger.error(f"Background emitter error: {e}")


def start_dashboard(host: str = DASHBOARD_HOST, port: int = DASHBOARD_PORT, debug: bool = False):
    """Start the dashboard server"""
    # Start background update thread
    update_thread = threading.Thread(target=background_emitter, daemon=True)
    update_thread.start()
    
    logger.info(f"Starting dashboard at http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    start_dashboard(debug=True)
