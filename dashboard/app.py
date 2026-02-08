import os
import sys

# Apply eventlet monkey patch before other imports
try:
    import eventlet
    eventlet.monkey_patch()
except ImportError:
    pass

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

# Use eventlet or gevent if available for better websocket performance
# Force only websocket transport to avoid HTTP GET polling logs
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet', transports=['websocket'])




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
    logger.info(f"🌐 Dashboard requested from {request.remote_addr}")
    return render_template('index.html')



@app.route('/api/summary')
def api_summary():
    """Get dashboard summary"""
    logger.debug(f"📊 Summary requested from {request.remote_addr}")
    summary = db.get_dashboard_summary()
    summary['bytes_sent_formatted'] = format_bytes(summary['bytes_sent_hour'])
    summary['bytes_received_formatted'] = format_bytes(summary['bytes_received_hour'])
    return jsonify(summary)


def _get_processed_devices(active_only=True):
    """Helper to get and process device list for dashboard"""
    import json
    devices = db.get_all_devices(active_only=active_only)
    for d in devices:
        d['bytes_display'] = format_bytes(0)
        if d.get('metadata'):
            try:
                meta = json.loads(d['metadata']) if isinstance(d['metadata'], str) else d['metadata']
                d['services'] = meta.get('services', [])
                d['discovery_methods'] = meta.get('discovery_methods', [])
                d['dhcp_lease_time'] = meta.get('dhcp_lease_time')
                if d['dhcp_lease_time']:
                    hours = d['dhcp_lease_time'] // 3600
                    d['dhcp_lease_display'] = f"{hours}h" if hours else f"{d['dhcp_lease_time'] // 60}m"
            except:
                pass
    return devices


@app.route('/api/devices')
def api_devices():
    """Get all active devices"""
    return jsonify(_get_processed_devices(active_only=True))



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


@app.route('/api/shutdown', methods=['POST'])
def api_shutdown():
    """Shutdown the entire application"""
    logger.info("🛑 Shutdown requested via dashboard")
    
    # 1. Stop background threads in this module
    global _running_emitter
    _running_emitter = False
    
    # 2. Stop core monitor components
    try:
        sniffer.stop()
    except Exception as e:
        logger.error(f"Error stopping sniffer: {e}")
        
    try:
        discovery.stop_background_scan()
    except Exception as e:
        logger.error(f"Error stopping discovery: {e}")
        
    try:
        # Stop fingerprinter if available
        import network_monitor
        if getattr(network_monitor, 'FINGERPRINTING_AVAILABLE', False):
            from device_fingerprint import fingerprinter
            fingerprinter.stop()
    except Exception as e:
        logger.error(f"Error stopping fingerprinter: {e}")
    
    # 3. Shutdown Flask/SocketIO
    # We use a separate thread to exit so we can return the success response first
    def delayed_exit():
        time.sleep(1)
        logger.info("System process exiting.")
        os._exit(0)
    
    threading.Thread(target=delayed_exit, daemon=True).start()
    
    return jsonify({'success': True, 'message': 'System is shutting down...'})


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
    logger.info(f"🟢 Dashboard client connected from {request.remote_addr}")
    emit('connected', {'status': 'ok'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info("🔴 Dashboard client disconnected")



@socketio.on('request_update')
def handle_update_request():
    """Send current stats to client"""
    summary = db.get_dashboard_summary()
    talkers = db.get_top_talkers(hours=1, limit=10)
    live_stats = sniffer.get_live_stats()
    devices = _get_processed_devices(active_only=True)
    emit('stats_update', {
        'summary': summary, 
        'top_talkers': talkers, 
        'live_stats': live_stats,
        'devices': devices
    })




_running_emitter = True

def background_emitter():
    """Background thread to emit periodic updates"""
    with app.app_context():
        while _running_emitter:
            time.sleep(5)
            try:
                summary = db.get_dashboard_summary()
                talkers = db.get_top_talkers(hours=1, limit=10)
                live_stats = sniffer.get_live_stats()
                devices = _get_processed_devices(active_only=True)
                socketio.emit('stats_update', {
                    'summary': summary, 
                    'top_talkers': talkers, 
                    'live_stats': live_stats,
                    'devices': devices
                })
            except Exception as e:
                if _running_emitter:
                    logger.error(f"Background emitter error: {e}")
                    import traceback
                    logger.error(traceback.format_exc())




def start_dashboard(host: str = DASHBOARD_HOST, port: int = DASHBOARD_PORT, debug: bool = False):
    """Start the dashboard server"""
    logger.info(f"🚀 Initializing dashboard server on {host}:{port}...")
    
    # Start background update thread
    update_thread = threading.Thread(target=background_emitter, daemon=True)
    update_thread.start()
    logger.info("📡 Background stats emitter thread started")
    
    try:
        logger.info(f"🌐 Dashboard is LIVE at http://{host}:{port}")
        # When using eventlet, we should avoid allow_unsafe_werkzeug=True if possible
        # and we set debug=False to avoid issues with sudo/threads
        socketio.run(app, host=host, port=port, debug=False, log_output=True)
    except Exception as e:
        logger.error(f"❌ Failed to start dashboard: {e}")
        import traceback
        logger.error(traceback.format_exc())



if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    start_dashboard(debug=True)
