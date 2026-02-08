import os
import sys
import asyncio
import json
import logging
from typing import Set
from contextlib import asynccontextmanager

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

from network_monitor import DASHBOARD_HOST, DASHBOARD_PORT, SECRET_KEY, db, discovery, sniffer, arp_spoofer

logger = logging.getLogger(__name__)

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"🟢 Dashboard client connected from {websocket.client.host}")
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info("🔴 Dashboard client disconnected")
    
    async def broadcast(self, message: dict):
        """Send message to all connected clients"""
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.add(connection)
        # Clean up disconnected clients
        self.active_connections -= disconnected

manager = ConnectionManager()

# Background task flag
_running_emitter = True


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def _get_processed_devices(active_only=True):
    """Helper to get and process device list for dashboard"""
    from network_monitor import is_excluded_host
    
    devices = db.get_all_devices(active_only=active_only)
    # Filter out excluded hosts (crypto1, etc.) - they shouldn't appear in dashboard
    devices = [d for d in devices if not is_excluded_host(ip=d.get('ip'), hostname=d.get('hostname'), mac=d.get('mac'))]
    
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


def get_stats_payload():
    """Build the stats payload for WebSocket broadcast"""
    summary = db.get_dashboard_summary()
    summary['bytes_sent_formatted'] = format_bytes(summary['bytes_sent_hour'])
    summary['bytes_received_formatted'] = format_bytes(summary['bytes_received_hour'])
    
    talkers = db.get_top_talkers(hours=1, limit=10)
    for t in talkers:
        t['total_formatted'] = format_bytes(t['total_bytes'])
        t['sent_formatted'] = format_bytes(t['bytes_sent'])
        t['received_formatted'] = format_bytes(t['bytes_received'])
    
    live_stats = sniffer.get_live_stats()
    for mac, s in live_stats.items():
        s['total_bytes'] = s['bytes_sent'] + s['bytes_received']
        s['total_formatted'] = format_bytes(s['total_bytes'])
    
    devices = _get_processed_devices(active_only=True)
    
    return {
        'type': 'stats_update',
        'summary': summary,
        'top_talkers': talkers,
        'live_stats': live_stats,
        'devices': devices
    }


async def background_emitter():
    """Background task to emit periodic updates via WebSocket"""
    global _running_emitter
    while _running_emitter:
        await asyncio.sleep(5)
        if manager.active_connections:
            try:
                payload = get_stats_payload()
                await manager.broadcast(payload)
            except Exception as e:
                if _running_emitter:
                    logger.error(f"Background emitter error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup and shutdown events"""
    global _running_emitter
    _running_emitter = True
    # Start background emitter
    emitter_task = asyncio.create_task(background_emitter())
    logger.info("📡 Background stats emitter started")
    yield
    # Shutdown
    _running_emitter = False
    emitter_task.cancel()
    try:
        await emitter_task
    except asyncio.CancelledError:
        pass
    logger.info("📡 Background stats emitter stopped")


# Create FastAPI app
app = FastAPI(title="Network Monitor", lifespan=lifespan)

# Mount static files and templates
templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
static_dir = os.path.join(os.path.dirname(__file__), 'static')
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)


# Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main dashboard page"""
    logger.info(f"🌐 Dashboard requested from {request.client.host}")
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/summary")
async def api_summary():
    """Get dashboard summary"""
    summary = db.get_dashboard_summary()
    summary['bytes_sent_formatted'] = format_bytes(summary['bytes_sent_hour'])
    summary['bytes_received_formatted'] = format_bytes(summary['bytes_received_hour'])
    return JSONResponse(summary)


@app.get("/api/devices")
async def api_devices():
    """Get all active devices"""
    return JSONResponse(_get_processed_devices(active_only=True))


@app.get("/api/devices/all")
async def api_all_devices():
    """Get all devices including inactive"""
    devices = db.get_all_devices(active_only=False)
    return JSONResponse(devices)


@app.get("/api/top-talkers")
async def api_top_talkers(hours: int = 1, limit: int = 10):
    """Get top bandwidth consumers"""
    talkers = db.get_top_talkers(hours=hours, limit=limit)
    for t in talkers:
        t['total_formatted'] = format_bytes(t['total_bytes'])
        t['sent_formatted'] = format_bytes(t['bytes_sent'])
        t['received_formatted'] = format_bytes(t['bytes_received'])
    return JSONResponse(talkers)


@app.get("/api/connections")
async def api_connections(mac: str = None, limit: int = 100):
    """Get recent connections"""
    connections = db.get_recent_connections(mac=mac, limit=limit)
    return JSONResponse(connections)


@app.get("/api/live-stats")
async def api_live_stats():
    """Get live traffic stats from sniffer"""
    stats = sniffer.get_live_stats()
    for mac, s in stats.items():
        s['total_bytes'] = s['bytes_sent'] + s['bytes_received']
        s['total_formatted'] = format_bytes(s['total_bytes'])
    return JSONResponse(stats)


@app.post("/api/device/{mac}/name")
async def set_device_name(mac: str, request: Request):
    """Set custom name for a device"""
    data = await request.json()
    name = data.get('name', '')
    return JSONResponse({'success': True, 'mac': mac, 'name': name})


@app.post("/api/shutdown")
async def api_shutdown():
    """Shutdown the entire application"""
    global _running_emitter
    logger.info("🛑 Shutdown requested via dashboard")
    
    _running_emitter = False
    
    # Stop core monitor components
    try:
        sniffer.stop()
    except Exception as e:
        logger.error(f"Error stopping sniffer: {e}")
        
    try:
        discovery.stop_background_scan()
    except Exception as e:
        logger.error(f"Error stopping discovery: {e}")
        
    try:
        import network_monitor
        if getattr(network_monitor, 'FINGERPRINTING_AVAILABLE', False):
            from device_fingerprint import fingerprinter
            fingerprinter.stop()
    except Exception as e:
        logger.error(f"Error stopping fingerprinter: {e}")
    
    # Schedule delayed exit
    async def delayed_exit():
        await asyncio.sleep(1)
        logger.info("System process exiting.")
        os._exit(0)
    
    asyncio.create_task(delayed_exit())
    
    return JSONResponse({'success': True, 'message': 'System is shutting down...'})


@app.post("/api/device/{mac}/monitor")
async def toggle_monitoring(mac: str, request: Request):
    """Toggle active monitoring (MITM) for a device"""
    data = await request.json()
    action = data.get('action')
    
    # Get IP for this MAC
    device = discovery.devices.get(mac)
    device_ip = device.ip if device else None
    
    # Fallback to database if not in RAM
    if not device_ip:
        db_device = db.get_device(mac)
        if db_device:
            device_ip = db_device.get('ip')
            
    if not device_ip:
        logger.warning(f"❌ Cannot start monitoring for {mac}: IP not found")
        return JSONResponse({'success': False, 'error': 'Device IP not found'})
        
    if action == 'start':
        try:
            # Run blocking ARP operations in thread pool to avoid blocking event loop
            if not arp_spoofer._running:
                await asyncio.to_thread(arp_spoofer.start)
            await asyncio.to_thread(arp_spoofer.add_target, device_ip, mac)
            return JSONResponse({'success': True, 'status': 'monitoring', 'ip': device_ip})
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
            return JSONResponse({'success': False, 'error': str(e)})
            
    elif action == 'stop':
        await asyncio.to_thread(arp_spoofer.remove_target, device_ip)
        return JSONResponse({'success': True, 'status': 'stopped'})
        
    return JSONResponse({'success': False, 'error': 'Invalid action'})


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    
    # Send initial stats immediately
    try:
        payload = get_stats_payload()
        payload['type'] = 'connected'
        await websocket.send_json(payload)
    except Exception as e:
        logger.error(f"Error sending initial stats: {e}")
    
    try:
        while True:
            # Wait for any message from client (keepalive or request)
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get('type') == 'request_update':
                    payload = get_stats_payload()
                    await websocket.send_json(payload)
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


def start_dashboard(host: str = DASHBOARD_HOST, port: int = DASHBOARD_PORT, debug: bool = False):
    """Start the dashboard server"""
    logger.info(f"🚀 Initializing dashboard server on {host}:{port}...")
    logger.info(f"🌐 Dashboard is LIVE at http://{host}:{port}")
    
    try:
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="warning" if not debug else "info",
            access_log=False
        )
    except Exception as e:
        logger.error(f"❌ Failed to start dashboard: {e}")
        import traceback
        logger.error(traceback.format_exc())


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    start_dashboard(debug=True)
