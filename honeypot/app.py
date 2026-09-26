"""
PHANTOM GRID - Advanced Honeypot System
Sci-Fi themed security honeypot with real protocol listeners
"""
# eventlet monkey-patch MUST come first before any other imports
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning, module='eventlet')
import eventlet
eventlet.monkey_patch()

import os
import json
import threading
import logging
import sys
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from modules.protocol_manager import ProtocolManager
from modules.log_manager import LogManager
from modules.config_manager import ConfigManager

# ─── Flask App Setup ─────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(32)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ─── Global State ─────────────────────────────────────────────────────────────
config_mgr = ConfigManager()
log_mgr = LogManager(socketio)
protocol_mgr = ProtocolManager(log_mgr, config_mgr)

USERS = {}  # username -> hashed password (set at startup)

# ─── User Model ───────────────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    if user_id in USERS:
        return User(user_id)
    return None

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if not USERS:
        return redirect(url_for('setup'))
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    global USERS
    if USERS:
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if len(username) >= 3 and len(password) >= 6:
            USERS[username] = generate_password_hash(password)
            config_mgr.set('admin_user', username)
            config_mgr.save()
            return redirect(url_for('login'))
        return render_template('setup.html', error='Username ≥3 chars, password ≥6 chars')
    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not USERS:
        return redirect(url_for('setup'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if username in USERS and check_password_hash(USERS[username], password):
            login_user(User(username))
            return redirect(url_for('index'))
        return render_template('login.html', error='ACCESS DENIED — Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.route('/api/status')
@login_required
def api_status():
    return jsonify(protocol_mgr.get_status())

@app.route('/api/logs')
@login_required
def api_logs():
    limit = int(request.args.get('limit', 200))
    proto = request.args.get('proto', None)
    return jsonify(log_mgr.get_logs(limit=limit, proto=proto))

@app.route('/api/stats')
@login_required
def api_stats():
    return jsonify(log_mgr.get_stats())

@app.route('/api/protocol/toggle', methods=['POST'])
@login_required
def api_toggle_protocol():
    data = request.get_json()
    proto = data.get('protocol')
    action = data.get('action')  # 'start' or 'stop'
    result = protocol_mgr.toggle(proto, action)
    return jsonify(result)

@app.route('/api/protocol/banner', methods=['POST'])
@login_required
def api_set_banner():
    data = request.get_json()
    proto = data.get('protocol')
    banner = data.get('banner')
    config_mgr.set_banner(proto, banner)
    result = protocol_mgr.reload_banner(proto)
    return jsonify({'ok': True, 'proto': proto, 'banner': banner})

@app.route('/api/banners/presets')
@login_required
def api_banner_presets():
    return jsonify(config_mgr.get_banner_presets())

@app.route('/api/logs/export')
@login_required
def api_export_logs():
    from flask import Response
    fmt = request.args.get('format', 'json')
    data = log_mgr.export(fmt)
    mime = 'application/json' if fmt == 'json' else 'text/plain'
    return Response(data, mimetype=mime,
                    headers={'Content-Disposition': f'attachment; filename=honeypot_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.{fmt}'})

@app.route('/api/logs/clear', methods=['POST'])
@login_required
def api_clear_logs():
    log_mgr.clear()
    return jsonify({'ok': True})

@app.route('/api/protocols/start_all', methods=['POST'])
@login_required
def api_start_all():
    results = {}
    for proto in ['http', 'ftp', 'ssh', 'snmp', 'smb', 'telnet', 'smtp']:
        results[proto] = protocol_mgr.toggle(proto, 'start')
    return jsonify(results)

@app.route('/api/config')
@login_required
def api_get_config():
    return jsonify(config_mgr.get_all())

@app.route('/api/config', methods=['POST'])
@login_required
def api_set_config():
    data = request.get_json()
    for k, v in data.items():
        config_mgr.set(k, v)
    config_mgr.save()
    return jsonify({'ok': True})

# ─── SocketIO Events ──────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    if not current_user.is_authenticated:
        return False
    emit('status', protocol_mgr.get_status())
    emit('init_logs', log_mgr.get_logs(limit=100))

@socketio.on('request_stats')
def on_request_stats():
    emit('stats_update', log_mgr.get_stats())

# ─── Startup ──────────────────────────────────────────────────────────────────

def start_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          P H A N T O M   G R I D  v2.0                      ║
║          Advanced Honeypot Security System                   ║
╠══════════════════════════════════════════════════════════════╣
║  Protocols: HTTP · FTP · SSH · SNMP · SMB · Telnet · SMTP  ║
╚══════════════════════════════════════════════════════════════╝
""")

if __name__ == '__main__':
    start_banner()
    print("[*] Starting PHANTOM GRID on http://0.0.0.0:5000")
    print("[*] On first run: visit http://localhost:5000/setup to create admin account")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
