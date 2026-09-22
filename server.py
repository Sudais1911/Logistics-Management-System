from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
import json
from datetime import datetime
from collections import Counter
import re
import html
import os
import smtplib
import hmac
import hashlib
import base64
import time
from urllib.parse import parse_qs
from email.message import EmailMessage

BASE = Path(__file__).resolve().parent
DATA = BASE / 'data'
DATA.mkdir(exist_ok=True)

SHIPMENTS = DATA / 'shipments.json'
REQUESTS = DATA / 'shipment_requests.json'
MESSAGES = DATA / 'owner_messages.json'


def load_dotenv_file(path):
    """Load simple KEY=VALUE pairs from a local .env file without extra packages."""
    if not path.exists():
        return
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip().strip('\"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value

load_dotenv_file(BASE / '.env')

# Authentication / session configuration. Change all credential values before public deployment.
SESSION_SECRET = os.getenv('SESSION_SECRET', 'change-this-session-secret-before-public-deploy')
SESSION_MAX_AGE = int(os.getenv('SESSION_MAX_AGE', '28800'))
SECURE_COOKIE = os.getenv('SECURE_COOKIE', '0').lower() in {'1', 'true', 'yes'}
OWNER_USERNAME = os.getenv('OWNER_USERNAME', 'owner')
OWNER_PASSWORD = os.getenv('OWNER_PASSWORD', 'Owner@1234')
CLIENT_USERNAME = os.getenv('CLIENT_USERNAME', 'client')
CLIENT_PASSWORD = os.getenv('CLIENT_PASSWORD', 'Client@1234')

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))

def create_session(role: str) -> str:
    payload = {'role': role, 'exp': int(time.time()) + SESSION_MAX_AGE}
    raw = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    body = _b64(raw)
    sig = hmac.new(SESSION_SECRET.encode('utf-8'), body.encode('utf-8'), hashlib.sha256).hexdigest()
    return body + '.' + sig

def get_session(headers):
    cookie_header = headers.get('Cookie', '')
    cookies = {}
    for part in cookie_header.split(';'):
        if '=' in part:
            k, v = part.strip().split('=', 1)
            cookies[k] = v
    token = cookies.get('session')
    if not token or '.' not in token:
        return None
    body, sig = token.rsplit('.', 1)
    expected = hmac.new(SESSION_SECRET.encode('utf-8'), body.encode('utf-8'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_unb64(body).decode('utf-8'))
        if int(payload.get('exp', 0)) < int(time.time()):
            return None
        role = payload.get('role')
        return role if role in {'owner', 'client'} else None
    except Exception:
        return None

def cookie_header(token, max_age=SESSION_MAX_AGE):
    parts = [f'session={token}', 'Path=/', f'Max-Age={max_age}', 'HttpOnly', 'SameSite=Lax']
    if SECURE_COOKIE:
        parts.append('Secure')
    return '; '.join(parts)

def clear_cookie_header():
    parts = ['session=', 'Path=/', 'Max-Age=0', 'HttpOnly', 'SameSite=Lax']
    if SECURE_COOKIE:
        parts.append('Secure')
    return '; '.join(parts)

def credentials_match(username, password):
    if hmac.compare_digest(str(username), OWNER_USERNAME) and hmac.compare_digest(str(password), OWNER_PASSWORD):
        return 'owner'
    if hmac.compare_digest(str(username), CLIENT_USERNAME) and hmac.compare_digest(str(password), CLIENT_PASSWORD):
        return 'client'
    return None

DEFAULT_SHIPMENTS = [
    {
        'tracking_id': 'LX10001', 'client_name': 'Acme Retail Pvt Ltd',
        'origin': 'Bengaluru', 'destination': 'Mumbai', 'status': 'In Transit',
        'last_update': '2026-09-14 10:30', 'eta': '2026-09-16',
        'events': [
            {'time': '2026-09-14 10:30', 'location': 'Bengaluru Hub', 'status': 'In Transit'},
            {'time': '2026-09-13 21:15', 'location': 'Bengaluru Hub', 'status': 'Shipment Departed'},
            {'time': '2026-09-13 15:40', 'location': 'Bengaluru Warehouse', 'status': 'Picked Up'}
        ]
    },
    {
        'tracking_id': 'LX10002', 'client_name': 'North Star Traders',
        'origin': 'Hyderabad', 'destination': 'Chennai', 'status': 'Delivered',
        'last_update': '2026-09-13 17:20', 'eta': 'Delivered',
        'events': [
            {'time': '2026-09-13 17:20', 'location': 'Chennai', 'status': 'Delivered'},
            {'time': '2026-09-13 08:10', 'location': 'Chennai Hub', 'status': 'Out for Delivery'},
            {'time': '2026-09-12 18:35', 'location': 'Hyderabad Hub', 'status': 'In Transit'}
        ]
    }
]

def read_json(path, default):
    if not path.exists():
        path.write_text(json.dumps(default, indent=2), encoding='utf-8')
        return default
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        path.write_text(json.dumps(default, indent=2), encoding='utf-8')
        return default

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2), encoding='utf-8')

read_json(SHIPMENTS, DEFAULT_SHIPMENTS)
read_json(REQUESTS, [])
read_json(MESSAGES, [])

def owner_message(payload):
    msg = {
        'id': datetime.now().strftime('%Y%m%d%H%M%S%f'),
        'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'client_name': str(payload.get('client_name','')).strip(),
        'phone': str(payload.get('phone','')).strip(),
        'request_type': str(payload.get('request_type','')).strip(),
        'origin': str(payload.get('origin','')).strip(),
        'destination': str(payload.get('destination','')).strip(),
        'goods': str(payload.get('goods','')).strip(),
        'quantity': str(payload.get('quantity','')).strip(),
        'pickup_date': str(payload.get('pickup_date','')).strip(),
        'tracking_id': str(payload.get('tracking_id','')).strip(),
        'details': str(payload.get('details','')).strip(),
        'channel': 'Local Prototype',
        'status': 'New'
    }
    messages = read_json(MESSAGES, [])
    messages.insert(0, msg)
    write_json(MESSAGES, messages)
    requests = read_json(REQUESTS, [])
    requests.insert(0, msg)
    write_json(REQUESTS, requests)
    return msg

STYLE = r''':root{--bg:#f4f7fb;--card:#fff;--primary:#1264a3;--primary2:#0b4f82;--text:#17212b;--muted:#64748b;--border:#dbe4ec;--good:#14804a;--shadow:0 10px 30px rgba(0,0,0,.07)}*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text)}.top{background:#0f172a;color:#fff;padding:16px 20px;display:flex;gap:18px;justify-content:space-between;align-items:center;flex-wrap:wrap}.brand{font-weight:800}.nav{display:flex;gap:8px;flex-wrap:wrap}.nav a{color:#fff;background:rgba(255,255,255,.08);padding:8px 11px;border-radius:8px;text-decoration:none}.wrap{max-width:1100px;margin:28px auto;padding:0 16px}.hero,.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:20px;box-shadow:var(--shadow)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}.btn{border:0;border-radius:10px;padding:12px 16px;font-weight:700;cursor:pointer}.primary{background:var(--primary);color:#fff}.light{background:#e8f1f8;color:var(--primary2)}input,textarea{width:100%;padding:12px;border:1px solid var(--border);border-radius:10px;font-size:15px}textarea{min-height:100px;resize:vertical}label{display:block;font-weight:700;margin:10px 0 6px}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:700px){.row{grid-template-columns:1fr}}.chat{max-width:720px;margin:auto}.window{background:#e9f4fb;border:1px solid var(--border);border-radius:18px;padding:16px;min-height:560px}.msg{display:flex;margin:9px 0}.left{justify-content:flex-start}.right{justify-content:flex-end}.bubble{max-width:84%;padding:12px 14px;border-radius:15px}.left .bubble{background:#fff;border:1px solid var(--border)}.right .bubble{background:var(--primary);color:#fff}.options{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}.opt{background:#fff;color:var(--primary2);border:1px solid #b9ccd9;border-radius:10px;padding:10px 12px;cursor:pointer}.result{margin-top:12px;background:#fff;border:1px solid var(--border);padding:14px;border-radius:12px}.status{display:inline-block;padding:5px 9px;border-radius:999px;background:#e9f7f0;color:var(--good);font-weight:700}.notice{padding:12px;border-radius:10px;background:#eef6ff;border:1px solid #cfe4fa}table{width:100%;border-collapse:collapse;background:#fff}.owner-table{table-layout:fixed}.owner-table th,.owner-table td{text-align:left;padding:10px;border-bottom:1px solid var(--border);font-size:14px;vertical-align:top}.owner-table thead th{background:#f8fafc}.owner-table th:first-child{width:18%}.owner-table .action-head,.owner-table .action-cell{width:150px;text-align:right}.contact-btn{display:inline-block;background:var(--primary);color:#fff;text-decoration:none;border-radius:9px;padding:9px 12px;font-weight:700;white-space:nowrap}.contact-btn:hover{background:var(--primary2)}.contact-btn[aria-disabled=\"true\"]{opacity:.5;pointer-events:none}.owner-table .action-cell{border-left:1px solid var(--border);vertical-align:middle}@media(max-width:700px){.owner-table{display:block;overflow-x:auto;white-space:normal}.owner-table .action-head,.owner-table .action-cell{width:125px}}.kpis{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:14px;margin-top:18px}.kpi{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:16px;box-shadow:var(--shadow)}.kpi .num{font-size:30px;font-weight:800;margin-top:5px}.kpi .label{color:var(--muted);font-size:13px}.executive-grid{display:grid;grid-template-columns:1.2fr .8fr;gap:16px;margin-top:18px}.bar-row{margin:10px 0}.bar-label{display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px}.bar-track{height:10px;background:#edf2f7;border-radius:999px;overflow:hidden}.bar-fill{height:100%;background:var(--primary);border-radius:999px}.small-table{width:100%;border-collapse:collapse}.small-table th,.small-table td{padding:9px;border-bottom:1px solid var(--border);text-align:left;font-size:13px}.action-link{color:var(--primary);font-weight:700;text-decoration:none}@media(max-width:900px){.kpis{grid-template-columns:repeat(2,minmax(150px,1fr))}.executive-grid{grid-template-columns:1fr}}@media(max-width:520px){.kpis{grid-template-columns:1fr}}h1,h2,h3{margin-top:0}.muted{color:var(--muted)}.inline-form{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.inline-form input,.inline-form select{width:auto;min-width:130px;padding:9px}.login-wrap{max-width:620px}.login-card{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:24px;box-shadow:var(--shadow);margin:0 auto}.login-header{text-align:center}.role-badge{display:inline-block;background:#e8f1f8;color:var(--primary2);padding:6px 10px;border-radius:999px;font-size:12px;font-weight:800}.role-cards{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:20px 0}.role-card{border:1px solid var(--border);border-radius:14px;padding:16px;background:#fbfdff}.role-icon{font-size:28px}.login-form{margin-top:10px}.login-note{font-size:12px;color:var(--muted);margin-top:14px;text-align:center}.error-notice{background:#fff3f2;border-color:#f5c2c0;color:#a21b16}@media(max-width:600px){.role-cards{grid-template-columns:1fr}}.inline-form input[type=hidden]{display:none}.inline-form .btn{padding:9px 12px}@media(max-width:700px){.inline-form{align-items:stretch}.inline-form input,.inline-form select,.inline-form .btn{width:100%}}'''

LOGIN = '''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Logistics Portal Login</title><link rel="stylesheet" href="/static/style.css"></head><body><div class="top"><div class="brand">Logistics Portal</div></div><div class="wrap login-wrap"><div class="login-card"><div class="login-header"><span class="role-badge">Secure Access</span><h1>Sign in to Logistics Portal</h1><p class="muted">Your login determines which interface you can access.</p></div><div class="role-cards"><div class="role-card"><div class="role-icon">👤</div><h3>Client</h3><p>Track shipments and submit new shipment inquiries.</p></div><div class="role-card"><div class="role-icon">🧑‍💼</div><h3>Owner</h3><p>Manage inquiries, shipments, client updates and the executive dashboard.</p></div></div>{message}<form method="post" action="/login" class="login-form"><label>Username</label><input name="username" autocomplete="username" required><label>Password</label><input type="password" name="password" autocomplete="current-password" required><button class="btn primary" type="submit">Sign In</button></form><p class="login-note">For public deployment, replace the demo credentials with your own environment variables.</p></div></div></body></html>'''

INDEX = '''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Logistics Chatbot</title><link rel="stylesheet" href="/static/style.css"></head><body><div class="top"><div class="brand">Logistics Chatbot</div><div class="nav"><a href="/">Home</a><a href="/chat">Client Chat</a><a href="/owner">Owner Dashboard</a></div></div><div class="wrap"><div class="hero"><h1>Logistics Client Chatbot</h1><p class="muted">Free local prototype for shipment tracking and new-shipment inquiry.</p><div class="grid"><div class="card"><h3>Client Chat</h3><p>Track shipments or submit a guided shipment request.</p><a class="btn primary" href="/chat">Open Client Chat</a></div><div class="card"><h3>Owner Dashboard</h3><p>See client requirements captured by the chatbot.</p><a class="btn light" href="/owner">Open Owner Dashboard</a></div></div></div><div class="card" style="margin-top:18px"><h3>Workflow</h3><p>Client → Shipment Inquiry → Tracking / New Shipment → Owner receives requirements.</p><div class="notice">WhatsApp is not connected in this prototype, so your personal number is untouched.</div></div></div></body></html>'''

CHAT = '''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Client Chat</title><link rel="stylesheet" href="/static/style.css"></head><body><div class="top"><div class="brand">Client Portal</div><div class="nav"><a href="/chat">Client Chat</a><a href="/logout">Logout</a></div></div><div class="wrap chat"><div class="window" id="w"></div></div><script>
const w=document.getElementById('w');
function msg(t,u=false){const d=document.createElement('div');d.className='msg '+(u?'right':'left');const b=document.createElement('div');b.className='bubble';b.innerHTML=t;d.appendChild(b);w.appendChild(d);w.scrollTop=w.scrollHeight}
function opts(arr){const d=document.createElement('div');d.className='options';arr.forEach(x=>{const b=document.createElement('button');b.className='opt';b.textContent=x[0];b.onclick=x[1];d.appendChild(b)});w.appendChild(d)}
function box(html){const d=document.createElement('div');d.className='result';d.innerHTML=html;w.appendChild(d);w.scrollTop=w.scrollHeight;return d}
function menu(){msg('Hello! 👋 Welcome to our logistics service.');msg('What would you like to do?');opts([['📦 Track Shipment',track],['🚚 Request New Shipment',shipment],['💬 Contact Owner',contact]])}
function track(){msg('Track Shipment',true);msg('Please enter your Tracking ID. Example: LX10001');box('<label>Tracking ID</label><input id="tid" placeholder="LX10001"><button class="btn primary" style="margin-top:10px" onclick="doTrack()">Check Status</button>')}
async function doTrack(){const id=document.getElementById('tid').value.trim();if(!id)return;msg(id,true);const r=await fetch('/api/track',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tracking_id:id})});const j=await r.json();if(!j.ok){msg(j.message);opts([['Try Again',track],['Main Menu',menu]]);return}const s=j.shipment;msg('<strong>'+s.tracking_id+'</strong><br><strong>Route:</strong> '+s.origin+' → '+s.destination+'<br><strong>Status:</strong> <span class="status">'+s.status+'</span><br><strong>Last update:</strong> '+s.last_update+'<br><strong>ETA:</strong> '+s.eta+(s.client_update?'<br><br><strong>Latest client update:</strong> '+s.client_update:'') );box('<strong>Tracking history</strong><div>'+s.events.map(e=>'<div style="margin:8px 0"><strong>'+e.status+'</strong><br><span class="muted">'+e.time+' — '+e.location+'</span></div>').join('')+'</div>');opts([['Track Another',track],['Main Menu',menu]])}
function shipment(){msg('Request New Shipment',true);msg('Please complete the shipment inquiry. The owner will receive these requirements.');box('<form id="sf" onsubmit="sendShipment(event)"><div class="row"><div><label>Client Name *</label><input name="client_name" required></div><div><label>Phone *</label><input name="phone" required></div></div><div class="row"><div><label>Origin *</label><input name="origin" required></div><div><label>Destination *</label><input name="destination" required></div></div><div class="row"><div><label>Goods / Cargo *</label><input name="goods" required></div><div><label>Quantity *</label><input name="quantity" required></div></div><label>Pickup Date *</label><input type="date" name="pickup_date" required><label>Additional Details</label><textarea name="details" placeholder="Weight, dimensions, special handling, vehicle type, etc."></textarea><button class="btn primary" style="margin-top:10px" type="submit">Submit Shipment Inquiry</button></form>')}
async function sendShipment(e){e.preventDefault();const data=Object.fromEntries(new FormData(document.getElementById('sf')).entries());const r=await fetch('/api/shipment-request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const j=await r.json();msg(j.message+(j.request_id?'<br>Request ID: <strong>'+j.request_id.slice(-10)+'</strong>':''));opts([['Main Menu',menu]])}
function contact(){msg('Contact Owner',true);box('<form id="cf" onsubmit="sendContact(event)"><label>Your Name *</label><input name="client_name" required><label>Phone *</label><input name="phone" required><label>Message</label><textarea name="details"></textarea><button class="btn primary" style="margin-top:10px" type="submit">Send to Owner</button></form>')}
async function sendContact(e){e.preventDefault();const data=Object.fromEntries(new FormData(document.getElementById('cf')).entries());const r=await fetch('/api/contact-owner',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const j=await r.json();msg(j.message);opts([['Main Menu',menu]])}
menu();</script></body></html>'''


def esc(x):
    return str(x).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('\"','&quot;').replace("'",'&#39;')

OWNER_EMAIL = 'thunders1911@gmail.com'
BATCH_SIZE = max(1, int(os.getenv('EMAIL_BATCH_SIZE', '5')))

def send_email_message(subject, body):
    host = os.getenv('SMTP_HOST', 'smtp.gmail.com')
    port = int(os.getenv('SMTP_PORT', '587'))
    username = os.getenv('SMTP_USERNAME', '')
    password = os.getenv('SMTP_APP_PASSWORD', '')
    sender = os.getenv('SMTP_FROM', username)
    if not username or not password:
        return False, 'Email is saved locally, but SMTP is not configured yet.'
    mail = EmailMessage()
    mail['Subject'] = subject
    mail['From'] = sender
    mail['To'] = OWNER_EMAIL
    mail.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.starttls()
            smtp.login(username, password)
            smtp.send_message(mail)
        return True, f'Batch email sent to {OWNER_EMAIL}.'
    except Exception as exc:
        return False, f'Batch email could not be sent: {exc}'

def pending_new_orders():
    """Return the single GLOBAL queue of unbatched shipment orders.

    Every New Shipment Request counts as one order, regardless of client.
    There is deliberately no per-client grouping or counter.
    """
    messages = read_json(MESSAGES, [])
    pending = [
        m for m in messages
        if m.get('request_type') == 'New Shipment Request'
        and not m.get('email_batched', False)
    ]
    # FIFO: messages are stored newest-first, so reverse the list.
    return list(reversed(pending))


def send_order_batch_if_ready():
    pending = pending_new_orders()
    if len(pending) < BATCH_SIZE:
        return False, f'Global order queue: {len(pending)}/{BATCH_SIZE}. No email sent yet.'

    # One global batch across ALL clients.
    batch = pending[:BATCH_SIZE]
    all_messages = read_json(MESSAGES, [])
    prior_batches = [m for m in all_messages if m.get('email_batch_number')]
    batch_number = (max((int(m.get('email_batch_number', 0)) for m in prior_batches), default=0) + 1)

    lines = [
        'New Logistics Shipment Order Batch',
        '',
        f'Global batch number: {batch_number}',
        f'Orders in this batch: {len(batch)}',
        f'Global batch size: {BATCH_SIZE}',
        '',
        'The orders below are from the shared queue and may belong to different clients.',
        ''
    ]
    for index, m in enumerate(batch, 1):
        lines.extend([
            f'ORDER {index}',
            f"Request ID: {m.get('id','')}",
            f"Client: {m.get('client_name','')}",
            f"Phone: {m.get('phone','')}",
            f"Origin: {m.get('origin','')}",
            f"Destination: {m.get('destination','')}",
            f"Goods: {m.get('goods','')}",
            f"Quantity: {m.get('quantity','')}",
            f"Pickup date: {m.get('pickup_date','')}",
            f"Details: {m.get('details','')}",
            f"Received: {m.get('created_at','')}",
            '-' * 60,
        ])

    sent, email_message = send_email_message(
        f'Logistics Shipment Orders — Global Batch #{batch_number} ({len(batch)} orders)',
        '\n'.join(lines)
    )
    if not sent:
        return False, email_message

    batch_ids = {m.get('id') for m in batch}
    messages = read_json(MESSAGES, [])
    for m in messages:
        if m.get('id') in batch_ids:
            m['email_batched'] = True
            m['email_batch_size'] = len(batch)
            m['email_batch_number'] = batch_number
            m['email_batched_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    write_json(MESSAGES, messages)

    requests = read_json(REQUESTS, [])
    for m in requests:
        if m.get('id') in batch_ids:
            m['email_batched'] = True
            m['email_batch_size'] = len(batch)
            m['email_batch_number'] = batch_number
            m['email_batched_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    write_json(REQUESTS, requests)

    return True, f'{email_message} Global batch #{batch_number} contained {len(batch)} orders from the shared queue. The next order starts the next batch cycle.'

def send_owner_email(message):
    if message.get('request_type') == 'New Shipment Request':
        return send_order_batch_if_ready()
    body = f"""New logistics inquiry\n\nClient: {message.get('client_name','')}\nPhone: {message.get('phone','')}\nRequest: {message.get('request_type','')}\nOrigin: {message.get('origin','')}\nDestination: {message.get('destination','')}\nGoods: {message.get('goods','')}\nQuantity: {message.get('quantity','')}\nPickup date: {message.get('pickup_date','')}\nTracking ID: {message.get('tracking_id','')}\nDetails: {message.get('details','')}\nReceived: {message.get('created_at','')}\n\nRequest ID: {message.get('id','')}"""
    return send_email_message(f"New Logistics Inquiry — {message.get('client_name','Unknown Client')}", body)

def owner_page():
    messages = read_json(MESSAGES, [])
    shipments = read_json(SHIPMENTS, [])

    total_requests = len(messages)
    new_requests = sum(1 for m in messages if str(m.get('status', 'New')).lower() in {'new','pending'})
    in_transit = sum(1 for s in shipments if str(s.get('status', '')).lower() in {'in transit', 'out for delivery', 'picked up', 'shipment departed'})
    delivered = sum(1 for s in shipments if str(s.get('status', '')).lower() == 'delivered')
    status_counts = Counter(str(s.get('status', 'Unknown')) for s in shipments)
    destinations = Counter(str(m.get('destination', 'Unknown')) for m in messages if str(m.get('destination', '')).strip())

    max_status = max(status_counts.values(), default=1)
    status_bars = []
    for label, count in sorted(status_counts.items(), key=lambda x: (-x[1], x[0])):
        width = int((count / max_status) * 100)
        status_bars.append('<div class="bar-row"><div class="bar-label"><span>' + esc(label) + '</span><strong>' + str(count) + '</strong></div><div class="bar-track"><div class="bar-fill" style="width:' + str(width) + '%"></div></div></div>')
    bars_html = ''.join(status_bars) or '<p class="muted">No shipment status data yet.</p>'

    recent_rows=[]
    for m in messages[:5]:
        recent_rows.append('<tr><td>'+esc(m.get('created_at',''))+'</td><td>'+esc(m.get('client_name',''))+'</td><td>'+esc(m.get('request_type',''))+'</td><td>'+esc(m.get('destination',''))+'</td><td><span class="status">'+esc(m.get('status','New'))+'</span></td></tr>')
    recent_html=''.join(recent_rows) or '<tr><td colspan="5" class="muted">No requests received yet.</td></tr>'

    destination_rows=[]
    for dest,count in destinations.most_common(5):
        destination_rows.append('<tr><td>'+esc(dest)+'</td><td>'+str(count)+'</td></tr>')
    destination_html=''.join(destination_rows) or '<tr><td colspan="2" class="muted">No destination data yet.</td></tr>'

    shipment_rows=[]
    for sh in shipments:
        tid=esc(sh.get('tracking_id',''))
        shipment_rows.append(
            '<tr><td><strong>'+tid+'</strong></td><td>'+esc(sh.get('client_name',''))+'</td><td>'+esc(sh.get('origin',''))+' → '+esc(sh.get('destination',''))+'</td>'
            '<td><span class="status">'+esc(sh.get('status',''))+'</span></td><td>'+esc(sh.get('eta',''))+'</td>'
            '<td><form class="inline-form" onsubmit="updateShipment(event)"><input type="hidden" name="tracking_id" value="'+tid+'">'
            '<select name="status"><option '+('selected' if sh.get('status')=='Booked' else '')+'>Booked</option><option '+('selected' if sh.get('status')=='Picked Up' else '')+'>Picked Up</option><option '+('selected' if sh.get('status')=='In Transit' else '')+'>In Transit</option><option '+('selected' if sh.get('status')=='Out for Delivery' else '')+'>Out for Delivery</option><option '+('selected' if sh.get('status')=='Delivered' else '')+'>Delivered</option><option '+('selected' if sh.get('status')=='Delayed' else '')+'>Delayed</option><option '+('selected' if sh.get('status')=='On Hold' else '')+'>On Hold</option></select>'
            '<input name="location" placeholder="Current location" value="'+esc(sh.get('events',[{}])[0].get('location','') if sh.get('events') else '')+'">'
            '<input name="eta" placeholder="ETA" value="'+esc(sh.get('eta',''))+'">'
            '<input name="note" placeholder="Client update / note">'
            '<button class="btn primary" type="submit">Update</button></form></td></tr>'
        )
    shipment_html=''.join(shipment_rows) or '<tr><td colspan="6" class="muted">No shipments available.</td></tr>'

    cards=[]
    for m in messages:
        phone_raw=str(m.get('phone','')).strip(); phone_digits=re.sub(r'[^0-9+]','',phone_raw)
        contact_href='tel:'+phone_digits if phone_digits else '#'; contact_attr='' if phone_digits else ' aria-disabled="true" onclick="return false;"'
        status_options=''.join('<option '+('selected' if m.get('status', 'New')==x else '')+'>'+x+'</option>' for x in ['New','Pending','Approved','Contacted','Rejected','Closed'])
        card=(
          '<div class="card" style="margin-top:18px"><div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap">'
          '<div><h3 style="margin-bottom:5px">'+esc(m.get('request_type',''))+'</h3><div class="muted">Received '+esc(m.get('created_at',''))+'</div></div>'
          '<span class="status">'+esc(m.get('status','New'))+'</span></div>'
          '<table class="owner-table" style="margin-top:12px"><thead><tr><th>Field</th><th>Client Requirement</th><th class="action-head">Action</th></tr></thead><tbody>'
          '<tr><th>Client</th><td>'+esc(m.get('client_name',''))+'</td><td class="action-cell" rowspan="2"><a class="contact-btn" href="'+html.escape(contact_href, quote=True)+'"'+contact_attr+'>Contact</a></td></tr>'
          '<tr><th>Phone</th><td>'+esc(phone_raw)+'</td></tr>'
          '<tr><th>Origin</th><td>'+(esc(m.get('origin','')) or '-')+'</td><td></td></tr>'
          '<tr><th>Destination</th><td>'+(esc(m.get('destination','')) or '-')+'</td><td></td></tr>'
          '<tr><th>Goods</th><td>'+(esc(m.get('goods','')) or '-')+'</td><td></td></tr>'
          '<tr><th>Quantity</th><td>'+(esc(m.get('quantity','')) or '-')+'</td><td></td></tr>'
          '<tr><th>Pickup Date</th><td>'+(esc(m.get('pickup_date','')) or '-')+'</td><td></td></tr>'
          '<tr><th>Tracking ID</th><td>'+(esc(m.get('tracking_id','')) or '-')+'</td><td></td></tr>'
          '<tr><th>Details</th><td>'+(esc(m.get('details','')) or '-')+'</td><td></td></tr>'
          '<tr><th>Inquiry Status</th><td><form onsubmit="updateInquiry(event)" class="inline-form"><input type="hidden" name="id" value="'+esc(m.get('id',''))+'"><select name="status">'+status_options+'</select><input name="note" placeholder="Owner note (optional)"><button class="btn light" type="submit">Save</button></form></td><td></td></tr>'
          '</tbody></table></div>'
        )
        cards.append(card)
    details_html=''.join(cards) or '<div class="card" style="margin-top:18px"><p>No client requests yet. Submit one from the Client Chat.</p></div>'

    return ('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    '<title>Executive Owner Dashboard</title><link rel="stylesheet" href="/static/style.css"></head><body>'
    '<div class="top"><div class="brand">Logistics — Executive Owner Dashboard</div><div class="nav"><a href="/owner">Dashboard</a><a href="/logout">Logout</a></div></div><div class="wrap">'
    '<div class="hero"><h1>Executive Owner Dashboard</h1><p class="muted">Manage inquiries, update shipments and keep clients informed.</p><div class="kpis">'
    '<div class="kpi"><div class="label">Total Client Inquiries</div><div class="num">'+str(total_requests)+'</div></div>'
    '<div class="kpi"><div class="label">New / Pending Inquiries</div><div class="num">'+str(new_requests)+'</div></div>'
    '<div class="kpi"><div class="label">Shipments In Transit</div><div class="num">'+str(in_transit)+'</div></div>'
    '<div class="kpi"><div class="label">Delivered Shipments</div><div class="num">'+str(delivered)+'</div></div></div></div>'
    '<div class="executive-grid"><div class="card"><h2>Shipment Status</h2>'+bars_html+'</div><div class="card"><h2>Top Destinations</h2><table class="small-table"><thead><tr><th>Destination</th><th>Requests</th></tr></thead><tbody>'+destination_html+'</tbody></table></div></div>'
    '<div class="card" style="margin-top:18px"><div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap"><h2 style="margin:0">Shipment Management</h2><span class="muted">Update status, location, ETA and client-facing note</span></div>'
    '<div style="overflow-x:auto;margin-top:10px"><table class="small-table"><thead><tr><th>Tracking ID</th><th>Client</th><th>Route</th><th>Status</th><th>ETA</th><th>Update</th></tr></thead><tbody>'+shipment_html+'</tbody></table></div></div>'
    '<div id="toast" class="notice" style="display:none;margin-top:14px"></div>'
    '<div class="card" style="margin-top:18px"><h2 style="margin-bottom:8px">Recent Client Activity</h2><div style="overflow-x:auto"><table class="small-table"><thead><tr><th>Received</th><th>Client</th><th>Request</th><th>Destination</th><th>Status</th></tr></thead><tbody>'+recent_html+'</tbody></table></div></div>'
    '<h2 style="margin-top:28px">Client Requirements</h2><p class="muted">Approve/contact/close inquiries, and use the phone shortcut to contact the client.</p>'+details_html+
    '</div><script>\n'
    'async function post(url,data){const r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)});return await r.json();}\n'
    'function toast(t){const x=document.getElementById("toast");x.textContent=t;x.style.display="block";setTimeout(()=>x.style.display="none",3500);}\n'
    'async function updateShipment(e){e.preventDefault();const f=e.target;const d=Object.fromEntries(new FormData(f).entries());const r=await post("/api/shipment-update",d);toast(r.message||"Updated");if(r.ok)setTimeout(()=>location.reload(),500);}\n'
    'async function updateInquiry(e){e.preventDefault();const f=e.target;const d=Object.fromEntries(new FormData(f).entries());const r=await post("/api/inquiry-update",d);toast(r.message||"Updated");if(r.ok)setTimeout(()=>location.reload(),500);}\n'
    '</script></body></html>')


def login_page(message=''):
    safe_message = ''
    if message:
        safe_message = '<div class="notice error-notice">' + esc(message) + '</div>'
    return LOGIN.replace('{message}', safe_message)

class Handler(BaseHTTPRequestHandler):
    def send_bytes(self, data, content_type='text/html; charset=utf-8', status=200):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def page(self, html): self.send_bytes(html.encode('utf-8'))
    def json(self, obj, status=200): self.send_bytes(json.dumps(obj).encode(), 'application/json; charset=utf-8', status)

    def redirect(self, location, extra_headers=None, status=303):
        self.send_response(status)
        self.send_header('Location', location)
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def unauthorized(self, api=False):
        if api:
            self.json({'ok': False, 'message': 'Unauthorized. Please sign in first.'}, 401)
        else:
            self.redirect('/login')

    def require_role(self, role, api=False):
        current = get_session(self.headers)
        if current != role:
            self.unauthorized(api=api)
            return False
        return True

    def do_GET(self):
        path = urlparse(self.path).path
        current = get_session(self.headers)
        if path == '/':
            if current == 'owner': self.redirect('/owner')
            elif current == 'client': self.redirect('/chat')
            else: self.page(login_page())
        elif path == '/login':
            if current == 'owner': self.redirect('/owner')
            elif current == 'client': self.redirect('/chat')
            else: self.page(login_page())
        elif path == '/logout':
            self.redirect('/login', {'Set-Cookie': clear_cookie_header()})
        elif path == '/chat':
            if self.require_role('client'): self.page(CHAT)
        elif path == '/owner':
            if self.require_role('owner'): self.page(owner_page())
        elif path == '/static/style.css': self.send_bytes(STYLE.encode(), 'text/css; charset=utf-8')
        elif path == '/api/messages':
            if self.require_role('owner', api=True): self.json(read_json(MESSAGES, []))
        else: self.send_bytes(b'Not found', 'text/plain; charset=utf-8', 404)

    def read_body(self):
        n = int(self.headers.get('Content-Length','0'))
        raw = self.rfile.read(n)
        try: return json.loads(raw.decode('utf-8'))
        except Exception: return {}

    def do_POST(self):
        path = urlparse(self.path).path
        if path == '/login':
            length = int(self.headers.get('Content-Length', '0'))
            raw = self.rfile.read(length).decode('utf-8')
            form = parse_qs(raw)
            username = form.get('username', [''])[0]
            password = form.get('password', [''])[0]
            role = credentials_match(username, password)
            if not role:
                self.page(login_page('Invalid username or password.'))
                return
            self.redirect('/owner' if role == 'owner' else '/chat', {'Set-Cookie': cookie_header(create_session(role))})
            return

        data = self.read_body()
        protected_roles = {
            '/api/track': 'client',
            '/api/shipment-request': 'client',
            '/api/contact-owner': 'client',
            '/api/shipment-update': 'owner',
            '/api/inquiry-update': 'owner',
            '/api/whatsapp-owner-notification': 'owner'
        }
        required_role = protected_roles.get(path)
        if required_role and not self.require_role(required_role, api=True):
            return
        if path == '/api/track':
            tid = str(data.get('tracking_id','')).strip().upper()
            shipments = read_json(SHIPMENTS, [])
            found = next((s for s in shipments if s['tracking_id'].upper() == tid), None)
            if not found: self.json({'ok':False,'message':'Tracking ID not found. Please check the ID and try again.'},404)
            else: self.json({'ok':True,'shipment':found})
        elif path == '/api/shipment-request':
            required = ['client_name','phone','origin','destination','goods','quantity','pickup_date']
            if any(not str(data.get(k,'')).strip() for k in required):
                self.json({'ok':False,'message':'Please complete all required fields.'},400); return
            m = owner_message({**data,'request_type':'New Shipment Request'})
            sent, email_message = send_owner_email(m)
            self.json({'ok':True,'message':'Your shipment request has been submitted successfully. The owner has received your requirements. '+email_message,'request_id':m['id'],'email_sent':sent})
        elif path == '/api/contact-owner':
            if not str(data.get('client_name','')).strip() or not str(data.get('phone','')).strip():
                self.json({'ok':False,'message':'Name and phone are required.'},400); return
            m = owner_message({**data,'request_type':'General Inquiry'})
            sent, email_message = send_owner_email(m)
            self.json({'ok':True,'message':'Your inquiry has been sent to the owner. '+email_message,'request_id':m['id'],'email_sent':sent})
        elif path == '/api/shipment-update':
            tid=str(data.get('tracking_id','')).strip().upper()
            shipments=read_json(SHIPMENTS,[])
            sh=next((x for x in shipments if str(x.get('tracking_id','')).upper()==tid),None)
            if not sh:
                self.json({'ok':False,'message':'Shipment not found.'},404); return
            status=str(data.get('status','')).strip() or sh.get('status','In Transit')
            location=str(data.get('location','')).strip()
            eta=str(data.get('eta','')).strip() or sh.get('eta','')
            note=str(data.get('note','')).strip()
            now=datetime.now().strftime('%Y-%m-%d %H:%M')
            sh['status']=status; sh['eta']=eta; sh['last_update']=now
            event={'time':now,'location':location or (sh.get('events',[{}])[0].get('location','') if sh.get('events') else ''),'status':status}
            if note: event['note']=note; sh['client_update']=note
            sh.setdefault('events',[]).insert(0,event)
            write_json(SHIPMENTS,shipments)
            self.json({'ok':True,'message':'Shipment updated. The new status, ETA and client-facing update are now visible when the client checks tracking.'})
        elif path == '/api/inquiry-update':
            inquiry_id=str(data.get('id','')).strip()
            messages=read_json(MESSAGES,[]); requests=read_json(REQUESTS,[])
            found=None
            for arr in (messages,requests):
                for m in arr:
                    if str(m.get('id',''))==inquiry_id:
                        m['status']=str(data.get('status','New')).strip() or 'New'
                        m['owner_note']=str(data.get('note','')).strip()
                        m['updated_at']=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        found=m
            if not found:
                self.json({'ok':False,'message':'Inquiry not found.'},404); return
            write_json(MESSAGES,messages); write_json(REQUESTS,requests)
            self.json({'ok':True,'message':'Inquiry status updated.'})
        elif path == '/api/whatsapp-owner-notification':
            self.json({'ok':True,'mode':'prototype','message':'WhatsApp is not connected yet. Owner message is stored locally.','payload_preview':data})
        else: self.send_bytes(b'Not found','text/plain; charset=utf-8',404)

if __name__ == '__main__':
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', '5000'))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f'Logistics chatbot running at http://{host}:{port}')
    print('Open / for login, /chat for client UI and /owner for owner dashboard.')
    server.serve_forever()
