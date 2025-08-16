from __future__ import annotations
import os, sqlite3, csv, io, datetime as dt, json, uuid, time
from functools import wraps
from flask import Flask, g, request, redirect, url_for, make_response, abort, render_template_string as T, session, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect, generate_csrf

APP_NAME = "LMNOP"
DB_PATH = os.environ.get("LMNOP_DB", "lmnop.db")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")  # bootstrap first admin
SECRET = os.environ.get("SECRET_KEY")
if not SECRET:
    raise RuntimeError("SECRET_KEY environment variable required")

app = Flask(__name__)
app.secret_key = SECRET
app.config['WTF_CSRF_SECRET_KEY'] = os.environ.get('WTF_CSRF_SECRET_KEY', SECRET)
csrf = CSRFProtect(app)

# file uploads
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
TS_PHOTO_DIR = os.path.join(UPLOAD_FOLDER, 'timesheet_photos')
JOB_FILE_DIR = os.path.join(UPLOAD_FOLDER, 'job_files')
os.makedirs(TS_PHOTO_DIR, exist_ok=True)
os.makedirs(JOB_FILE_DIR, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ROLE_HIERARCHY = {'worker': 0, 'manager': 1, 'admin': 2}

def require_role(min_role: str):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            u = session.get('user')
            if not u or ROLE_HIERARCHY.get(u['role'], 0) < ROLE_HIERARCHY.get(min_role, 0):
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ---------------- DB
SCHEMA = r"""
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'worker' -- worker|manager|admin
);
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT, email TEXT,
  address TEXT,
  notes TEXT
);
CREATE TABLE IF NOT EXISTS catalog (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  unit TEXT DEFAULT 'ea',
  cost REAL NOT NULL DEFAULT 0,
  kind TEXT DEFAULT 'material' -- material|service|equipment
);
CREATE TABLE IF NOT EXISTS estimates (
  id INTEGER PRIMARY KEY,
  client_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  created_at TEXT NOT NULL,
  margin_pct REAL NOT NULL DEFAULT 15,
  tax_pct REAL NOT NULL DEFAULT 5,
  status TEXT NOT NULL DEFAULT 'draft', -- draft|sent|accepted|rejected
  notes TEXT,
  FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS estimate_items (
  id INTEGER PRIMARY KEY,
  estimate_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  qty REAL NOT NULL DEFAULT 1,
  unit TEXT DEFAULT 'ea',
  unit_cost REAL NOT NULL DEFAULT 0,
  FOREIGN KEY(estimate_id) REFERENCES estimates(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY,
  client_id INTEGER NOT NULL,
  estimate_id INTEGER,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open', -- open|scheduled|in_progress|hold|done|invoiced
  budget_hours REAL DEFAULT 0,
  budget_cost REAL DEFAULT 0,
  start_date TEXT, due_date TEXT,
  notes TEXT,
  FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE,
  FOREIGN KEY(estimate_id) REFERENCES estimates(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS timesheets (
  id INTEGER PRIMARY KEY,
  employee TEXT NOT NULL,
  job_id INTEGER,
  day TEXT NOT NULL,
  hours REAL NOT NULL,
  rate REAL NOT NULL DEFAULT 0,
  notes TEXT,
  photo TEXT,
  approved INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER,
  FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE SET NULL,
  FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS job_files (
  id INTEGER PRIMARY KEY,
  job_id INTEGER NOT NULL,
  filename TEXT NOT NULL,
  original_name TEXT,
  uploaded_by INTEGER,
  FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
  FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE SET NULL
);
"""

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize database tables and seed demo data."""
    with sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        db.row_factory = sqlite3.Row
        for stmt in SCHEMA.split(';'):
            s = stmt.strip()
            if s:
                db.execute(s)
        # add new columns if missing
        cols = [r['name'] for r in db.execute("PRAGMA table_info(timesheets)")]
        if 'photo' not in cols:
            db.execute("ALTER TABLE timesheets ADD COLUMN photo TEXT")

        # bootstrap users
        cur = db.execute("SELECT COUNT(*) c FROM users")
        count = cur.fetchone()['c']
        if count == 0:
            db.execute(
                "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                ("admin", generate_password_hash(ADMIN_PASSWORD), 'admin'),
            )
            db.executemany(
                "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                [
                    ("manager", generate_password_hash("manager"), "manager"),
                    ("alice", generate_password_hash("alice"), "worker"),
                    ("bob", generate_password_hash("bob"), "worker"),
                ],
            )
        elif count == 1:
            db.executemany(
                "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                [
                    ("manager", generate_password_hash("manager"), "manager"),
                    ("alice", generate_password_hash("alice"), "worker"),
                    ("bob", generate_password_hash("bob"), "worker"),
                ],
            )

        # sample clients and jobs
        cur = db.execute("SELECT COUNT(*) c FROM clients")
        if cur.fetchone()['c'] == 0:
            db.execute("INSERT INTO clients(name) VALUES('Acme Corp')")
            db.execute("INSERT INTO clients(name) VALUES('Globex Inc')")
        cur = db.execute("SELECT COUNT(*) c FROM jobs")
        if cur.fetchone()['c'] == 0:
            clients = db.execute("SELECT id FROM clients ORDER BY id").fetchall()
            if clients:
                db.execute(
                    "INSERT INTO jobs(client_id,title,status) VALUES(?,?,?)",
                    (clients[0]['id'], 'Site Prep', 'open'),
                )
            if len(clients) > 1:
                db.execute(
                    "INSERT INTO jobs(client_id,title,status) VALUES(?,?,?)",
                    (clients[1]['id'], 'Concrete Pour', 'open'),
                )

        db.commit()

# initialize database when module is imported
with app.app_context():
    init_db()

# ---------------- Auth
@app.before_request
def auth_guard():
    open_eps = {'login','manifest','swjs','static'}
    if request.endpoint in open_eps:
        return
    if not session.get('user'):
        return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    err = None
    now = time.time()
    locked_until = session.get('lockout_until')
    if locked_until:
        if now < locked_until:
            remaining = int(locked_until - now)
            err = f'Too many failed attempts. Try again in {remaining}s.'
        else:
            session.pop('lockout_until', None)
            session.pop('login_attempts', None)
    if not err and request.method == 'POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','').strip()
        row = get_db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if row and check_password_hash(row['password_hash'], p):
            session['user'] = {'id': row['id'], 'username': row['username'], 'role': row['role']}
            session.pop('login_attempts', None)
            session.pop('lockout_until', None)
            return redirect(url_for('dashboard'))
        err = 'Invalid credentials'
        attempts = session.get('login_attempts', 0) + 1
        session['login_attempts'] = attempts
        app.logger.warning("Failed login attempt for '%s' from %s", u, request.remote_addr)
        if attempts >= 5:
            session['lockout_until'] = now + 30
        else:
            time.sleep(min(attempts, 5))
    return T(BASE, body=T(LOGIN, err=err))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# admin: manage users
@app.route('/users')
@require_role('admin')
def users_list():
    rows = get_db().execute("SELECT id,username,role FROM users ORDER BY id").fetchall()
    return T(BASE, body=T(USERS, rows=rows))

@app.route('/users/create', methods=['POST'])
@require_role('admin')
def users_create():
    f = request.form
    get_db().execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                     (f['username'].strip(), generate_password_hash(f['password']), f.get('role','worker')))
    get_db().commit()
    return redirect(url_for('users_list'))

@app.route('/users/<int:uid>/delete', methods=['POST'])
@require_role('admin')
def users_delete(uid):
    if uid == session['user']['id']:
        abort(400)
    get_db().execute("DELETE FROM users WHERE id=?", (uid,))
    get_db().commit()
    return redirect(url_for('users_list'))

# ---------------- Helpers

def now():
    return dt.datetime.now().strftime('%Y-%m-%d %H:%M')

def today():
    return dt.date.today().isoformat()

# ---------------- Views
@app.route('/')
@app.route('/dashboard')
def dashboard():
    db = get_db()
    kpi_est = db.execute("SELECT COUNT(*) c FROM estimates WHERE status IN ('draft','sent')").fetchone()['c']
    kpi_jobs_open = db.execute("SELECT COUNT(*) c FROM jobs WHERE status NOT IN ('done','invoiced')").fetchone()['c']
    unapproved_hours = db.execute("SELECT COALESCE(SUM(hours),0) s FROM timesheets WHERE approved=0").fetchone()['s'] or 0
    recent = db.execute("""
      SELECT e.id as id, e.title as title, c.name as client, e.status as status, e.created_at as created
      FROM estimates e JOIN clients c ON c.id=e.client_id
      ORDER BY e.id DESC LIMIT 5
    """).fetchall()
    jlist = db.execute("""
      SELECT j.id, j.title, c.name client, j.status
      FROM jobs j JOIN clients c ON c.id=j.client_id
      ORDER BY j.id DESC LIMIT 5
    """).fetchall()
    return T(BASE, body=T(DASH, kpi_est=kpi_est, kpi_jobs_open=kpi_jobs_open,
                          unapproved_hours=unapproved_hours, recent=recent, jlist=jlist))

# ---- Clients
@app.route('/clients')
@require_role('manager')
def clients():
    rows = get_db().execute("SELECT * FROM clients ORDER BY id DESC").fetchall()
    return T(BASE, body=T(CLIENTS, rows=rows))

@app.route('/clients/create', methods=['POST'])
@require_role('manager')
def clients_create():
    f = request.form
    get_db().execute("INSERT INTO clients(name,phone,email,address,notes) VALUES(?,?,?,?,?)",
                     (f['name'], f.get('phone'), f.get('email'), f.get('address'), f.get('notes')))
    get_db().commit()
    return redirect(url_for('clients'))

@app.route('/clients/<int:cid>/delete', methods=['POST'])
@require_role('manager')
def clients_delete(cid):
    get_db().execute("DELETE FROM clients WHERE id=?", (cid,))
    get_db().commit()
    return redirect(url_for('clients'))

# ---- Catalog
@app.route('/catalog')
@require_role('manager')
def catalog():
    rows = get_db().execute("SELECT * FROM catalog ORDER BY id DESC").fetchall()
    return T(BASE, body=T(CATALOG, rows=rows))

@app.route('/catalog/create', methods=['POST'])
@require_role('manager')
def catalog_create():
    f = request.form
    get_db().execute("INSERT INTO catalog(name,unit,cost,kind) VALUES(?,?,?,?)",
                     (f['name'], f.get('unit','ea'), float(f.get('cost',0)), f.get('kind','material')))
    get_db().commit()
    return redirect(url_for('catalog'))

@app.route('/catalog/<int:item_id>/delete', methods=['POST'])
@require_role('manager')
def catalog_delete(item_id):
    get_db().execute("DELETE FROM catalog WHERE id=?", (item_id,))
    get_db().commit()
    return redirect(url_for('catalog'))

# ---- Estimates
@app.route('/estimates')
@require_role('manager')
def estimates():
    rows = get_db().execute("""
        SELECT e.*, c.name client_name,
        (SELECT COALESCE(SUM(qty*unit_cost),0) FROM estimate_items WHERE estimate_id=e.id) AS subtotal
        FROM estimates e JOIN clients c ON c.id=e.client_id
        ORDER BY e.id DESC
    """).fetchall()
    return T(BASE, body=T(ESTIMATES, rows=rows))

@app.route('/estimates/new')
@require_role('manager')
def estimates_new():
    clients = get_db().execute("SELECT id,name FROM clients ORDER BY name").fetchall()
    return T(BASE, body=T(ESTIMATE_NEW, clients=clients, today=today()))

@app.route('/estimates/create', methods=['POST'])
@require_role('manager')
def estimates_create():
    f = request.form
    db = get_db()
    cur = db.execute("INSERT INTO estimates(client_id,title,created_at,margin_pct,tax_pct,status,notes) VALUES(?,?,?,?,?,?,?)",
              (int(f['client_id']), f['title'], now(), float(f.get('margin_pct',15)), float(f.get('tax_pct',5)), f.get('status','draft'), f.get('notes')))
    eid = cur.lastrowid
    db.commit()
    return redirect(url_for('estimate_edit', eid=eid))

@app.route('/estimates/<int:eid>')
@require_role('manager')
def estimate_edit(eid):
    db = get_db()
    est = db.execute("SELECT * FROM estimates WHERE id=?", (eid,)).fetchone()
    if not est: abort(404)
    items = db.execute("SELECT * FROM estimate_items WHERE estimate_id=? ORDER BY id", (eid,)).fetchall()
    clients = db.execute("SELECT id,name FROM clients ORDER BY name").fetchall()
    cat = db.execute("SELECT * FROM catalog ORDER BY name").fetchall()
    subtotal = sum([i['qty']*i['unit_cost'] for i in items])
    margin = subtotal * (est['margin_pct']/100.0)
    taxed = (subtotal + margin) * (est['tax_pct']/100.0)
    total = subtotal + margin + taxed
    return T(BASE, body=T(ESTIMATE_EDIT, est=est, items=items, clients=clients, cat=cat,
                          subtotal=subtotal, margin=margin, taxed=taxed, total=total))

@app.route('/estimates/<int:eid>/update', methods=['POST'])
@require_role('manager')
def estimate_update(eid):
    f = request.form
    get_db().execute(
        "UPDATE estimates SET client_id=?, title=?, margin_pct=?, tax_pct=?, status=?, notes=? WHERE id=?",
        (int(f['client_id']), f['title'], float(f.get('margin_pct',15)), float(f.get('tax_pct',5)), f.get('status','draft'), f.get('notes'), eid))
    get_db().commit()
    return redirect(url_for('estimate_edit', eid=eid))

@app.route('/estimates/<int:eid>/items/add', methods=['POST'])
@require_role('manager')
def estimate_items_add(eid):
    f = request.form
    if 'catalog_id' in f and f['catalog_id']:
        row = get_db().execute("SELECT name,unit,cost FROM catalog WHERE id=?", (int(f['catalog_id']),)).fetchone()
        name, unit, unit_cost = row['name'], row['unit'], row['cost']
    else:
        name = f.get('name','Item')
        unit = f.get('unit','ea')
        unit_cost = float(f.get('unit_cost',0))
    qty = float(f.get('qty',1))
    get_db().execute("INSERT INTO estimate_items(estimate_id,name,qty,unit,unit_cost) VALUES(?,?,?,?,?)",
                     (eid, name, qty, unit, unit_cost))
    get_db().commit()
    return redirect(url_for('estimate_edit', eid=eid))

@app.route('/estimates/<int:eid>/items/<int:iid>/del', methods=['POST'])
@require_role('manager')
def estimate_items_del(eid, iid):
    get_db().execute("DELETE FROM estimate_items WHERE id=? AND estimate_id=?", (iid, eid))
    get_db().commit()
    return redirect(url_for('estimate_edit', eid=eid))

@app.route('/estimates/<int:eid>/print')
@require_role('manager')
def estimate_print(eid):
    db = get_db()
    est = db.execute("SELECT e.*, c.name client_name, c.address, c.email, c.phone FROM estimates e JOIN clients c ON c.id=e.client_id WHERE e.id=?", (eid,)).fetchone()
    if not est: abort(404)
    items = db.execute("SELECT * FROM estimate_items WHERE estimate_id=? ORDER BY id", (eid,)).fetchall()
    subtotal = sum([i['qty']*i['unit_cost'] for i in items])
    margin = subtotal * (est['margin_pct']/100.0)
    taxed = (subtotal + margin) * (est['tax_pct']/100.0)
    total = subtotal + margin + taxed
    return T(PRINT, est=est, items=items, subtotal=subtotal, margin=margin, taxed=taxed, total=total, app_name=APP_NAME)

@app.route('/estimates/<int:eid>/csv')
@require_role('manager')
def estimate_csv(eid):
    db = get_db()
    est = db.execute("SELECT * FROM estimates WHERE id=?", (eid,)).fetchone()
    if not est: abort(404)
    items = db.execute("SELECT * FROM estimate_items WHERE estimate_id=? ORDER BY id", (eid,)).fetchall()
    sio = io.StringIO(); w = csv.writer(sio)
    w.writerow(["Name","Qty","Unit","Unit Cost","Line Total"])
    for it in items:
        w.writerow([it['name'], it['qty'], it['unit'], it['unit_cost'], it['qty']*it['unit_cost']])
    resp = make_response(sio.getvalue())
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = f'attachment; filename=estimate_{eid}.csv'
    return resp

# ---- Jobs
@app.route('/jobs')
@require_role('manager')
def jobs():
    db = get_db()
    rows = db.execute("""
      SELECT j.*, c.name client_name FROM jobs j
      JOIN clients c ON c.id=j.client_id
      ORDER BY j.id DESC
    """).fetchall()
    return T(BASE, body=T(JOBS, rows=rows))

@app.route('/jobs/new')
@require_role('manager')
def jobs_new():
    db = get_db()
    clients = db.execute("SELECT id,name FROM clients ORDER BY name").fetchall()
    estimates = db.execute("SELECT id,title FROM estimates ORDER BY id DESC").fetchall()
    return T(BASE, body=T(JOB_NEW, clients=clients, estimates=estimates, today=today()))

@app.route('/jobs/create', methods=['POST'])
@require_role('manager')
def jobs_create():
    f = request.form
    db = get_db()
    db.execute("INSERT INTO jobs(client_id,estimate_id,title,status,budget_hours,budget_cost,start_date,due_date,notes) VALUES(?,?,?,?,?,?,?,?,?)",
               (int(f['client_id']), int(f.get('estimate_id') or 0) or None, f['title'], f.get('status','open'), float(f.get('budget_hours',0)), float(f.get('budget_cost',0)), f.get('start_date'), f.get('due_date'), f.get('notes')))
    db.commit()
    return redirect(url_for('jobs'))

@app.route('/jobs/<int:jid>')
@require_role('worker')
def job_view(jid):
    db = get_db()
    j = db.execute("SELECT j.*, c.name client_name FROM jobs j JOIN clients c ON c.id=j.client_id WHERE j.id=?", (jid,)).fetchone()
    if not j: abort(404)
    ts = db.execute("SELECT * FROM timesheets WHERE job_id=? ORDER BY day DESC", (jid,)).fetchall()
    actual_hours = sum([row['hours'] for row in ts])
    actual_cost = sum([row['hours']*row['rate'] for row in ts])
    files = db.execute("SELECT * FROM job_files WHERE job_id=? ORDER BY id", (jid,)).fetchall()
    return T(BASE, body=T(JOB_VIEW, j=j, ts=ts, actual_hours=actual_hours, actual_cost=actual_cost, files=files))

# ---- Timesheets
@app.route('/timesheets')
def timesheets():
    db = get_db()
    rows = db.execute("SELECT t.*, j.title job_title FROM timesheets t LEFT JOIN jobs j ON j.id=t.job_id ORDER BY day DESC, id DESC").fetchall()
    jobs = db.execute("SELECT id,title FROM jobs ORDER BY title").fetchall()
    return T(BASE, body=T(TIMESHEETS, rows=rows, jobs=jobs, today=today()))

@app.route('/timesheets/create', methods=['POST'])
def timesheets_create():
    f = request.form
    file = request.files.get('photo')
    photo = None
    if file and file.filename:
        filename = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
        file.save(os.path.join(TS_PHOTO_DIR, filename))
        photo = filename
    rate = float(f.get('rate',0)) if session['user']['role'] in ['manager','admin'] else 0
    get_db().execute("INSERT INTO timesheets(employee,job_id,day,hours,rate,notes,photo,created_by) VALUES(?,?,?,?,?,?,?,?)",
                     (f['employee'], int(f.get('job_id') or 0) or None, f['day'], float(f['hours']), rate, f.get('notes'), photo, session['user']['id']))
    get_db().commit()
    return redirect(url_for('timesheets'))

@app.route('/timesheets/<int:tid>/approve', methods=['POST'])
@require_role('manager')
def timesheets_approve(tid):
    get_db().execute("UPDATE timesheets SET approved=1 WHERE id=?", (tid,))
    get_db().commit()
    return redirect(url_for('timesheets'))

@app.route('/timesheets/<int:tid>/delete', methods=['POST'])
@require_role('manager')
def timesheets_delete(tid):
    get_db().execute("DELETE FROM timesheets WHERE id=?", (tid,))
    get_db().commit()
    return redirect(url_for('timesheets'))

@app.route('/timesheets/csv')
@require_role('manager')
def timesheets_csv():
    db = get_db()
    rows = db.execute("SELECT t.*, j.title job_title FROM timesheets t LEFT JOIN jobs j ON j.id=t.job_id ORDER BY day DESC, id DESC").fetchall()
    sio = io.StringIO(); w = csv.writer(sio)
    w.writerow(["Employee","Job","Date","Hours","Rate","Total","Approved","Notes"])
    for r in rows:
        w.writerow([r['employee'], r['job_title'] or '', r['day'], r['hours'], r['rate'], r['hours']*r['rate'], 'yes' if r['approved'] else 'no', r['notes'] or ''])
    resp = make_response(sio.getvalue())
    resp.headers['Content-Type'] = 'text/csv'
    resp.headers['Content-Disposition'] = 'attachment; filename=timesheets.csv'
    return resp

@app.route('/timesheet_photos/<path:filename>')
@require_role('worker')
def timesheet_photo(filename):
    return send_from_directory(TS_PHOTO_DIR, filename)

@app.route('/job_files/<path:filename>')
@require_role('worker')
def job_file(filename):
    return send_from_directory(JOB_FILE_DIR, filename)

@app.route('/jobs/<int:jid>/files/upload', methods=['POST'])
@require_role('manager')
def job_file_upload(jid):
    file = request.files.get('file')
    if not file or not file.filename:
        abort(400)
    filename = secure_filename(f"{jid}_{uuid.uuid4().hex}_{file.filename}")
    file.save(os.path.join(JOB_FILE_DIR, filename))
    db = get_db()
    db.execute("INSERT INTO job_files(job_id, filename, original_name, uploaded_by) VALUES(?,?,?,?)",
               (jid, filename, file.filename, session['user']['id']))
    db.commit()
    return redirect(url_for('job_view', jid=jid))

# ---------------- PWA
@app.route('/manifest.webmanifest')
def manifest():
    data = {
        "name": APP_NAME,
        "short_name": APP_NAME,
        "start_url": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#0f172a",
        "icons": []
    }
    resp = make_response(json.dumps(data))
    resp.headers['Content-Type'] = 'application/manifest+json'
    return resp

@app.route('/sw.js')
def swjs():
    js = """
const CACHE='lmnop-v1';
const ASSETS=['/'];
self.addEventListener('install',e=>{
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)));
  self.skipWaiting();
});
self.addEventListener('activate',e=>{
  e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))));
  clients.claim();
});
self.addEventListener('fetch',e=>{
  e.respondWith(fetch(e.request).then(r=>{
    const clone=r.clone();
    caches.open(CACHE).then(c=>c.put(e.request,clone));
    return r;
  }).catch(()=>caches.match(e.request).then(r=>r||new Response('offline',{status:503}))));
});
"""
    resp = make_response(js)
    resp.headers['Content-Type'] = 'application/javascript'
    return resp

@app.context_processor
def inject_globals():
    return dict(APP_NAME=APP_NAME, DB_PATH=DB_PATH, session=session, csrf_token=generate_csrf)

# ---------------- UI
BASE = r"""
{% set title = 'Dashboard' %}
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="manifest" href="/manifest.webmanifest"> 
    <meta name="theme-color" content="#0f172a">
      <title>{{ title or APP_NAME }}</title>
    <script src="https://unpkg.com/htmx.org@1.9.12"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js')}</script>
  </head>
# codex/fix-mobile-formatting-and-add-file-uploads
  <body class=\"bg-slate-50 text-slate-900\">
    <nav class=\"bg-white border-b sticky top-0 z-10\">
      <div class=\"max-w-6xl mx-auto px-4 py-3 flex items-center gap-4\">
        <a href=\"{{ url_for('dashboard') }}\" class=\"text-xl font-bold\">{{ APP_NAME }}</a>
        <div class=\"flex gap-4 text-sm flex-wrap\">
          {% if session.get('user') %}
            {% if session['user']['role'] in ['manager','admin'] %}
            <a class=\"hover:underline\" href=\"{{ url_for('clients') }}\">Clients</a>
            <a class=\"hover:underline\" href=\"{{ url_for('catalog') }}\">Catalog</a>
            <a class=\"hover:underline\" href=\"{{ url_for('estimates') }}\">Estimates</a>
            {% endif %}
            <a class=\"hover:underline\" href=\"{{ url_for('jobs') }}\">Jobs</a>
            <a class=\"hover:underline\" href=\"{{ url_for('timesheets') }}\">Timesheets</a>
          {% endif %}
        </div>
        <div class="ml-auto flex gap-4 items-center">
          {% if session.get('user') %}
            <span class="text-sm text-slate-500">{{ session['user']['username'] }} ({{ session['user']['role'] }})</span>
            {% if session['user']['role']=='admin' %}
              <a class="text-sm hover:underline" href="{{ url_for('users_list') }}">Users</a>
            {% endif %}
            <a class="text-sm text-slate-500 hover:underline" href="{{ url_for('logout') }}">Logout</a>
          {% endif %}
        </div>
      </div>
    </nav>
    <main class="max-w-6xl mx-auto p-4">
      {{ body|safe }}
    </main>
      <footer class="max-w-6xl mx-auto p-4 text-xs text-slate-500">{{ APP_NAME }} • SQLite: {{ DB_PATH }}</footer>
  </body>
</html>
"""

LOGIN = r"""
<div class="max-w-sm mx-auto mt-24 bg-white p-6 rounded-2xl shadow">
  <h1 class="text-xl font-semibold mb-4">Sign in</h1>
  {% if err %}<div class="text-red-600 text-sm mb-3">{{ err }}</div>{% endif %}
  <form method="post" class="space-y-3">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input name="username" class="w-full border rounded-xl p-2" placeholder="username" value="admin"> 
    <input type="password" name="password" class="w-full border rounded-xl p-2" placeholder="password"> 
    <button class="w-full bg-slate-900 text-white rounded-xl py-2">Continue</button>
  </form>
  <p class="text-xs text-slate-500 mt-3">First run bootstrap: user "admin" uses ADMIN_PASSWORD env var.</p>
</div>
"""

USERS = r"""
<div class="flex items-center mb-3"><h1 class="text-2xl font-semibold">Users</h1></div>
<div class="bg-white rounded-2xl p-4 shadow mb-4">
  <form method="post" action="{{ url_for('users_create') }}" class="grid md:grid-cols-4 gap-2">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input class="border rounded-xl p-2" name="username" placeholder="Username" required>
    <input class="border rounded-xl p-2" name="password" placeholder="Password" required>
    <select name="role" class="border rounded-xl p-2"><option>worker</option><option>manager</option><option>admin</option></select>
    <button class="bg-slate-900 text-white rounded-xl px-4">Add</button>
  </form>
</div>
<div class="bg-white rounded-2xl p-4 shadow">
  <table class="w-full text-sm">
    <thead><tr class="text-left text-slate-500"><th>#</th><th>User</th><th>Role</th><th></th></tr></thead>
    <tbody>
      {% for r in rows %}
      <tr class="border-t"><td class="py-2">{{ r['id'] }}</td><td>{{ r['username'] }}</td><td>{{ r['role'] }}</td>
        <td class="text-right"><form method="post" action="{{ url_for('users_delete', uid=r['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="text-red-600 text-sm">Delete</button></form></td></tr>
      {% else %}<tr><td colspan="4" class="py-3 text-slate-500">No users.</td></tr>{% endfor %}
    </tbody>
  </table>
</div>
"""

# The rest of the templates are identical to v1
DASH = r"""
<h1 class="text-2xl font-semibold mb-4">Dashboard</h1>
<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
  <div class="bg-white rounded-2xl p-4 shadow"><div class="text-sm text-slate-500">Open Estimates</div><div class="text-3xl font-bold">{{ kpi_est }}</div></div>
  <div class="bg-white rounded-2xl p-4 shadow"><div class="text-sm text-slate-500">Active Jobs</div><div class="text-3xl font-bold">{{ kpi_jobs_open }}</div></div>
  <div class="bg-white rounded-2xl p-4 shadow"><div class="text-sm text-slate-500">Unapproved Hours</div><div class="text-3xl font-bold">{{ '%.2f' % unapproved_hours }}</div></div>
</div>
<div class="grid md:grid-cols-2 gap-4 mt-6">
  <div class="bg-white rounded-2xl p-4 shadow">
    <div class="flex items-center mb-2"><h2 class="font-semibold">Recent Estimates</h2>
      <a class="ml-auto text-sm text-slate-500 hover:underline" href="{{ url_for('estimates') }}">View all</a></div>
    <ul class="divide-y">
      {% for r in recent %}
      <li class="py-2 flex gap-2">
        <div class="font-medium">#{{ r['id'] }} {{ r['title'] }}</div>
        <div class="text-slate-500">{{ r['client'] }}</div>
        <span class="ml-auto text-xs rounded-full px-2 py-1 bg-slate-100">{{ r['status'] }}</span>
      </li>
      {% else %}<li class="py-2 text-slate-500">No estimates yet.</li>{% endfor %}
    </ul>
  </div>
  <div class="bg-white rounded-2xl p-4 shadow">
    <div class="flex items-center mb-2"><h2 class="font-semibold">Recent Jobs</h2>
      <a class="ml-auto text-sm text-slate-500 hover:underline" href="{{ url_for('jobs') }}">View all</a></div>
    <ul class="divide-y">
      {% for j in jlist %}
      <li class="py-2 flex gap-2 items-center">
        <div class="font-medium">#{{ j['id'] }} {{ j['title'] }}</div>
        <div class="text-slate-500">{{ j['client'] }}</div>
        <span class="ml-auto text-xs rounded-full px-2 py-1 bg-slate-100">{{ j['status'] }}</span>
      </li>
      {% else %}<li class="py-2 text-slate-500">No jobs yet.</li>{% endfor %}
    </ul>
  </div>
</div>
"""

CLIENTS = r"""
<div class="flex items-center mb-3">
  <h1 class="text-2xl font-semibold">Clients</h1>
</div>
<div class="bg-white rounded-2xl p-4 shadow mb-4">
  <form method="post" action="{{ url_for('clients_create') }}" class="grid md:grid-cols-5 gap-2">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input class="border rounded-xl p-2" name="name" placeholder="Name" required>
    <input class="border rounded-xl p-2" name="phone" placeholder="Phone">
    <input class="border rounded-xl p-2" name="email" placeholder="Email">
    <input class="border rounded-xl p-2" name="address" placeholder="Address">
    <input class="border rounded-xl p-2 md:col-span-4" name="notes" placeholder="Notes">
    <button class="bg-slate-900 text-white rounded-xl px-4">Add</button>
  </form>
</div>
<div class="bg-white rounded-2xl p-4 shadow">
  <table class="w-full text-sm">
    <thead><tr class="text-left text-slate-500"><th>Name</th><th>Phone</th><th>Email</th><th>Address</th><th>Notes</th><th></th></tr></thead>
    <tbody>
      {% for r in rows %}
      <tr class="border-t"><td class="py-2">{{ r['name'] }}</td><td>{{ r['phone'] or '' }}</td><td>{{ r['email'] or '' }}</td><td>{{ r['address'] or '' }}</td><td>{{ r['notes'] or '' }}</td>
        <td class="text-right"><form method="post" action="{{ url_for('clients_delete', cid=r['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="text-red-600 text-sm">Delete</button></form></td></tr>
      {% else %}<tr><td colspan="6" class="py-3 text-slate-500">No clients.</td></tr>{% endfor %}
    </tbody>
  </table>
</div>
"""

CATALOG = r"""
<div class="flex items-center mb-3"><h1 class="text-2xl font-semibold">Catalog</h1></div>
<div class="bg-white rounded-2xl p-4 shadow mb-4">
  <form method="post" action="{{ url_for('catalog_create') }}" class="grid md:grid-cols-5 gap-2">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input class="border rounded-xl p-2" name="name" placeholder="Name" required>
    <input class="border rounded-xl p-2" name="unit" placeholder="Unit" value="ea">
    <input class="border rounded-xl p-2" name="cost" placeholder="Cost" type="number" step="0.01" value="0">
    <select class="border rounded-xl p-2" name="kind"><option>material</option><option>service</option><option>equipment</option></select>
    <button class="bg-slate-900 text-white rounded-xl px-4">Add</button>
  </form>
</div>
<div class="bg-white rounded-2xl p-4 shadow">
  <table class="w-full text-sm">
    <thead><tr class="text-left text-slate-500"><th>Name</th><th>Unit</th><th>Cost</th><th>Kind</th><th></th></tr></thead>
    <tbody>
      {% for r in rows %}
      <tr class="border-t"><td class="py-2">{{ r['name'] }}</td><td>{{ r['unit'] }}</td><td>${{ '%.2f' % r['cost'] }}</td><td>{{ r['kind'] }}</td>
        <td class="text-right"><form method="post" action="{{ url_for('catalog_delete', item_id=r['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="text-red-600 text-sm">Delete</button></form></td></tr>
      {% else %}<tr><td colspan="5" class="py-3 text-slate-500">No items.</td></tr>{% endfor %}
    </tbody>
  </table>
</div>
"""

ESTIMATES = r"""
<div class="flex items-center mb-3"><h1 class="text-2xl font-semibold">Estimates</h1>
  <a href="{{ url_for('estimates_new') }}" class="ml-auto bg-slate-900 text-white rounded-xl px-4 py-2 text-sm">New Estimate</a>
</div>
<div class="bg-white rounded-2xl p-4 shadow">
  <table class="w-full text-sm">
    <thead><tr class="text-left text-slate-500"><th>#</th><th>Title</th><th>Client</th><th>Status</th><th>Total</th><th></th></tr></thead>
    <tbody>
    {% for r in rows %}
      {% set total = (r['subtotal'] + (r['subtotal'] * r['margin_pct']/100.0)) * (1 + r['tax_pct']/100.0) %}
      <tr class="border-t">
        <td class="py-2">{{ r['id'] }}</td>
        <td><a class="hover:underline" href="{{ url_for('estimate_edit', eid=r['id']) }}">{{ r['title'] }}</a></td>
        <td>{{ r['client_name'] }}</td>
        <td>{{ r['status'] }}</td>
        <td>${{ '%.2f' % total }}</td>
        <td><a href="{{ url_for('estimate_print', eid=r['id']) }}" class="text-sm text-slate-500 hover:underline">Print</a></td>
      </tr>
    {% else %}<tr><td colspan="6" class="py-3 text-slate-500">No estimates.</td></tr>{% endfor %}
    </tbody>
  </table>
</div>
"""

ESTIMATE_NEW = r"""
<h1 class="text-2xl font-semibold mb-3">New Estimate</h1>
<form method="post" action="{{ url_for('estimates_create') }}" class="grid md:grid-cols-2 gap-3 bg-white p-4 rounded-2xl shadow">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <div>
    <label class="text-sm text-slate-500">Client</label>
    <select name="client_id" class="w-full border rounded-xl p-2" required>
      {% for c in clients %}<option value="{{ c['id'] }}">{{ c['name'] }}</option>{% endfor %}
    </select>
  </div>
  <div>
    <label class="text-sm text-slate-500">Title</label>
    <input name="title" class="w-full border rounded-xl p-2" placeholder="Driveway prep & gravel" required>
  </div>
  <div>
    <label class="text-sm text-slate-500">Margin %</label>
    <input name="margin_pct" type="number" step="0.1" value="15" class="w-full border rounded-xl p-2">
  </div>
  <div>
    <label class="text-sm text-slate-500">Tax %</label>
    <input name="tax_pct" type="number" step="0.1" value="5" class="w-full border rounded-xl p-2">
  </div>
  <div class="md:col-span-2">
    <label class="text-sm text-slate-500">Notes</label>
    <textarea name="notes" class="w-full border rounded-xl p-2" rows="3"></textarea>
  </div>
  <button class="bg-slate-900 text-white rounded-xl px-4 py-2">Create</button>
</form>
"""

ESTIMATE_EDIT = r"""
<div class="flex items-center mb-3">
  <h1 class="text-2xl font-semibold">Estimate #{{ est['id'] }}</h1>
  <a href="{{ url_for('estimate_print', eid=est['id']) }}" class="ml-auto text-sm bg-white border rounded-xl px-3 py-1 shadow">Print</a>
  <a href="{{ url_for('estimate_csv', eid=est['id']) }}" class="ml-2 text-sm bg-white border rounded-xl px-3 py-1 shadow">CSV</a>
</div>
<form method="post" action="{{ url_for('estimate_update', eid=est['id']) }}" class="grid md:grid-cols-3 gap-3 bg-white p-4 rounded-2xl shadow mb-4">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <div>
    <label class="text-sm text-slate-500">Client</label>
    <select name="client_id" class="w-full border rounded-xl p-2">
      {% for c in clients %}<option value="{{ c['id'] }}" {% if c['id']==est['client_id'] %}selected{% endif %}>{{ c['name'] }}</option>{% endfor %}
    </select>
  </div>
  <div>
    <label class="text-sm text-slate-500">Title</label>
    <input name="title" class="w-full border rounded-xl p-2" value="{{ est['title'] }}"> 
  </div>
  <div>
    <label class="text-sm text-slate-500">Status</label>
    <select name="status" class="w-full border rounded-xl p-2">
      {% for s in ['draft','sent','accepted','rejected'] %}<option {% if s==est['status'] %}selected{% endif %}>{{ s }}</option>{% endfor %}
    </select>
  </div>
  <div>
    <label class="text-sm text-slate-500">Margin %</label>
    <input name="margin_pct" type="number" step="0.1" value="{{ est['margin_pct'] }}" class="w-full border rounded-xl p-2">
  </div>
  <div>
    <label class="text-sm text-slate-500">Tax %</label>
    <input name="tax_pct" type="number" step="0.1" value="{{ est['tax_pct'] }}" class="w-full border rounded-xl p-2">
  </div>
  <div class="md:col-span-3">
    <label class="text-sm text-slate-500">Notes</label>
    <textarea name="notes" class="w-full border rounded-xl p-2" rows="3">{{ est['notes'] or '' }}</textarea>
  </div>
  <button class="bg-slate-900 text-white rounded-xl px-4 py-2">Save</button>
</form>
<div class="bg-white rounded-2xl p-4 shadow mb-4">
  <h2 class="font-semibold mb-2">Line Items</h2>
  <form method="post" action="{{ url_for('estimate_items_add', eid=est['id']) }}" class="grid md:grid-cols-6 gap-2 mb-3">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <select name="catalog_id" class="border rounded-xl p-2">
      <option value="">Custom…</option>
      {% for c in cat %}<option value="{{ c['id'] }}">{{ c['name'] }} (${{ '%.2f' % c['cost'] }})</option>{% endfor %}
    </select>
    <input name="name" class="border rounded-xl p-2" placeholder="Item name"> 
    <input name="qty" type="number" step="0.01" value="1" class="border rounded-xl p-2"> 
    <input name="unit" class="border rounded-xl p-2" value="ea"> 
    <input name="unit_cost" type="number" step="0.01" class="border rounded-xl p-2" placeholder="0.00"> 
    <button class="bg-slate-900 text-white rounded-xl px-4">Add</button>
  </form>
  <table class="w-full text-sm">
    <thead><tr class="text-left text-slate-500"><th>Name</th><th>Qty</th><th>Unit</th><th>Unit Cost</th><th>Total</th><th></th></tr></thead>
    <tbody>
      {% for i in items %}
      <tr class="border-t"><td class="py-2">{{ i['name'] }}</td><td>{{ i['qty'] }}</td><td>{{ i['unit'] }}</td><td>${{ '%.2f' % i['unit_cost'] }}</td><td>${{ '%.2f' % (i['qty']*i['unit_cost']) }}</td>
        <td class="text-right"><form method="post" action="{{ url_for('estimate_items_del', eid=est['id'], iid=i['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="text-red-600 text-sm">Delete</button></form></td></tr>
      {% else %}<tr><td colspan="6" class="py-3 text-slate-500">No items.</td></tr>{% endfor %}
    </tbody>
  </table>
</div>
<div class="grid md:grid-cols-4 gap-4">
  <div class="bg-white rounded-2xl p-4 shadow md:col-start-4">
    <div class="text-sm text-slate-500">Subtotal</div>
    <div class="text-xl font-semibold">${{ '%.2f' % subtotal }}</div>
    <div class="text-sm text-slate-500 mt-2">Margin ({{ est['margin_pct'] }}%)</div>
    <div>${{ '%.2f' % margin }}</div>
    <div class="text-sm text-slate-500 mt-2">Tax ({{ est['tax_pct'] }}%)</div>
    <div>${{ '%.2f' % taxed }}</div>
    <div class="mt-3 text-sm text-slate-500">Total</div>
    <div class="text-2xl font-bold">${{ '%.2f' % total }}</div>
  </div>
</div>
"""

PRINT = r"""
<!doctype html><html><head><meta charset="utf-8"><title>Estimate #{{ est['id'] }}</title>
  <style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu; margin:40px;} table{border-collapse:collapse;width:100%} td,th{border-top:1px solid #ddd;padding:8px;text-align:left}</style>
</head><body>
<h1>Estimate #{{ est['id'] }} — {{ est['title'] }}</h1>
<p><strong>Client:</strong> {{ est['client_name'] }}<br>
<strong>Address:</strong> {{ est['address'] or '' }}<br>
<strong>Email:</strong> {{ est['email'] or '' }} | <strong>Phone:</strong> {{ est['phone'] or '' }}</p>
<table><thead><tr><th>Item</th><th>Qty</th><th>Unit</th><th>Unit Cost</th><th>Total</th></tr></thead>
<tbody>
{% for i in items %}<tr><td>{{ i['name'] }}</td><td>{{ i['qty'] }}</td><td>{{ i['unit'] }}</td><td>${{ '%.2f' % i['unit_cost'] }}</td><td>${{ '%.2f' % (i['qty']*i['unit_cost']) }}</td></tr>{% endfor %}
</tbody></table>
<p>Subtotal: ${{ '%.2f' % subtotal }}<br>
Margin ({{ est['margin_pct'] }}%): ${{ '%.2f' % margin }}<br>
Tax ({{ est['tax_pct'] }}%): ${{ '%.2f' % taxed }}<br>
<strong>Total: ${{ '%.2f' % total }}</strong></p>
<p style="color:#666">Generated by {{ app_name }}</p>
</body></html>
"""

JOBS = r"""
# codex/fix-mobile-formatting-and-add-file-uploads
<div class=\"flex items-center mb-3\"><h1 class=\"text-2xl font-semibold\">Jobs</h1>
  {% if session['user']['role'] in ['manager','admin'] %}
  <a href=\"{{ url_for('jobs_new') }}\" class=\"ml-auto bg-slate-900 text-white rounded-xl px-4 py-2 text-sm\">New Job</a>
  {% endif %}
</div>
<div class=\"bg-white rounded-2xl p-4 shadow overflow-x-auto\">
  <table class=\"w-full text-sm\">
    <thead><tr class=\"text-left text-slate-500\"><th>#</th><th>Title</th><th>Client</th><th>Status</th>{% if session['user']['role'] in ['manager','admin'] %}<th>Budget Hrs</th><th>Budget $</th>{% endif %}<th></th></tr></thead>
    <tbody>
      {% for r in rows %}
        <tr class="border-t"><td class="py-2">{{ r['id'] }}</td>
        <td><a href="{{ url_for('job_view', jid=r['id']) }}" class="hover:underline">{{ r['title'] }}</a></td>
        <td>{{ r['client_name'] }}</td>
        <td>{{ r['status'] }}</td>
        {% if session['user']['role'] in ['manager','admin'] %}
        <td>{{ r['budget_hours'] }}</td>
        <td>${{ '%.2f' % (r['budget_cost'] or 0) }}</td>
        {% endif %}
        <td></td></tr>
# codex/fix-mobile-formatting-and-add-file-uploads
      {% else %}<tr><td colspan=\"{{ 7 if session['user']['role'] in ['manager','admin'] else 5 }}\" class=\"py-3 text-slate-500\">No jobs.</td></tr>{% endfor %}
    </tbody>
  </table>
</div>
"""

JOB_NEW = r"""
<h1 class="text-2xl font-semibold mb-3">New Job</h1>
<form method="post" action="{{ url_for('jobs_create') }}" class="grid md:grid-cols-3 gap-3 bg-white p-4 rounded-2xl shadow">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <div>
    <label class="text-sm text-slate-500">Client</label>
    <select name="client_id" class="w-full border rounded-xl p-2" required>
      {% for c in clients %}<option value="{{ c['id'] }}">{{ c['name'] }}</option>{% endfor %}
    </select>
  </div>
  <div>
    <label class="text-sm text-slate-500">Estimate (optional)</label>
    <select name="estimate_id" class="w-full border rounded-xl p-2">
      <option value="">—</option>
      {% for e in estimates %}<option value="{{ e['id'] }}">#{{ e['id'] }} {{ e['title'] }}</option>{% endfor %}
    </select>
  </div>
  <div>
    <label class="text-sm text-slate-500">Title</label>
    <input name="title" class="w-full border rounded-xl p-2" placeholder="Site prep & trucking" required>
  </div>
  <div>
    <label class="text-sm text-slate-500">Status</label>
    <select name="status" class="w-full border rounded-xl p-2"><option>open</option><option>scheduled</option><option>in_progress</option><option>hold</option><option>done</option><option>invoiced</option></select>
  </div>
  <div><label class="text-sm text-slate-500">Budget Hours</label><input type="number" step="0.1" name="budget_hours" class="w-full border rounded-xl p-2" value="0"></div>
  <div><label class="text-sm text-slate-500">Budget $</label><input type="number" step="0.01" name="budget_cost" class="w-full border rounded-xl p-2" value="0"></div>
  <div><label class="text-sm text-slate-500">Start</label><input type="date" name="start_date" class="w-full border rounded-xl p-2" value="{{ today }}"></div>
  <div><label class="text-sm text-slate-500">Due</label><input type="date" name="due_date" class="w-full border rounded-xl p-2"></div>
  <div class="md:col-span-3"><label class="text-sm text-slate-500">Notes</label><textarea name="notes" class="w-full border rounded-xl p-2" rows="3"></textarea></div>
  <button class="bg-slate-900 text-white rounded-xl px-4 py-2">Create</button>
</form>
"""

JOB_VIEW = r"""
# codex/fix-mobile-formatting-and-add-file-uploads
<div class=\"flex items-center mb-3\"><h1 class=\"text-2xl font-semibold\">Job #{{ j['id'] }} — {{ j['title'] }}</h1></div>
{% if session['user']['role'] in ['manager','admin'] %}
<div class=\"grid md:grid-cols-3 gap-4\">
  <div class=\"md:col-span-2 bg-white rounded-2xl p-4 shadow overflow-x-auto\">
    <h2 class=\"font-semibold mb-2\">Timesheets</h2>
    <table class=\"w-full text-sm\">
      <thead><tr class=\"text-left text-slate-500\"><th>Employee</th><th>Date</th><th>Hours</th><th>Rate</th><th>$</th><th>Photo</th><th>Approved</th><th></th></tr></thead>
      <tbody>
        {% for t in ts %}
        <tr class=\"border-t\"><td class=\"py-2\">{{ t['employee'] }}</td><td>{{ t['day'] }}</td><td>{{ t['hours'] }}</td><td>${{ '%.2f' % t['rate'] }}</td><td>${{ '%.2f' % (t['hours']*t['rate']) }}</td><td>{% if t['photo'] %}<a class=\"text-blue-600 hover:underline\" href=\"{{ url_for('timesheet_photo', filename=t['photo']) }}\" target=\"_blank\">View</a>{% else %}—{% endif %}</td><td>{{ 'yes' if t['approved'] else 'no' }}</td>
          <td class=\"text-right\"><form method=\"post\" action=\"{{ url_for('timesheets_delete', tid=t['id']) }}\"><input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\"><button class=\"text-red-600 text-sm\">Delete</button></form></td>
        </tr>
        {% else %}<tr><td colspan=\"8\" class=\"py-3 text-slate-500\">No entries yet.</td></tr>{% endfor %}
      </tbody>
    </table>
  </div>
  <div class="bg-white rounded-2xl p-4 shadow">
    <h2 class="font-semibold mb-2">Summary</h2>
    <div class="text-sm text-slate-500">Client</div>
    <div class="mb-2">{{ j['client_name'] }}</div>
    <div class="grid grid-cols-2 gap-2 text-sm">
      <div>Budget Hrs</div><div class="text-right">{{ j['budget_hours'] }}</div>
      <div>Actual Hrs</div><div class="text-right">{{ '%.2f' % actual_hours }}</div>
      <div>Budget $</div><div class="text-right">${{ '%.2f' % (j['budget_cost'] or 0) }}</div>
      <div>Actual $</div><div class="text-right">${{ '%.2f' % actual_cost }}</div>
    </div>
  </div>
</div>
{% endif %}
<div class=\"bg-white rounded-2xl p-4 shadow mt-4\">
  <h2 class=\"font-semibold mb-2\">Documents</h2>
  <ul class=\"text-sm\">
    {% for f in files %}
      <li><a class=\"text-blue-600 hover:underline\" href=\"{{ url_for('job_file', filename=f['filename']) }}\" target=\"_blank\">{{ f['original_name'] }}</a></li>
    {% else %}
      <li class=\"text-slate-500\">No documents.</li>
    {% endfor %}
  </ul>
  {% if session['user']['role'] in ['manager','admin'] %}
  <form class=\"mt-2\" method=\"post\" action=\"{{ url_for('job_file_upload', jid=j['id']) }}\" enctype=\"multipart/form-data\">
    <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\">
    <input type=\"file\" name=\"file\" class=\"text-sm\" required>
    <button class=\"bg-slate-900 text-white rounded-xl px-3 py-1 text-sm\">Upload</button>
  </form>
  {% endif %}
</div>
"""

TIMESHEETS = r"""
# codex/fix-mobile-formatting-and-add-file-uploads
<div class=\"flex items-center mb-3\"><h1 class=\"text-2xl font-semibold\">Timesheets</h1></div>
<div class=\"bg-white rounded-2xl p-4 shadow mb-4\">
  <form method=\"post\" action=\"{{ url_for('timesheets_create') }}\" class=\"grid md:grid-cols-6 gap-2\" enctype=\"multipart/form-data\">
    <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\">
    <input class=\"border rounded-xl p-2\" name=\"employee\" placeholder=\"Employee\" required>
    <select class=\"border rounded-xl p-2\" name=\"job_id\">
      <option value=\"\">No job</option>
      {% for j in jobs %}<option value=\"{{ j['id'] }}\">{{ j['title'] }}</option>{% endfor %}
    </select>
    <input class=\"border rounded-xl p-2\" type=\"date\" name=\"day\" value=\"{{ today }}\">
    <input class=\"border rounded-xl p-2\" type=\"number\" step=\"0.1\" name=\"hours\" placeholder=\"8\">
    {% if session['user']['role'] in ['manager','admin'] %}
    <input class=\"border rounded-xl p-2\" type=\"number\" step=\"0.01\" name=\"rate\" placeholder=\"35\">
    {% endif %}
    <input class=\"border rounded-xl p-2 md:col-span-5\" name=\"notes\" placeholder=\"Notes\">
    <input type=\"file\" name=\"photo\" accept=\"image/*\" class=\"md:col-span-5 text-sm\">
    <button class=\"bg-slate-900 text-white rounded-xl px-4\">Add</button>
  </form>
</div>
<div class=\"bg-white rounded-2xl p-4 shadow overflow-x-auto\">
  <table class=\"w-full text-sm\">
    <thead><tr class=\"text-left text-slate-500\"><th>Employee</th><th>Job</th><th>Date</th><th>Hours</th>{% if session['user']['role'] in ['manager','admin'] %}<th>Rate</th><th>$</th>{% endif %}<th>Photo</th><th>Approved</th><th></th></tr></thead>
    <tbody>
      {% for r in rows %}
      <tr class=\"border-t\"><td class=\"py-2\">{{ r['employee'] }}</td><td>{% if r['job_id'] %}<a href=\"{{ url_for('job_view', jid=r['job_id']) }}\" class=\"hover:underline\">{{ r['job_title'] }}</a>{% endif %}</td><td>{{ r['day'] }}</td><td>{{ r['hours'] }}</td>{% if session['user']['role'] in ['manager','admin'] %}<td>${{ '%.2f' % r['rate'] }}</td><td>${{ '%.2f' % (r['hours']*r['rate']) }}</td>{% endif %}<td>{% if r['photo'] %}<a class=\"text-blue-600 hover:underline\" href=\"{{ url_for('timesheet_photo', filename=r['photo']) }}\" target=\"_blank\">View</a>{% else %}—{% endif %}</td><td>{{ 'yes' if r['approved'] else 'no' }}</td>
        <td class=\"text-right flex gap-2 justify-end\">
          {% if session['user']['role'] in ['manager','admin'] and not r['approved'] %}
            <form method="post" action="{{ url_for('timesheets_approve', tid=r['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="text-green-600 text-sm">Approve</button></form>
          {% endif %}
          {% if session['user']['role'] in ['manager','admin'] %}
            <form method="post" action="{{ url_for('timesheets_delete', tid=r['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="text-red-600 text-sm">Delete</button></form>
          {% endif %}
        </td>
      </tr>
# codex/fix-mobile-formatting-and-add-file-uploads
      {% else %}<tr><td colspan=\"{{ 9 if session['user']['role'] in ['manager','admin'] else 7 }}\" class=\"py-3 text-slate-500\">No entries.</td></tr>{% endfor %}

    </tbody>
  </table>
  <div class="mt-3">
    {% if session['user']['role'] in ['manager','admin'] %}
    <a class="text-sm text-slate-500 hover:underline" href="{{ url_for('timesheets_csv') }}">Export CSV</a>
    {% endif %}
  </div>
</div>
"""

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
