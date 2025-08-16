
import datetime as dt
import json
import sqlite3
import uuid

from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf
APP_NAME = "LMNOP"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin")  # bootstrap first admin
if not SECRET:

app.secret_key = SECRET
csrf = CSRFProtect(app)
# file uploads
TS_PHOTO_DIR = os.path.join(UPLOAD_FOLDER, 'timesheet_photos')
os.makedirs(TS_PHOTO_DIR, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ROLE_HIERARCHY = {'worker': 0, 'manager': 1, 'admin': 2}
def require_role(min_role: str):
        @wraps(f)
            u = session.get('user')
                abort(403)
        return wrapped

SCHEMA = r"""
CREATE TABLE IF NOT EXISTS users (
  username TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL DEFAULT 'worker', -- worker|manager|admin
);
  id INTEGER PRIMARY KEY,
  phone TEXT, email TEXT,
  notes TEXT
CREATE TABLE IF NOT EXISTS catalog (
  name TEXT NOT NULL,
  cost REAL NOT NULL DEFAULT 0,
);
  id INTEGER PRIMARY KEY,
  title TEXT NOT NULL,
  margin_pct REAL NOT NULL DEFAULT 15,
  status TEXT NOT NULL DEFAULT 'draft', -- draft|sent|accepted|rejected
  FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE

  id INTEGER PRIMARY KEY,
  filename TEXT NOT NULL,
  uploaded_by INTEGER,
  FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE SET NULL
"""
def get_db():
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    return g.db
@app.teardown_appcontext
    db = g.pop('db', None)
        db.close()
def init_db():
    with sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES) as db:
        for stmt in SCHEMA.split(';'):
            if s:
        # add new columns if missing
        if 'photo' not in cols:
        ucols = [r['name'] for r in db.execute("PRAGMA table_info(users)")]
            db.execute("ALTER TABLE users ADD COLUMN default_rate REAL NOT NULL DEFAULT 0")
        # bootstrap users
        count = cur.fetchone()['c']
            db.execute(
                ("admin", generate_password_hash(ADMIN_PASSWORD), 'admin', 0),
            db.executemany(
                [
                    ("alice", generate_password_hash("alice"), "worker", 25),
                ],
        elif count == 1:
                "INSERT INTO users(username,password_hash,role,default_rate) VALUES(?,?,?,?)",
                    ("manager", generate_password_hash("manager"), "manager", 40),
                    ("bob", generate_password_hash("bob"), "worker", 30),
            )
        # sample clients and jobs
        if cur.fetchone()['c'] == 0:
            db.execute("INSERT INTO clients(name) VALUES('Globex Inc')")
        if cur.fetchone()['c'] == 0:
            if clients:
                    "INSERT INTO jobs(client_id,title,status) VALUES(?,?,?)",
                )
                db.execute(
                    (clients[1]['id'], 'Concrete Pour', 'open'),


with app.app_context():

@app.before_request
    open_eps = {'login','manifest','swjs','static'}
        return
        return redirect(url_for('login'))
@app.route('/login', methods=['GET','POST'])
    err = None
    locked_until = session.get('lockout_until')
        if now < locked_until:
            err = f'Too many failed attempts. Try again in {remaining}s.'
            session.pop('lockout_until', None)
    if not err and request.method == 'POST':
        p = request.form.get('password','').strip()
        if row and check_password_hash(row['password_hash'], p):
            session.pop('login_attempts', None)
            return redirect(url_for('dashboard'))
        attempts = session.get('login_attempts', 0) + 1
        app.logger.warning("Failed login attempt for '%s' from %s", u, request.remote_addr)
            session['lockout_until'] = now + 30
            time.sleep(min(attempts, 5))

def logout():
    return redirect(url_for('login'))
# admin: manage users
@require_role('admin')
    rows = get_db().execute("SELECT id,username,role FROM users ORDER BY id").fetchall()

@require_role('admin')
    f = request.form
                     (f['username'].strip(), generate_password_hash(f['password']), f.get('role','worker')))
    return redirect(url_for('users_list'))
@app.route('/users/<int:uid>/delete', methods=['POST'])
@@ -451,119 +487,156 @@ def jobs_new():
def jobs_create():
    db = get_db()
               (int(f['client_id']), int(f.get('estimate_id') or 0) or None, f['title'], f.get('status','open'), float(f.get('budget_hours',0)), float(f.get('budget_cost',0)), f.get('start_date'), f.get('due_date'), f.get('notes')))
    return redirect(url_for('jobs'))
@app.route('/jobs/<int:jid>')
def job_view(jid):
    j = db.execute("SELECT j.*, c.name client_name FROM jobs j JOIN clients c ON c.id=j.client_id WHERE j.id=?", (jid,)).fetchone()
    ts = db.execute("SELECT * FROM timesheets WHERE job_id=? ORDER BY day DESC", (jid,)).fetchall()
    actual_cost = sum([row['hours']*row['rate'] for row in ts])
    return T(BASE, body=T(JOB_VIEW, j=j, ts=ts, actual_hours=actual_hours, actual_cost=actual_cost, files=files))
# ---- Timesheets
def timesheets():
    show_all = request.args.get('all') == '1' and session['user']['role'] in ['manager','admin']
        rows = db.execute("SELECT t.*, j.title job_title FROM timesheets t LEFT JOIN jobs j ON j.id=t.job_id ORDER BY day DESC, id DESC").fetchall()
        rows = db.execute(
            (session['user']['username'],)
    jobs = db.execute("SELECT id,title FROM jobs WHERE status IN ('open','in_progress') ORDER BY title").fetchall()
    return T(BASE, body=T(TIMESHEETS, rows=rows, jobs=jobs, users=users, today=today(), show_all=show_all))
@app.route('/timesheets/create', methods=['POST'])
    f = request.form
    file = request.files.get('photo')
    try:
        user_row = db.execute("SELECT username, default_rate FROM users WHERE id=?", (uid,)).fetchone()
            abort(400)
            filename = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
            photo = filename
        if session['user']['role'] in ['manager','admin']:
            rate = float(rate or 0)
            "INSERT INTO timesheets(employee,job_id,day,hours,rate,notes,photo,created_by) VALUES(?,?,?,?,?,?,?,?)",
                user_row['username'],
                f['day'],
                rate,
                photo,
            ),
        db.commit()
        app.logger.error("Failed to create timesheet: %s", e)
    return redirect(url_for('timesheets'))
@app.route('/timesheets/<int:tid>/approve', methods=['POST'])
def timesheets_approve(tid):
    get_db().commit()

@require_role('manager')
    get_db().execute("DELETE FROM timesheets WHERE id=?", (tid,))
    return redirect(url_for('timesheets'))
@app.route('/timesheets/csv')
def timesheets_csv():
    rows = db.execute("SELECT t.*, j.title job_title FROM timesheets t LEFT JOIN jobs j ON j.id=t.job_id ORDER BY day DESC, id DESC").fetchall()
    w.writerow(["Employee","Job","Date","Hours","Rate","Total","Approved","Notes"])
        w.writerow([r['employee'], r['job_title'] or '', r['day'], r['hours'], r['rate'], r['hours']*r['rate'], 'yes' if r['approved'] else 'no', r['notes'] or ''])
    resp.headers['Content-Type'] = 'text/csv'
    return resp
@app.route('/timesheet_photos/<path:filename>')
def timesheet_photo(filename):

@require_role('worker')
    return send_from_directory(JOB_FILE_DIR, filename)
@app.route('/jobs/<int:jid>/files/upload', methods=['POST'])
def job_file_upload(jid):
    if not file or not file.filename:
    try:
        file.save(os.path.join(JOB_FILE_DIR, filename))
        db.execute(
            (jid, filename, file.filename, session['user']['id']),
        db.commit()
        app.logger.error("Failed to upload job file for job %s: %s", jid, e)
    return redirect(url_for('job_view', jid=jid))
# ---------------- PWA
def manifest():
        "name": APP_NAME,
        "start_url": "/",
        "background_color": "#ffffff",
        "icons": []
    resp = make_response(json.dumps(data))
    return resp
@app.route('/sw.js')
    js = """
const ASSETS=['/'];
  e.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)));
  }).catch(()=>caches.match(e.request).then(r=>r||new Response('offline',{status:503}))));
"""
    resp.headers['Content-Type'] = 'application/javascript'

def inject_globals():

BASE = r"""
<!doctype html>
  <head>
    <link rel="manifest" href="/manifest.webmanifest"> 
      <title>{{ title or APP_NAME }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
    <nav class="bg-white border-b sticky top-0 z-10">
        <a href="{{ url_for('dashboard') }}" class="text-xl font-bold">{{ APP_NAME }}</a>
            {% if session['user']['role'] in ['manager','admin'] %}
            <a class="hover:underline" href="{{ url_for('catalog') }}">Catalog</a>
            {% endif %}
            <a class="hover:underline" href="{{ url_for('timesheets') }}">Timesheets</a>
        </div>
          {% if session.get('user') %}
            {% if session['user']['role']=='admin' %}
            {% endif %}
          {% endif %}
      </div>
    <main class="max-w-6xl mx-auto p-4">
    </main>
  </body>
"""
LOGIN = r"""
  <h1 class="text-xl font-semibold mb-4">Sign in</h1>
@@ -896,189 +968,229 @@ ESTIMATE_EDIT = r"""
</div>

<!doctype html><html><head><meta charset="utf-8"><title>Estimate #{{ est['id'] }}</title>
</head><body>
<p><strong>Client:</strong> {{ est['client_name'] }}<br>
<strong>Email:</strong> {{ est['email'] or '' }} | <strong>Phone:</strong> {{ est['phone'] or '' }}</p>
<tbody>
</tbody></table>
Margin ({{ est['margin_pct'] }}%): ${{ '%.2f' % margin }}<br>
<strong>Total: ${{ '%.2f' % total }}</strong></p>
</body></html>

<div class="flex items-center mb-3"><h1 class="text-2xl font-semibold">Jobs</h1>
  {% if session['user']['role'] in ['manager','admin'] %}
  {% endif %}
<div class="bg-white rounded-2xl p-4 shadow overflow-x-auto">
    <thead><tr class="text-left text-slate-500"><th>#</th><th>Title</th><th>Client</th><th>Status</th>{% if session['user']['role'] in ['manager','admin'] %}<th>Budget Hrs</th><th>Budget $</th>{% endif %}<th></th></tr></thead>
      {% for r in rows %}
        <td><a href="{{ url_for('job_view', jid=r['id']) }}" class="hover:underline">{{ r['title'] }}</a></td>
        <td>{{ r['status'] }}</td>
        <td>{{ r['budget_hours'] }}</td>
        {% endif %}
      {% else %}<tr><td colspan="{{ 7 if session['user']['role'] in ['manager','admin'] else 5 }}" class="py-3 text-slate-500">No jobs.</td></tr>{% endfor %}
    </tbody>
</div>

<h1 class="text-2xl font-semibold mb-3">New Job</h1>
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <label class="text-sm text-slate-500">Client</label>
      {% for c in clients %}<option value="{{ c['id'] }}">{{ c['name'] }}</option>{% endfor %}
  </div>
    <label class="text-sm text-slate-500">Estimate (optional)</label>
      <option value="">—</option>
    </select>
  <div>
    <input name="title" class="w-full border rounded-xl p-2" placeholder="Site prep & trucking" required>
  <div>
    <select name="status" class="w-full border rounded-xl p-2"><option>open</option><option>scheduled</option><option>in_progress</option><option>hold</option><option>done</option><option>invoiced</option></select>
  <div><label class="text-sm text-slate-500">Budget Hours</label><input type="number" step="0.1" name="budget_hours" class="w-full border rounded-xl p-2" value="0"></div>
  <div><label class="text-sm text-slate-500">Start</label><input type="date" name="start_date" class="w-full border rounded-xl p-2" value="{{ today }}"></div>
  <div class="md:col-span-3"><label class="text-sm text-slate-500">Notes</label><textarea name="notes" class="w-full border rounded-xl p-2" rows="3"></textarea></div>
</form>

<div class="flex items-center mb-3"><h1 class="text-2xl font-semibold">Job #{{ j['id'] }} — {{ j['title'] }}</h1></div>
{% if session['user']['role'] in ['manager','admin'] %}
  <div class="md:col-span-2 bg-white rounded-2xl p-4 shadow overflow-x-auto">
    <table class="w-full text-sm">
      <tbody>
        <tr class="border-t"><td class="py-2">{{ t['employee'] }}</td><td>{{ t['day'] }}</td><td>{{ t['hours'] }}</td><td>${{ '%.2f' % t['rate'] }}</td><td>${{ '%.2f' % (t['hours']*t['rate']) }}</td><td>{% if t['photo'] %}<a class="text-blue-600 hover:underline" href="{{ url_for('timesheet_photo', filename=t['photo']) }}" target="_blank">View</a>{% else %}—{% endif %}</td><td>{{ 'yes' if t['approved'] else 'no' }}</td>
        </tr>
      </tbody>
  </div>
    <h2 class="font-semibold mb-2">Summary</h2>
    <div class="mb-2">{{ j['client_name'] }}</div>
      <div>Budget Hrs</div><div class="text-right">{{ j['budget_hours'] }}</div>
      <div>Budget $</div><div class="text-right">${{ '%.2f' % (j['budget_cost'] or 0) }}</div>
    </div>
</div>
<div class="bg-white rounded-2xl p-4 shadow mt-4">
  <ul class="text-sm">
      <li><a class="text-blue-600 hover:underline" href="{{ url_for('job_file', filename=f['filename']) }}" target="_blank">{{ f['original_name'] }}</a></li>
      <li class="text-slate-500">No documents.</li>
  </ul>
  <form class="mt-2" method="post" action="{{ url_for('job_file_upload', jid=j['id']) }}" enctype="multipart/form-data">
    <input type="file" name="file" class="text-sm" required>
  </form>
</div>

<div class="flex items-center mb-3"><h1 class="text-2xl font-semibold flex-1">Timesheets</h1>{% if session['user']['role'] in ['manager','admin'] %}{% if show_all %}<a class="text-sm text-slate-500 hover:underline" href="{{ url_for('timesheets') }}">Show Mine</a>{% else %}<a class="text-sm text-slate-500 hover:underline" href="{{ url_for('timesheets', all=1) }}">Show All</a>{% endif %}{% endif %}</div>
  <form id="ts-form" method="post" action="{{ url_for('timesheets_create') }}" class="grid md:grid-cols-6 gap-2" enctype="multipart/form-data">
    <select class="border rounded-xl p-2" name="employee_id" required>
    <select class="border rounded-xl p-2" name="job_id">
      {% for j in jobs %}<option value="{{ j['id'] }}">{{ j['title'] }}</option>{% endfor %}
    <input class="border rounded-xl p-2" type="date" name="day" value="{{ today }}">
    {% if session['user']['role'] in ['manager','admin'] %}
    {% endif %}
    <datalist id="notes-list">
    </datalist>
    <div class="flex gap-2">
      <button type="button" id="quick-add-today" class="bg-slate-600 text-white rounded-xl px-4">Add for Today</button>
  </form>
<div class="bg-white rounded-2xl p-4 shadow overflow-x-auto">
    <thead><tr class="text-left text-slate-500"><th>Employee</th><th>Job</th><th>Date</th><th>Hours</th>{% if session['user']['role'] in ['manager','admin'] %}<th>Rate</th><th>$</th>{% endif %}<th>Photo</th><th>Approved</th><th></th></tr></thead>
      {% for r in rows %}
        <td class="text-right flex gap-2 justify-end">
            <form method="post" action="{{ url_for('timesheets_approve', tid=r['id']) }}"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="text-green-600 text-sm">Approve</button></form>
          {% if session['user']['role'] in ['manager','admin'] %}
          {% endif %}
      </tr>
    </tbody>
  <div class="mt-3">
    <a class="text-sm text-slate-500 hover:underline" href="{{ url_for('timesheets_csv') }}">Export CSV</a>
  </div>
<script>
  const dateInput = document.querySelector('input[type="date"][name="day"]');
  const form = document.getElementById('ts-form');
  const userSelect = document.querySelector('select[name="employee_id"]');
  const notesInput = document.querySelector('input[name="notes"]');
  if(jobSelect){
    if(lastJob) jobSelect.value = lastJob;
  }
    const lastUser = localStorage.getItem('lastEmployeeId');
    const updateRate = ()=>{ if(rateInput) rateInput.value = userRates[userSelect.value] || ''; };
      localStorage.setItem('lastEmployeeId', this.value);
    });
  }
    const lastNotes = localStorage.getItem('lastNotes');
    notesInput.addEventListener('change', ()=>localStorage.setItem('lastNotes', notesInput.value));
  const quickBtn = document.getElementById('quick-add-today');
    quickBtn.addEventListener('click', function(){
      form.submit();
  }
</script>

    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
