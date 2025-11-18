#!/usr/bin/env python3
import os, re, time, shutil, subprocess, json, secrets
from typing import Dict, Any, List, Tuple
from flask import Flask, request, jsonify, Response, make_response, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import yaml

APP_TITLE   = "OGG Web Monitor & Control"
CONFIG_PATH = os.environ.get("OGG_WEB_CONFIG", "/opt/oracle/ogg_web/config/ogg_local.yaml")
USERS_PATH  = os.environ.get("OGG_USERS_FILE", "/opt/oracle/ogg_web/config/users.json")
LISTEN_HOST = os.environ.get("OGG_WEB_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("OGG_WEB_PORT", "5000"))
POLL_SECONDS= int(os.environ.get("OGG_POLL_SECONDS", "10"))
SECRET_KEY  = os.environ.get("OGG_SECRET_KEY") or secrets.token_hex(32)
DISCOVERY_ROOTS = ["/u01","/u02","/u03","/opt/oracle","/opt/ogg","/opt"]

app = Flask(__name__)
app.config.update(
    SECRET_KEY = SECRET_KEY,
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "Lax",
    SESSION_COOKIE_SECURE = False  # set True when behind HTTPS
)

# ---------------- Security headers ----------------
@app.after_request
def _sec_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
    return resp

def _json_no_cache(payload, code=200):
    r = make_response(json.dumps(payload), code)
    r.mimetype = "application/json"
    r.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return r

# ---------------- Users & config files -------------
def _read_users() -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(USERS_PATH):
        return {}
    with open(USERS_PATH, "r", encoding="utf-8") as f:
        return json.load(f) or {}

def _write_users(d: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(USERS_PATH), exist_ok=True)
    tmp = USERS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)
    os.replace(tmp, USERS_PATH)

def ensure_initial_admin():
    users = _read_users()
    if users: return
    user = os.environ.get("OGG_ADMIN_USER", "admin")
    pwd  = os.environ.get("OGG_ADMIN_PASS", "ChangeMe!123")
    users[user] = {"hash": generate_password_hash(pwd), "role": "admin", "created": int(time.time())}
    _write_users(users)
    print(f"* Created initial admin '{user}' with default/provided password — change it in Admin > Users.")

def load_config() -> Dict[str, Any]:
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"Config not found: {CONFIG_PATH}")
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if "homes" not in data or not isinstance(data["homes"], list):
        raise ValueError("config must contain a 'homes' list")
    return data

def save_config(cfg: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)
    os.replace(tmp, CONFIG_PATH)

# ---------------- Auth helpers --------------------
def _issue_csrf():
    if not session.get("csrf"):
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]

def login_required(fn):
    def wrap(*a, **k):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return fn(*a, **k)
    wrap.__name__ = fn.__name__
    return wrap

def api_login_required(fn):
    def wrap(*a, **k):
        if not session.get("user"):
            return _json_no_cache({"error":"auth required"}, 401)
        return fn(*a, **k)
    wrap.__name__ = fn.__name__
    return wrap

def admin_required(fn):
    def wrap(*a, **k):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "admin":
            return make_response("Forbidden", 403)
        return fn(*a, **k)
    wrap.__name__ = fn.__name__
    return wrap

def api_admin_required(fn):
    def wrap(*a, **k):
        if not session.get("user"):
            return _json_no_cache({"error":"auth required"}, 401)
        if session.get("role") != "admin":
            return _json_no_cache({"error":"forbidden"}, 403)
        if request.headers.get("X-CSRF-Token") != session.get("csrf"):
            return _json_no_cache({"error":"invalid csrf"}, 403)
        return fn(*a, **k)
    wrap.__name__ = fn.__name__
    return wrap

# ---------------- Discovery & ggsci ---------------
def discover_homes(max_hits:int=6) -> List[Dict[str, Any]]:
    homes: List[Dict[str, Any]] = []
    for p in os.environ.get("PATH","").split(":"):
        exe = os.path.join(p, "ggsci")
        if os.path.isfile(exe) and os.access(exe, os.X_OK):
            gh = os.path.dirname(exe)
            if all(h.get("gg_home") != gh for h in homes):
                homes.append({"name": os.path.basename(gh) or gh, "gg_home": gh})
    for root in DISCOVERY_ROOTS:
        for d, subdirs, files in os.walk(root):
            if (d.count(os.sep) - root.count(os.sep)) > 4:
                subdirs[:] = []; continue
            if "ggsci" in files:
                gh = d
                if all(h.get("gg_home") != gh for h in homes):
                    homes.append({"name": os.path.basename(gh) or gh, "gg_home": gh})
                    if len(homes) >= max_hits: break
        if len(homes) >= max_hits: break
    return homes

def attach_defaults(homes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ORACLE_HOME = os.environ.get("ORACLE_HOME", "").rstrip("/")
    TNS_ADMIN  = os.environ.get("TNS_ADMIN", (ORACLE_HOME + "/network/admin" if ORACLE_HOME else ""))
    out = []
    for h in homes:
        gh   = (h.get("gg_home") or "").rstrip("/")
        name = h.get("name") or os.path.basename(gh) or gh
        out.append({
            "name": name, "gg_home": gh,
            "oracle_home": h.get("oracle_home", ORACLE_HOME),
            "tns_admin":   h.get("tns_admin", TNS_ADMIN),
            "db_name":     h.get("db_name", ""),
            "useridalias": h.get("useridalias", ""),
            "show_lag":    h.get("show_lag", True),
        })
    return out

def _find_home(home_name: str) -> Dict[str, Any]:
    try:
        cfg = load_config()
        for h in cfg["homes"]:
            nm = h.get("name") or h.get("gg_home")
            if home_name == nm:
                return h
    except Exception:
        pass
    for h in attach_defaults(discover_homes()):
        nm = h.get("name") or h.get("gg_home")
        if home_name == nm:
            return h
    raise KeyError("Home not found")

def _build_env(home: Dict[str, Any]) -> Dict[str, str]:
    env = os.environ.copy()
    gg_home = home["gg_home"].rstrip("/")
    oracle_home = home.get("oracle_home","").rstrip("/")
    if not oracle_home:
        raise RuntimeError("oracle_home not set (set YAML or export ORACLE_HOME)")
    tns_admin = home.get("tns_admin") or (oracle_home + "/network/admin")
    path_extra = home.get("path_extra", "")
    env["OGG_HOME"] = gg_home
    env["ORACLE_HOME"] = oracle_home
    env["TNS_ADMIN"] = tns_admin
    env["PATH"] = f"{gg_home}:{oracle_home}/bin:{path_extra}:{env.get('PATH','')}" if path_extra else f"{gg_home}:{oracle_home}/bin:{env.get('PATH','')}"
    env["LD_LIBRARY_PATH"] = f"{oracle_home}/lib:{env.get('LD_LIBRARY_PATH','')}"
    return env

def _run_ggsci(home: Dict[str, Any], lines: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    env = _build_env(home)
    ggsci = os.path.join(home["gg_home"], "ggsci")
    script = "\n".join(lines) + "\n"
    try:
        p = subprocess.run([ggsci], input=script.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, env=env, check=False)
        return p.returncode, p.stdout.decode(errors="ignore"), p.stderr.decode(errors="ignore")
    except FileNotFoundError:
        return 1, "", f"ggsci not found at {ggsci}"
    except subprocess.TimeoutExpired:
        return 124, "", "ggsci command timed out"

# ---------------- Parsers ------------------------
MANAGER_STATUS_RE = re.compile(r"Manager\s+is\s+(RUNNING|DOWN)!?", re.IGNORECASE)
STATUS_WORD = r"(RUNNING|STOPPED|ABENDED|STARTING|STOPPING|RETRYING|WAITING|DELAYED)"
PROC_LINE_NAME_FIRST_RE = re.compile(
    rf"^(EXTRACT|REPLICAT)\s+([A-Za-z0-9_.\-]+)\s+{STATUS_WORD}\b.*$",
    re.IGNORECASE
)
PROC_LINE_STATUS_FIRST_RE = re.compile(
    rf"^(EXTRACT|REPLICAT)\s+{STATUS_WORD}\s+([A-Za-z0-9_.\-]+)"
    rf"(?:\s+([0-9:]+|[0-9]+\s*seconds|None))?"
    rf"(?:\s+([0-9:]+|[0-9]+\s*seconds|None))?",
    re.IGNORECASE
)
LAG_LINE_RE   = re.compile(r"Lag\s+at\s+Chkpt\s*:\s*([0-9:]+|[0-9]+\s*seconds|None)", re.IGNORECASE)
SINCE_LINE_RE = re.compile(r"Time\s+Since\s+Chkpt\s*:\s*([0-9:]+|[0-9]+\s*seconds|None)", re.IGNORECASE)

def _parse_info_all(text: str) -> Dict[str, Any]:
    lines = [ln.rstrip() for ln in text.splitlines()]
    manager = None
    procs: List[Dict[str, Any]] = []
    for ln in lines:
        if not ln.strip(): continue
        m = MANAGER_STATUS_RE.search(ln)
        if m:
            manager = m.group(1).upper(); continue
        s1 = PROC_LINE_STATUS_FIRST_RE.match(ln)
        if s1:
            ptype, status, name = s1.group(1).upper(), s1.group(2).upper(), s1.group(3)
            lag, since = s1.group(4), s1.group(5)
            procs.append({"type": ptype, "name": name, "status": status, "lag": lag, "since": since})
            continue
        s2 = PROC_LINE_NAME_FIRST_RE.match(ln)
        if s2:
            ptype, name, status = s2.group(1).upper(), s2.group(2), s2.group(3).upper()
            procs.append({"type": ptype, "name": name, "status": status, "lag": None, "since": None})
            continue
        # loose fallback
        parts = ln.split()
        if len(parts) >= 3 and parts[0].upper() in ("EXTRACT","REPLICAT"):
            ptype = parts[0].upper()
            st_ix = None
            for i in range(1, min(5, len(parts))):
                if re.fullmatch(STATUS_WORD, parts[i], flags=re.IGNORECASE):
                    st_ix = i; break
            if st_ix is not None:
                status = parts[st_ix].upper()
                name = parts[1] if st_ix == 2 else (parts[st_ix+1] if st_ix+1 < len(parts) else "")
                lag = parts[st_ix+2] if st_ix+2 < len(parts) and re.fullmatch(r"[0-9:]+|[0-9]+\s*seconds|None", parts[st_ix+2], flags=re.IGNORECASE) else None
                since = parts[st_ix+3] if st_ix+3 < len(parts) and re.fullmatch(r"[0-9:]+|[0-9]+\s*seconds|None", parts[st_ix+3], flags=re.IGNORECASE) else None
                if name:
                    procs.append({"type": ptype, "name": name, "status": status, "lag": lag, "since": since})
    return {"manager": manager, "processes": procs}

def _augment_lag(home: Dict[str, Any], procs: List[Dict[str, Any]], timeout: int = 20) -> None:
    """Fill lag/since by calling 'info <proc>' for RUNNING procs lacking values."""
    need = [p for p in procs if p.get("status")=="RUNNING" and (not p.get("lag") or not p.get("since"))]
    for pr in need:
        rc, out, _ = _run_ggsci(home, [f"info {pr['name']}"], timeout=timeout)
        if rc != 0: continue
        lag_m = LAG_LINE_RE.search(out); since_m = SINCE_LINE_RE.search(out)
        pr["lag"] = pr.get("lag") or (lag_m.group(1) if lag_m else None)
        pr["since"] = pr.get("since") or (since_m.group(1) if since_m else None)

# ---------------- Auth routes --------------------
LOGIN_HTML = """
<!doctype html><meta charset="utf-8"><title>Login</title>
<style>
:root{--fg:#111827;--muted:#6b7280;--line:#e5e7eb;--card:#ffffff;--btn:#0d6efd;--btnb:#0b5ed7;}
body{margin:0;font-family:system-ui; background:#ffffff; color:var(--fg)}
.card{max-width:380px;margin:12vh auto;background:var(--card);border:1px solid var(--line);border-radius:14px;color:var(--fg);padding:22px;box-shadow:0 8px 20px rgba(0,0,0,.05)}
h2{margin:0 0 10px 0}
label{display:block;margin:10px 0 4px 0;color:#374151}
input{width:100%;padding:10px;border-radius:10px;border:1px solid var(--line);background:#ffffff;color:var(--fg)}
.btn{margin-top:14px;width:100%;padding:10px;border-radius:10px;border:1px solid var(--btnb);background:var(--btn);color:#fff;cursor:pointer}
.err{margin-top:8px;color:#b91c1c}
.small{color:var(--muted);font-size:12px;margin-top:8px}
</style>
<div class="card">
  <h2>Sign in</h2>
  <form method="POST" action="/login">
    <label>Username</label><input name="username" autofocus>
    <label>Password</label><input name="password" type="password">
    <button class="btn">Login</button>
  </form>
  __ERR__
  <div class="small">Need access? Ask an admin.</div>
</div>
"""

@app.get("/login")
def login():
    if session.get("user"): return redirect(url_for("index"))
    return Response(LOGIN_HTML.replace("__ERR__",""), mimetype="text/html")

@app.post("/login")
def do_login():
    u = request.form.get("username","").strip()
    p = request.form.get("password","")
    users = _read_users()
    if u in users and check_password_hash(users[u]["hash"], p):
        session["user"] = u
        session["role"] = users[u].get("role","user")
        _issue_csrf()
        return redirect(request.args.get("next") or url_for("index"))
    return Response(LOGIN_HTML.replace("__ERR__","<div class='err'>Invalid credentials</div>"), mimetype="text/html")

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- Admin UI ----------------------
ADMIN_HTML = """
<!doctype html><meta charset='utf-8'/><title>Admin</title>
<style>
:root{--fg:#111827;--muted:#6b7280;--line:#e5e7eb;--card:#ffffff;--btn:#0d6efd;--btnb:#0b5ed7;}
body{margin:0;font-family:system-ui;background:#ffffff;color:var(--fg)}
header{padding:12px 16px;background:#ffffff;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center;position:sticky;top:0}
a{color:#0d6efd}
.wrap{max-width:1100px;margin:20px auto;padding:0 12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin-bottom:16px}
h3{margin:6px 0 10px 0;color:#111827}
table{width:100%;border-collapse:collapse}
th,td{padding:8px 10px;border-bottom:1px solid var(--line)}
input,select{background:#ffffff;color:var(--fg);border:1px solid var(--line);border-radius:10px;padding:8px;width:100%}
.btn{background:var(--btn);color:#fff;border:1px solid var(--btnb);padding:8px 10px;border-radius:10px;cursor:pointer}
.btn.red{background:#b91c1c;border-color:#991b1b}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
</style>
<header>
  <div style="font-weight:700">Admin</div>
  <div style="margin-left:auto"><a href="/">Home</a> • <a href="/logout">Logout</a></div>
</header>
<div class="wrap">
  <div class="card">
    <h3>Users</h3>
    <div class="grid">
      <div>
        <table id="tblUsers"><thead><tr><th>User</th><th>Role</th><th>Actions</th></tr></thead><tbody></tbody></table>
      </div>
      <div>
        <h4>Add / Update</h4>
        <label>Username</label><input id="u_user">
        <label>Password (leave blank to keep)</label><input id="u_pass" type="password">
        <label>Role</label><select id="u_role"><option>user</option><option>admin</option></select>
        <div style="margin-top:8px">
          <button class="btn" onclick="saveUser()">Save</button>
          <button class="btn red" onclick="delUser()">Delete</button>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <h3>GoldenGate Homes</h3>
    <div class="grid">
      <div>
        <table id="tblHomes"><thead><tr><th>Name</th><th>GG Home</th><th>Oracle Home</th><th>Actions</th></tr></thead><tbody></tbody></table>
      </div>
      <div>
        <h4>Add / Update</h4>
        <label>Name</label><input id="h_name">
        <label>GG Home</label><input id="h_gghome">
        <label>Oracle Home</label><input id="h_orahome">
        <label>TNS Admin (optional)</label><input id="h_tns">
        <label>DB Name (optional)</label><input id="h_db">
        <label>UserID Alias (optional)</label><input id="h_alias">
        <label>Show Lag (true/false)</label><input id="h_lag" placeholder="true" value="true">
        <div style="margin-top:8px">
          <button class="btn" onclick="saveHome()">Save</button>
          <button class="btn red" onclick="delHome()">Delete</button>
        </div>
      </div>
    </div>
  </div>
</div>
<script>
async function api(path, method='GET', body=null){
  const headers={'Content-Type':'application/json','X-CSRF-Token':getCsrf()};
  const r=await fetch(path,{method,headers,body:body?JSON.stringify(body):null});
  return await r.json();
}
function getCsrf(){ const m=document.cookie.match(/csrf=([^;]+)/); return m?decodeURIComponent(m[1]):'';}
function setCsrf(v){ document.cookie='csrf='+encodeURIComponent(v)+'; Path=/'; }

async function loadUsers(){
  const d=await api('/api/admin/users/list');
  setCsrf(d.csrf||'');
  const tb=document.querySelector('#tblUsers tbody'); tb.innerHTML='';
  (d.users||[]).forEach(u=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${u.name}</td><td>${u.role}</td><td><button class="btn" onclick="fillUser('${u.name}','${u.role}')">Edit</button></td>`;
    tb.appendChild(tr);
  });
}
function fillUser(u,r){ document.getElementById('u_user').value=u; document.getElementById('u_role').value=r; document.getElementById('u_pass').value=''; }
async function saveUser(){
  const u=document.getElementById('u_user').value.trim();
  const p=document.getElementById('u_pass').value;
  const r=document.getElementById('u_role').value;
  if(!u){alert('username required');return}
  const d=await api('/api/admin/users/upsert','POST',{username:u,password:p,role:r});
  if(!d.ok){alert(d.error||'error');return}
  await loadUsers(); alert('Saved'); 
}
async function delUser(){
  const u=document.getElementById('u_user').value.trim();
  if(!u){alert('username required');return}
  if(!confirm('Delete '+u+'?')) return;
  const d=await api('/api/admin/users/delete','POST',{username:u});
  if(!d.ok){alert(d.error||'error');return}
  await loadUsers(); alert('Deleted');
}

async function loadHomes(){
  const d=await api('/api/admin/homes/list');
  const tb=document.querySelector('#tblHomes tbody'); tb.innerHTML='';
  (d.homes||[]).forEach(h=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${h.name}</td><td>${h.gg_home||''}</td><td>${h.oracle_home||''}</td>
      <td><button class="btn" onclick='fillHome(${JSON.stringify(h).replace(/"/g,"&quot;")})'>Edit</button></td>`;
    tb.appendChild(tr);
  });
}
function fillHome(h){
  document.getElementById('h_name').value=h.name||'';
  document.getElementById('h_gghome').value=h.gg_home||'';
  document.getElementById('h_orahome').value=h.oracle_home||'';
  document.getElementById('h_tns').value=h.tns_admin||'';
  document.getElementById('h_db').value=h.db_name||'';
  document.getElementById('h_alias').value=h.useridalias||'';
  document.getElementById('h_lag').value=String(h.show_lag!==false);
}
async function saveHome(){
  const h={
    name:document.getElementById('h_name').value.trim(),
    gg_home:document.getElementById('h_gghome').value.trim(),
    oracle_home:document.getElementById('h_orahome').value.trim(),
    tns_admin:document.getElementById('h_tns').value.trim(),
    db_name:document.getElementById('h_db').value.trim(),
    useridalias:document.getElementById('h_alias').value.trim(),
    show_lag:(document.getElementById('h_lag').value.trim().toLowerCase()==='true')
  };
  if(!h.name||!h.gg_home){alert('name and gg_home are required');return}
  const d=await api('/api/admin/homes/upsert','POST',h);
  if(!d.ok){alert(d.error||'error');return}
  await loadHomes(); alert('Saved');
}
async function delHome(){
  const name=document.getElementById('h_name').value.trim();
  if(!name){alert('name required');return}
  if(!confirm('Delete '+name+'?')) return;
  const d=await api('/api/admin/homes/delete','POST',{name});
  if(!d.ok){alert(d.error||'error');return}
  await loadHomes(); alert('Deleted');
}
(async()=>{ await loadUsers(); await loadHomes(); })();
</script>
"""

@app.get("/admin")
@admin_required
def admin_page():
    resp = make_response(ADMIN_HTML)
    resp.set_cookie("csrf", _issue_csrf(), httponly=False, samesite="Lax", secure=app.config["SESSION_COOKIE_SECURE"])
    return resp

# ---------------- Admin APIs --------------------
@app.get("/api/admin/users/list")
@api_admin_required
def api_users_list():
    users = _read_users()
    data = [{"name": u, "role": v.get("role","user"), "created": v.get("created",0)} for u,v in sorted(users.items())]
    return _json_no_cache({"users": data, "csrf": _issue_csrf()})

@app.post("/api/admin/users/upsert")
@api_admin_required
def api_users_upsert():
    j = request.get_json(force=True)
    u = (j.get("username") or "").strip()
    r = (j.get("role") or "user").strip()
    p = j.get("password","")
    if not u: return _json_no_cache({"ok":False,"error":"username required"},400)
    if r not in ("user","admin"): return _json_no_cache({"ok":False,"error":"invalid role"},400)
    users = _read_users()
    rec = users.get(u, {"created": int(time.time())})
    if p: rec["hash"] = generate_password_hash(p)
    elif "hash" not in rec:
        return _json_no_cache({"ok":False,"error":"password required for new user"},400)
    rec["role"] = r
    users[u] = rec
    _write_users(users)
    return _json_no_cache({"ok": True})

@app.post("/api/admin/users/delete")
@api_admin_required
def api_users_delete():
    j = request.get_json(force=True)
    u = (j.get("username") or "").strip()
    if not u: return _json_no_cache({"ok":False,"error":"username required"},400)
    users = _read_users()
    if u not in users: return _json_no_cache({"ok":False,"error":"not found"},404)
    if len(users)==1: return _json_no_cache({"ok":False,"error":"cannot delete last user"},400)
    users.pop(u); _write_users(users)
    return _json_no_cache({"ok": True})

@app.get("/api/admin/homes/list")
@api_admin_required
def api_homes_list_admin():
    try:
        cfg = load_config()
        return _json_no_cache({"homes": cfg.get("homes",[]), "csrf": _issue_csrf()})
    except Exception as e:
        return _json_no_cache({"homes": [], "error": str(e), "csrf": _issue_csrf()})

@app.post("/api/admin/homes/upsert")
@api_admin_required
def api_homes_upsert():
    j = request.get_json(force=True)
    name = (j.get("name") or "").strip()
    gg_home = (j.get("gg_home") or "").strip()
    if not name or not gg_home:
        return _json_no_cache({"ok":False,"error":"name and gg_home required"},400)
    try: cfg = load_config()
    except Exception: cfg = {"homes":[]}
    homes = cfg.get("homes",[])
    idx = next((i for i,h in enumerate(homes) if (h.get("name") or h.get("gg_home")) == name), -1)
    rec = {
        "name": name, "gg_home": gg_home,
        "oracle_home": (j.get("oracle_home") or "").strip(),
        "tns_admin": (j.get("tns_admin") or "").strip(),
        "db_name": (j.get("db_name") or "").strip(),
        "useridalias": (j.get("useridalias") or "").strip(),
        "show_lag": bool(j.get("show_lag", True))
    }
    if idx >= 0: homes[idx] = rec
    else: homes.append(rec)
    cfg["homes"] = homes; save_config(cfg)
    return _json_no_cache({"ok": True})

@app.post("/api/admin/homes/delete")
@api_admin_required
def api_homes_delete():
    j = request.get_json(force=True)
    name = (j.get("name") or "").strip()
    if not name: return _json_no_cache({"ok":False,"error":"name required"},400)
    try: cfg = load_config()
    except Exception: return _json_no_cache({"ok":False,"error":"config missing"},404)
    homes = cfg.get("homes",[])
    new = [h for h in homes if (h.get("name") or h.get("gg_home")) != name]
    if len(new)==len(homes): return _json_no_cache({"ok":False,"error":"not found"},404)
    cfg["homes"] = new; save_config(cfg)
    return _json_no_cache({"ok": True})

# ---------------- Monitor APIs (auth) -----------
@app.get("/api/homes")
@api_login_required
def api_homes():
    source="config"; err=None; homes=[]
    try:
        cfg=load_config()
        homes=[{
            "name":h.get("name") or h.get("gg_home"),
            "gg_home":h.get("gg_home"),
            "oracle_home":h.get("oracle_home",""),
            "tns_admin":h.get("tns_admin",""),
            "useridalias":h.get("useridalias",""),
            "show_lag":h.get("show_lag",True)
        } for h in cfg["homes"]]
    except Exception as e:
        source="discovery"; err=str(e); homes=attach_defaults(discover_homes())
    return _json_no_cache({"homes":homes,"source":source,"error":err,"config_path":CONFIG_PATH})

@app.get("/api/status")
@api_login_required
def api_status():
    home_name = request.args.get("home")
    if not home_name: return _json_no_cache({"error":"home is required"},400)
    try: home = _find_home(home_name)
    except Exception as e: return _json_no_cache({"error":str(e)},404)

    rc1, mgr_out, _ = _run_ggsci(home, ["info mgr"], timeout=20)
    m = MANAGER_STATUS_RE.search(mgr_out or ""); manager = m.group(1).upper() if m else None

    rc2, out, err = _run_ggsci(home, ["info all"], timeout=40)
    parsed = _parse_info_all(out)
    if manager is None: manager = parsed.get("manager")
    procs = parsed.get("processes", [])
    # Always try to fill lag/since if missing:
    _augment_lag(home, procs, timeout=20)

    return _json_no_cache({
        "manager": manager,
        "processes": procs,
        "gg_home": home.get("gg_home",""),
        "oracle_home": home.get("oracle_home",""),
        "tns_admin": home.get("tns_admin","")
    })

@app.get("/api/status_raw")
@api_login_required
def api_status_raw():
    home_name = request.args.get("home")
    if not home_name: return Response("home is required\n", mimetype="text/plain", status=400)
    try: home = _find_home(home_name)
    except Exception as e: return Response(f"{e}\n", mimetype="text/plain", status=404)
    rc, out, err = _run_ggsci(home, ["info all"], timeout=40)
    return Response((out or err or ""), mimetype="text/plain")

@app.post("/api/control")
@api_login_required
def api_control():
    if request.headers.get("X-CSRF-Token") != session.get("csrf"):
        return _json_no_cache({"error":"invalid csrf"}, 403)
    data = request.get_json(force=True)
    for k in ("home","target_type","action"):
        if not data.get(k): return _json_no_cache({"error": f"Missing field: {k}"}, 400)
    try: home = _find_home(data["home"])
    except Exception as e: return _json_no_cache({"error": str(e)}, 404)

    target_type = data["target_type"].lower()
    action = data["action"].lower()
    name = data.get("target_name")

    # admin-only for mgr
    if target_type == "mgr":
        if session.get("role") != "admin":
            return _json_no_cache({"error":"forbidden (admin only)"}, 403)
        if   action == "start": cmd = "start mgr"
        elif action == "stop":  cmd = "stop mgr!"
        else: return _json_no_cache({"error":"Unsupported action for mgr"},400)
    else:
        if not name: return _json_no_cache({"error":"target_name is required for extract/replicat"},400)
        if   action == "start": cmd = f"start {name}"
        elif action == "stop":  cmd = f"stop {name}"
        elif action == "kill":  cmd = f"kill {name}"
        else: return _json_no_cache({"error":"Unsupported action"},400)

    rc, out, err = _run_ggsci(home, [cmd], timeout=30)
    return _json_no_cache({"ok": rc == 0, "output": out if out else err})

@app.post("/api/control_bulk")
@api_login_required
def api_control_bulk():
    if request.headers.get("X-CSRF-Token") != session.get("csrf"):
        return _json_no_cache({"error":"invalid csrf"}, 403)
    data = request.get_json(force=True)
    for k in ("home","type","action"):
        if not data.get(k): return _json_no_cache({"error": f"Missing field: {k}"}, 400)
    try: home = _find_home(data["home"])
    except Exception as e: return _json_no_cache({"error": str(e)}, 404)

    ptype = data["type"].lower(); action = data["action"].lower()
    if ptype not in ("extract","replicat"): return _json_no_cache({"error":"type must be extract or replicat"},400)
    if action not in ("start","stop","kill"): return _json_no_cache({"error":"action must be start/stop/kill"},400)

    rc, out, err = _run_ggsci(home, ["info all"], timeout=40)
    if rc != 0: return _json_no_cache({"error": err or out or "info all failed"}, 502)
    procs = _parse_info_all(out).get("processes", [])

    targets = []
    for p in procs:
        if p.get("type","").lower()!=ptype: continue
        st=p.get("status")
        if action=="start" and st!="RUNNING": targets.append(p["name"])
        elif action=="stop" and st!="STOPPED": targets.append(p["name"])
        elif action=="kill": targets.append(p["name"])
    if not targets:
        return _json_no_cache({"ok": True, "output": f"No {ptype} processes matched for action {action}"})

    cmds = [ ("start "+n) if action=="start" else ("stop "+n if action=="stop" else "kill "+n) for n in targets ]
    to = max(30, 5*len(cmds)); rc2, out2, err2 = _run_ggsci(home, cmds, timeout=to)
    return _json_no_cache({"ok": rc2 == 0, "output": out2 if out2 else err2})

# ---------------- Params APIs & Page ------------
@app.get("/api/params")
@api_login_required
def api_params_get():
    home_name = request.args.get("home"); proc = request.args.get("proc")
    if not (home_name and proc): return _json_no_cache({"ok": False, "error": "home and proc are required"}, 400)
    try: home = _find_home(home_name)
    except Exception as e: return _json_no_cache({"ok": False, "error": str(e)}, 404)
    prm_path = f"{home['gg_home'].rstrip('/')}/dirprm/{proc.lower()}.prm"
    try:
        with open(prm_path, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
        return _json_no_cache({"ok": True, "content": content, "path": prm_path})
    except FileNotFoundError:
        return _json_no_cache({"ok": False, "error": f"Param file not found: {prm_path}"}, 404)
    except Exception as e:
        return _json_no_cache({"ok": False, "error": f"Read error: {e}"}, 502)

@app.post("/api/params")
@api_login_required
def api_params_save():
    if request.headers.get("X-CSRF-Token") != session.get("csrf"):
        return _json_no_cache({"ok":False,"error":"invalid csrf"}, 403)
    data = request.get_json(force=True)
    for k in ("home","proc","content"):
        if not data.get(k): return _json_no_cache({"ok": False, "error": f"Missing field: {k}"}, 400)
    try: home = _find_home(data["home"])
    except Exception as e: return _json_no_cache({"ok": False, "error": str(e)}, 404)
    prm_path = f"{home['gg_home'].rstrip('/')}/dirprm/{data['proc'].lower()}.prm"
    backup_path = f"{prm_path}.bak.{int(time.time())}"
    try:
        if os.path.exists(prm_path): shutil.copy2(prm_path, backup_path)
        with open(prm_path, 'w', encoding='utf-8') as f: f.write(data['content'])
        return _json_no_cache({"ok": True, "backup": backup_path})
    except Exception as e:
        return _json_no_cache({"ok": False, "error": f"Write error: {e}"}, 502)

PARAMS_HTML_TMPL = """
<!doctype html><meta charset='utf-8'><title>Edit Params</title>
<style>
:root{--fg:#111827;--muted:#6b7280;--line:#e5e7eb;--card:#ffffff;--btn:#0d6efd;--btnb:#0b5ed7;}
body{margin:0;font-family:system-ui;background:#ffffff;color:var(--fg)}
header{padding:12px 16px;background:#ffffff;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:center}
a{color:#0d6efd}
.wrap{max-width:1100px;margin:16px auto;padding:0 12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}
label{color:#111827}
textarea{width:100%;height:65vh;background:#ffffff;color:var(--fg);border:1px solid var(--line);border-radius:12px;padding:10px;font-family:ui-monospace,Menlo,Consolas,monospace}
.btn{background:var(--btn);color:#fff;border:1px solid var(--btnb);padding:8px 12px;border-radius:10px;cursor:pointer}
.btn.red{background:#b91c1c;border-color:#991b1b}
.row{display:flex;gap:8px;margin-top:10px}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace}
</style>
<header>
  <div style="font-weight:700">Params — __PROC__</div>
  <div style="margin-left:auto"><a href="/">Back to Home</a></div>
</header>
<div class="wrap">
  <div class="card">
    <div style="margin-bottom:8px">
      <div><b>Home:</b> __HOME__</div>
      <div class="mono"><b>File:</b> __PRM_PATH__</div>
    </div>
    <label>Content</label>
    <textarea id="txt">__CONTENT__</textarea>
    <div class="row">
      <button class="btn" onclick="save()">Save</button>
      <button class="btn red" onclick="cancel()">Cancel</button>
    </div>
    <div id="msg" style="margin-top:10px;color:#b91c1c"></div>
  </div>
</div>
<script>
function csrf(){ const m=document.cookie.match(/csrf=([^;]+)/); return m?decodeURIComponent(m[1]):'';}
function cancel(){ window.location = '/'; }
async function save(){
  const r=await fetch('/api/params', {
    method:'POST',
    headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},
    body: JSON.stringify({home:'__HOME__', proc:'__PROC__', content: document.getElementById('txt').value})
  });
  const d=await r.json();
  if(d.ok){ window.location = '/'; } else { document.getElementById('msg').textContent = d.error || 'Error'; }
}
</script>
"""

@app.get("/params")
@login_required
def params_page():
    home = request.args.get("home","").strip()
    proc = request.args.get("proc","").strip()
    if not home or not proc:
        return redirect(url_for("index"))
    try:
        h = _find_home(home)
        prm_path = f"{h['gg_home'].rstrip('/')}/dirprm/{proc.lower()}.prm"
        with open(prm_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        html = (PARAMS_HTML_TMPL
                .replace("__HOME__", home)
                .replace("__PROC__", proc)
                .replace("__PRM_PATH__", prm_path)
                .replace("__CONTENT__", content.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")))
        resp = make_response(html)
        resp.set_cookie("csrf", _issue_csrf(), httponly=False, samesite="Lax", secure=app.config["SESSION_COOKIE_SECURE"])
        return resp
    except FileNotFoundError:
        html = (PARAMS_HTML_TMPL
                .replace("__HOME__", home)
                .replace("__PROC__", proc)
                .replace("__PRM_PATH__", "(file not found)")
                .replace("__CONTENT__", ""))
        resp = make_response(html)
        resp.set_cookie("csrf", _issue_csrf(), httponly=False, samesite="Lax", secure=app.config["SESSION_COOKIE_SECURE"])
        return resp
    except Exception as e:
        return make_response(f"Error: {e}", 500)

# --------------- Main UI (white theme + buttons) --------
INDEX_HTML_TMPL = """
<!doctype html><html lang='en'><head><meta charset='utf-8'/>
<meta name='viewport' content='width=device-width, initial-scale=1'/>
<title>__TITLE__</title>
<style>
:root{--fg:#111827;--muted:#6b7280;--ok:#15803d;--warn:#b45309;--bad:#b91c1c;--line:#e5e7eb;--card:#ffffff;--btn:#0d6efd;--btnb:#0b5ed7;}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,'Helvetica Neue',Arial,'Noto Sans';margin:0;background:#ffffff;color:var(--fg)}
header{padding:12px 16px;background:#ffffff;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:center;position:sticky;top:0;z-index:10}
.tag{background:#eff6ff;color:#1d4ed8;padding:4px 8px;border-radius:999px;font-size:12px;border:1px solid #dbeafe}
.container{padding:16px}
.grid{display:grid;grid-template-columns:280px 1fr;gap:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:0 2px 10px rgba(0,0,0,.04)}
.card h3{margin:0;padding:12px 14px;border-bottom:1px solid var(--line);font-size:16px;color:#111827}
.scroll{max-height:70vh;overflow:auto}
.home{padding:10px 12px;border-bottom:1px dashed var(--line);cursor:pointer}
.home:hover{background:#f9fafb}
table{width:100%;border-collapse:collapse}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);font-size:14px}
th{text-align:left;color:#374151;position:sticky;top:0;background:var(--card)}
.ok{color:var(--ok);font-weight:600}
.warn{color:var(--warn);font-weight:600}
.bad{color:var(--bad);font-weight:700}
.btn{background:var(--btn);color:#fff;border:1px solid var(--btnb);padding:6px 10px;border-radius:10px;cursor:pointer;font-size:12px}
.btn:hover{filter:brightness(0.95)}
.btn.red{background:#b91c1c;border-color:#991b1b}
.btn.green{background:#15803d;border-color:#166534}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px;align-items:center}
.muted{color:var(--muted);font-size:12px}
.err{background:#fef2f2;border:1px solid #fecaca;padding:8px;border-radius:10px;margin:6px 0;white-space:pre-wrap;display:none;color:#7f1d1d}
a{color:#0d6efd}
.small{color:var(--muted)}
code{background:#f3f4f6;border:1px solid var(--line);padding:2px 4px;border-radius:6px}
</style></head>
<body>
<header>
  <div style="font-weight:700">__TITLE__</div>
  <div class="tag">Refresh: __POLL__s</div>
  <div style="margin-left:auto">__NAV__</div>
</header>
<div class="container">
  <div class="grid">
    <div class="card">
      <h3>GoldenGate Homes (local)</h3>
      <div id="homes" class="scroll"></div>
      <div id="homesErr" class="err"></div>
    </div>
    <div class="card">
      <h3 id="panelTitle">Status</h3>
      <div style="padding: 12px">
        <div class="small" id="paths"></div>

        <!-- Top toolbar with requested buttons -->
        <div class="toolbar" id="controlsbar">
          <button class="btn" onclick="refreshNow()">Manual Refresh</button>
          <button class="btn green" onclick="doBulk('extract','start')">Start All Extracts</button>
          <button class="btn" onclick="doBulk('extract','stop')">Stop All Extracts</button>
          <button class="btn green" onclick="doBulk('replicat','start')">Start All Replicats</button>
          <button class="btn" onclick="doBulk('replicat','stop')">Stop All Replicats</button>
          <button class="btn green" onclick="doBoth('start')">Start ALL</button>
          <button class="btn red" onclick="doBoth('stop')">Stop ALL</button>
        </div>

        <!-- Manager line + admin-only mgr controls -->
        <div class="toolbar" id="mgrbar"></div>

        <div id="statusArea"></div>
        <div class="small" id="lastRef" style="margin-top:8px">—</div>
      </div>
    </div>
  </div>
</div>
<script>
let current=null;
const IS_ADMIN = __IS_ADMIN__;

function csrf(){ const m=document.cookie.match(/csrf=([^;]+)/); return m?decodeURIComponent(m[1]):'';}
function showHomesErr(msg){const he=document.getElementById('homesErr'); he.style.display='block'; he.textContent=msg;}

async function loadHomes(){
  try{
    const r=await fetch('/api/homes',{cache:'no-store'}); const data=await r.json();
    const div=document.getElementById('homes'); div.innerHTML='';
    if(data.error){ showHomesErr(`Config error: ${data.error}\\nConfig path: ${data.config_path||''}`); }
    let list=data.homes||[];
    if((!list||!list.length)&&data.discovered&&data.discovered.length>0){ showHomesErr("Using auto-discovered homes."); list=data.discovered; }
    if(!list||!list.length){ showHomesErr(`No GoldenGate homes found.`); return; }
    list.forEach(h=>{
      const d=document.createElement('div'); d.className='home';
      d.textContent=`• ${h.name}`;   // name only
      d.onclick=()=>{ current={home:h.name}; refreshNow(); document.getElementById('panelTitle').textContent=h.name; };
      div.appendChild(d);
    });
    if(!current){ current={home:list[0].name}; document.getElementById('panelTitle').textContent=list[0].name; refreshNow(); }
  }catch(e){ showHomesErr('Failed to load homes: '+e); }
}

async function refreshNow(){
  if(!current) return;
  const r=await fetch('/api/status?'+new URLSearchParams(current).toString(),{cache:'no-store'});
  const data=await r.json();
  renderStatus(data);
  document.getElementById('lastRef').textContent='Last refresh: '+new Date().toLocaleTimeString();
}

function renderStatus(data){
  const paths=document.getElementById('paths');
  if(data.gg_home||data.oracle_home){
    paths.innerHTML = `<b>GG Home:</b> <code>${data.gg_home||''}</code> &nbsp; | &nbsp; <b>Oracle Home:</b> <code>${data.oracle_home||''}</code>`;
  } else { paths.textContent=''; }

  const mgrbar=document.getElementById('mgrbar');
  mgrbar.innerHTML='';
  const mgrCls=(data.manager==='RUNNING')?'ok':'bad';
  const mgrSpan=document.createElement('div');
  mgrSpan.innerHTML = `Manager: <span class="${mgrCls}">${data.manager||'UNKNOWN'}</span>`;
  mgrbar.appendChild(mgrSpan);
  if(IS_ADMIN){
    const btns=document.createElement('span'); btns.style.marginLeft='10px';
    btns.innerHTML = `
      <button class="btn green" onclick="doAction('mgr','start')">Start MGR</button>
      <button class="btn red" onclick="doAction('mgr','stop')">Stop MGR</button>`;
    mgrbar.appendChild(btns);
  }

  const area=document.getElementById('statusArea');
  if(data.error){ area.innerHTML=`<div class="bad">${data.error}</div>`; return; }

  let html=`<table>
    <thead><tr><th>Type</th><th>Name</th><th>Status</th><th>Lag</th><th>Since</th><th>Actions</th></tr></thead><tbody>`;
  (data.processes||[]).forEach(p=>{
    const cls=p.status==='RUNNING'?'ok':(p.status==='ABENDED'?'bad':'warn');
    html+=`<tr>
      <td>${p.type}</td>
      <td><code>${p.name}</code></td>
      <td class="${cls}">${p.status}</td>
      <td>${p.lag||''}</td>
      <td>${p.since||''}</td>
      <td>
        <button class="btn green" onclick="doAction('${p.type.toLowerCase()}','start','${p.name}')">Start</button>
        <button class="btn" onclick="doAction('${p.type.toLowerCase()}','stop','${p.name}')">Stop</button>
        <button class="btn red" onclick="doAction('${p.type.toLowerCase()}','kill','${p.name}')">Kill</button>
        <button class="btn" onclick="window.location='/params?home='+encodeURIComponent(current.home)+'&proc='+encodeURIComponent('${p.name}')">Params</button>
      </td>
    </tr>`;
  });
  html+=`</tbody></table>`;

  html+=`<div style="margin-top:12px;padding-top:12px;border-top:1px dashed var(--line)">
    <div style="font-weight:600;margin-bottom:6px">ADD TRANDATA</div>
    <input id="obj" placeholder="SCHEMA.TABLE" style="background:#ffffff;color:#111827;border:1px solid var(--line);border-radius:8px;padding:6px"/>
    <input id="alias" placeholder="useridalias (optional overrides config)" style="background:#ffffff;color:#111827;border:1px solid var(--line);border-radius:8px;padding:6px"/>
    <button class="btn" onclick="addTranData()">Run</button>
    <div class="small">Uses DBLOGIN with useridalias when available.</div>
    <pre id="trandataOut" style="white-space:pre-wrap"></pre>
  </div>`;

  area.innerHTML=html;
}

async function doAction(targetType,action,targetName=null){
  if(!current) return;
  const payload={...current,target_type:targetType,action:action}; if(targetName) payload.target_name=targetName;
  const r=await fetch('/api/control',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify(payload)});
  const d=await r.json(); alert((d.ok?'OK\\n':'ERR\\n')+(d.output||d.error||'')); refreshNow();
}

async function doBulk(ptype,action){
  if(!current) return;
  const payload={home:current.home,type:ptype,action:action};
  const r=await fetch('/api/control_bulk',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf()},body:JSON.stringify(payload)});
  const d=await r.json(); alert((d.ok?'OK\\n':'ERR\\n')+(d.output||d.error||'')); refreshNow();
}

async function doBoth(action){
  if(!current) return;
  const headers={'Content-Type':'application/json','X-CSRF-Token':csrf()};
  const p1={home:current.home,type:'extract',action:action};
  const p2={home:current.home,type:'replicat',action:action};
  const r1=await fetch('/api/control_bulk',{method:'POST',headers,body:JSON.stringify(p1)}); const d1=await r1.json();
  const r2=await fetch('/api/control_bulk',{method:'POST',headers,body:JSON.stringify(p2)}); const d2=await r2.json();
  const ok=(!!d1.ok)&&(!d1.error)&&(!!d2.ok)&&(!d2.error);
  const msg1=(d1.ok?'[Extracts] OK':'[Extracts] ERR')+' '+(d1.output||d1.error||'');
  const msg2=(d2.ok?'[Replicats] OK':'[Replicats] ERR')+' '+(d2.output||d2.error||'');
  alert((ok?'OK\\n':'Mixed/ERR\\n')+msg1+'\\n'+msg2);
  refreshNow();
}

setInterval(()=>{ if(current) refreshNow(); }, __POLL__*1000);
loadHomes();
</script>
</body></html>
"""

def _build_index_html():
    nav = '<a href="/logout">Logout</a>'
    if session.get("role") == "admin":
        nav = '<a href="/admin">Admin</a> • ' + nav
    html = (INDEX_HTML_TMPL
            .replace("__TITLE__", APP_TITLE)
            .replace("__POLL__", str(POLL_SECONDS))
            .replace("__NAV__", nav)
            .replace("__IS_ADMIN__", "true" if session.get("role")=="admin" else "false"))
    return html

@app.get("/")
@login_required
def index():
    resp = make_response(_build_index_html())
    resp.set_cookie("csrf", _issue_csrf(), httponly=False, samesite="Lax", secure=app.config["SESSION_COOKIE_SECURE"])
    return resp

# simple page (kept but not linked)
SIMPLE_HTML = "<!doctype html><meta charset='utf-8'><pre id='out'>Loading...</pre><script>fetch('/api/homes').then(r=>r.json()).then(d=>{document.getElementById('out').textContent=JSON.stringify(d,null,2)});</script>"
@app.get("/simple")
@login_required
def simple():
    return Response(SIMPLE_HTML, mimetype="text/html")

# ---------------- Main -------------------------
if __name__ == "__main__":
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(USERS_PATH), exist_ok=True)
    ensure_initial_admin()
    print(f"* {APP_TITLE} http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"* Using config: {CONFIG_PATH}")
    print(f"* Users file : {USERS_PATH}")
    try:
        with open(CONFIG_PATH,'r',encoding='utf-8') as f:
            print('* Config head:\n'+''.join(f.readlines()[:30]))
    except Exception as e:
        print(f"* Config read issue: {e}")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT)
