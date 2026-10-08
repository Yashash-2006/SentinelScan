from flask import Flask, request, jsonify, send_from_directory
import threading,uuid,os,json,sqlite3,sys,tempfile
from datetime import datetime,timezone

BASE=os.path.dirname(os.path.abspath(__file__))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from scanner.engine import Scanner

IS_VERCEL = bool(os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))
if IS_VERCEL:
    DATA = os.path.join(tempfile.gettempdir(), "sentinelscan_data")
else:
    DATA = os.path.join(BASE, "data")

REPORTS = os.path.join(DATA, "reports")
os.makedirs(REPORTS, exist_ok=True)
DB = os.path.join(DATA, "scans.db")
app = Flask(__name__, static_folder="../frontend", static_url_path="")
jobs = {}

def db():
    c = sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY,target TEXT,started TEXT,finished TEXT,status TEXT,findings INTEGER,report_path TEXT)")
    c.commit()
    return c
def save(row):
    c = db()
    c.execute("INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?)", row)
    c.commit()
    c.close()

def worker(sid,target,opts):
    try:
        s=Scanner(target,**opts); report=s.run(progress=lambda x:jobs[sid].update(x))
        path=os.path.join(REPORTS,sid+".json")
        with open(path,"w",encoding="utf-8") as f: json.dump(report,f,indent=2)
        jobs[sid].update({"status":"completed","report":report,"report_path":path,"finished":datetime.now(timezone.utc).isoformat()})
        save((sid,target,jobs[sid]["started"],jobs[sid]["finished"],"completed",report["summary"]["total"],path))
    except Exception as e:
        jobs[sid].update({"status":"failed","error":str(e),"finished":datetime.now(timezone.utc).isoformat()})
        save((sid,target,jobs[sid]["started"],jobs[sid]["finished"],"failed",0,""))

@app.route("/")
def index(): return send_from_directory(app.static_folder,"index.html")

@app.post("/api/scans")
def create():
    d=request.get_json(silent=True) or {}; target=str(d.get("target","")).strip()
    if not d.get("permission"): return jsonify(error="Authorization confirmation is required."),400
    if not target.startswith(("http://","https://")): return jsonify(error="Target must start with http:// or https://"),400
    sid=uuid.uuid4().hex[:12]; started=datetime.now(timezone.utc).isoformat()
    jobs[sid]={"id":sid,"target":target,"status":"running","started":started,"progress":0,"stage":"Starting"}
    opts={"delay":min(max(float(d.get("delay",.25)),0),5),"max_pages":min(max(int(d.get("max_pages",30)),1),200),
          "timeout":min(max(float(d.get("timeout",8)),1),30)}
    if IS_VERCEL:
        worker(sid, target, opts)
    else:
        threading.Thread(target=worker, args=(sid, target, opts), daemon=True).start()
    return jsonify(id=sid)

@app.get("/api/scans/<sid>")
def status(sid):
    if sid in jobs: return jsonify(jobs[sid])
    c=db(); r=c.execute("SELECT * FROM scans WHERE id=?",(sid,)).fetchone(); c.close()
    if not r: return jsonify(error="Scan not found"),404
    return jsonify(id=r[0],target=r[1],started=r[2],finished=r[3],status=r[4],findings=r[5])

@app.get("/api/scans")
def history():
    c=db(); rows=c.execute("SELECT id,target,started,finished,status,findings FROM scans ORDER BY started DESC LIMIT 25").fetchall(); c.close()
    return jsonify([dict(zip(["id","target","started","finished","status","findings"],r)) for r in rows])

@app.get("/api/scans/<sid>/report")
def report(sid):
    p=os.path.join(REPORTS,sid+".json")
    if not os.path.exists(p): return jsonify(error="Report not ready"),404
    return send_from_directory(REPORTS,sid+".json",as_attachment=True)

if __name__=="__main__":
    port = int(os.environ.get("PORT", 3000))
    db().close(); app.run(host="127.0.0.1", port=port, debug=False)
