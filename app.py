# app.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import json
from pathlib import Path
from collections import Counter
import sqlite3
from datetime import datetime, timezone
import hashlib
import os
from fastapi import File, UploadFile
import shutil

BASE_DIR = Path(__file__).resolve().parent
REPORT_PATH = BASE_DIR / "report.json"
DB_PATH = BASE_DIR / "reviews.db"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# ensure folders exist
STATIC_DIR.mkdir(exist_ok=True)
TEMPLATES_DIR.mkdir(exist_ok=True)

# init app
app = FastAPI()
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# --- DB helpers ---
def get_db_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS reviewed_issues (
            id TEXT PRIMARY KEY,
            entity_type TEXT,
            entity_name TEXT,
            policy_name TEXT,
            issue_type TEXT,
            resource TEXT,
            reviewed_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()

init_db()

# --- utility: unique id for an issue ---
def make_issue_id(entity_type, entity_name, policy_name, issue_type, resource):
    # deterministic hash string; use sha1 for brevity
    seed = f"{entity_type}|{entity_name}|{policy_name}|{issue_type}|{resource}"
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()

def load_report():
    if not REPORT_PATH.exists():
        return {"findings": []}
    with open(REPORT_PATH, "r") as f:
        return json.load(f)

def get_reviewed_ids():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM reviewed_issues")
    rows = cur.fetchall()
    conn.close()
    return set(r["id"] for r in rows)

def mark_reviewed_in_db(issue_id, entity_type, entity_name, policy_name, issue_type, resource):
    conn = get_db_conn()
    cur = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    try:
        cur.execute(
            """
            INSERT INTO reviewed_issues (id, entity_type, entity_name, policy_name, issue_type, resource, reviewed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (issue_id, entity_type, entity_name, policy_name, issue_type, resource, now),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # already exists
        pass
    finally:
        conn.close()

# --- Routes ---
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    report = load_report()
    findings = report.get("findings", [])

    # compute issue ids and whether reviewed
    reviewed_ids = get_reviewed_ids()

    enriched = []
    for f in findings:
        entity = f.get("entity", {})
        policy_name = f.get("policy_name") or ""
        policy_type = f.get("policy_type") or ""
        for issue in f.get("issues", []):
            issue_type = issue.get("issue_type", "")
            # resource might be missing in some issue types
            resource = issue.get("resource") or str(issue.get("statement") or "")
            entity_type = entity.get("type", "")
            entity_name = entity.get("name", "")
            issue_id = make_issue_id(entity_type, entity_name, policy_name, issue_type, resource)
            is_reviewed = issue_id in reviewed_ids
            enriched.append({
                "id": issue_id,
                "entity_type": entity_type,
                "entity_name": entity_name,
                "policy_name": policy_name,
                "policy_type": policy_type,
                "issue_type": issue_type,
                "resource": resource,
                "is_reviewed": is_reviewed,
                "raw_issue": issue,
                "raw_policy": f.get("policy_document"),
            })

    # summary counts
    total_entities = len({ (f.get('entity',{}).get('type'), f.get('entity',{}).get('name')) for f in findings })
    total_issues = len(enriched)
    total_reviewed = sum(1 for f in enriched if f["is_reviewed"]) or 0

    # define 'critical' - we treat wildcard_action as critical; you can expand this list
    critical_types = {"wildcard_action", "wildcard_resource"}
    critical_count = sum(1 for e in enriched if e["issue_type"] in critical_types)
    reviewed_count = sum(1 for e in enriched if e["is_reviewed"])

    # pie chart data: counts by entity type (role/user/group)
    entity_types = [e.get("entity_type") for e in enriched]
    type_counts = Counter(entity_types)
    summary_labels = list(type_counts.keys())
    summary_values = list(type_counts.values())

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "findings": enriched,
            "summary_labels": summary_labels,
            "summary_values": summary_values,
            "total_entities": total_entities,
            "total_issues": total_issues,
            "critical_count": critical_count,
            "reviewed_count": reviewed_count,
            "total_reviewed": total_reviewed
        },
    )

@app.post("/review")
async def review_issue(payload: dict):
    """
    Expects JSON: { "id": "<issue_id>", "entity_type": "...", "entity_name": "...",
                    "policy_name": "...", "issue_type": "...", "resource": "..." }
    """
    required = ["id","entity_type","entity_name","policy_name","issue_type","resource"]
    if not all(k in payload for k in required):
        raise HTTPException(status_code=400, detail="missing keys")
    # store in DB
    mark_reviewed_in_db(
        payload["id"],
        payload["entity_type"],
        payload["entity_name"],
        payload["policy_name"],
        payload["issue_type"],
        payload["resource"],
    )
    return JSONResponse({"status": "ok", "id": payload["id"]})

@app.post("/upload-report")
async def upload_report(report: UploadFile = File(...)):
    if not report.filename.endswith(".json"):
        return JSONResponse({"error": "Invalid file type"}, status_code=400)
    
    report_path = BASE_DIR / "report.json"
    with report_path.open("wb") as f:
        shutil.copyfileobj(report.file, f)
    
    return JSONResponse({"status": "ok"})


# optional: endpoint to list reviewed items (for debugging)
@app.get("/reviewed")
async def list_reviewed():
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM reviewed_issues ORDER BY reviewed_at DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"reviewed": rows}

if __name__ == "__main__":
    import uvicorn
    print("Starting app, DB at:", DB_PATH)
    uvicorn.run(app, host="0.0.0.0", port=8000)
