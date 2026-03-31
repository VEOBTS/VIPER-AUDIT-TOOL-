import os
import zipfile
import shutil
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, request, send_file, jsonify
from flask_cors import CORS
from database import init_db, get_connection
from viper import run_scan

load_dotenv()

app = Flask(__name__)
app.secret_key = "viper-secret-key-change-this"
CORS(app)

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
ALLOWED_EXTENSIONS = {"move", "zip", "toml"}

SEVERITY_MAP = {
    "public_internal_set_balance":     "critical",
    "entry_mutation_no_perm":          "critical",
    "public_entry_burn_without_check": "critical",
    "struct_missing_has_key":          "high",
    "init_no_guard":                   "high",
    "oracle_no_sig_validation":        "high",
    "dynamic_field_unchecked":         "medium",
    "singleton_weak_init":             "medium",
}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def build_scan_dict(scan, findings_rows):
    critical = sum(1 for f in findings_rows if SEVERITY_MAP.get(f["rule"]) == "critical")
    high     = sum(1 for f in findings_rows if SEVERITY_MAP.get(f["rule"]) == "high")
    medium   = sum(1 for f in findings_rows if SEVERITY_MAP.get(f["rule"]) == "medium")
    low      = sum(1 for f in findings_rows if SEVERITY_MAP.get(f["rule"]) == "low")
    return {
        "id":             scan["id"],
        "filename":       scan["filename"],
        "scanned_at":     scan["scanned_at"],
        "total_findings": scan["total_findings"],
        "report_path":    scan["report_path"],
        "status":         "clean" if scan["total_findings"] == 0 else "findings",
        "critical_count": critical,
        "high_count":     high,
        "medium_count":   medium,
        "low_count":      low,
    }

# ── API: all scans ─────────────────────────────────────────────────────────
@app.route("/api/scans")
def api_scans():
    conn = get_connection()
    scans = conn.execute("SELECT * FROM scans ORDER BY scanned_at DESC").fetchall()
    result = []
    for scan in scans:
        findings = conn.execute(
            "SELECT rule FROM findings WHERE scan_id = ?", (scan["id"],)
        ).fetchall()
        result.append(build_scan_dict(scan, findings))
    conn.close()
    return jsonify(result)

# ── API: single scan ───────────────────────────────────────────────────────
@app.route("/api/scans/<int:scan_id>")
def api_scan_detail(scan_id):
    conn = get_connection()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    findings = conn.execute(
        "SELECT rule FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    result = build_scan_dict(scan, findings)
    conn.close()
    return jsonify(result)

# ── API: findings for a scan ───────────────────────────────────────────────
@app.route("/api/scans/<int:scan_id>/findings")
def api_findings(scan_id):
    conn = get_connection()
    findings = conn.execute(
        "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
    ).fetchall()
    conn.close()
    return jsonify([{
        "id":       f["id"],
        "scan_id":  f["scan_id"],
        "file":     f["file"],
        "rule":     f["rule"],
        "message":  f["message"],
        "severity": SEVERITY_MAP.get(f["rule"], "info"),
    } for f in findings])

# ── API: dashboard stats ───────────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    conn = get_connection()
    scans        = conn.execute("SELECT * FROM scans").fetchall()
    all_findings = conn.execute("SELECT rule FROM findings").fetchall()
    conn.close()

    total_scans       = len(scans)
    total_findings    = sum(s["total_findings"] for s in scans)
    clean_scans       = sum(1 for s in scans if s["total_findings"] == 0)
    critical_rules    = {"public_internal_set_balance", "entry_mutation_no_perm", "public_entry_burn_without_check"}
    critical_findings = sum(1 for f in all_findings if f["rule"] in critical_rules)
    score = 100 if total_findings == 0 else max(10, 100 - critical_findings * 15 - (total_findings - critical_findings) * 5)

    return jsonify({
        "total_scans":       total_scans,
        "total_findings":    total_findings,
        "critical_findings": critical_findings,
        "clean_scans":       clean_scans,
        "security_score":    score,
    })

# ── API: upload + scan ─────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
def api_scan_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Only .move, .toml, or .zip files allowed"}), 400

    timestamp   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_name   = f"{timestamp}_{file.filename}"
    upload_path = os.path.join(UPLOAD_FOLDER, safe_name)
    file.save(upload_path)

    if file.filename.endswith(".zip"):
        extract_dir = os.path.join(UPLOAD_FOLDER, f"{timestamp}_extracted")
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(upload_path, "r") as z:
            z.extractall(extract_dir)
        scan_target = extract_dir
    else:
        single_dir = os.path.join(UPLOAD_FOLDER, f"{timestamp}_single")
        os.makedirs(single_dir, exist_ok=True)
        shutil.copy(upload_path, single_dir)
        scan_target = single_dir

    report_filename = f"report_{timestamp}.txt"
    report_path     = os.path.join(REPORT_FOLDER, report_filename)
    findings        = run_scan(scan_target, report_path)

    conn   = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (filename, scanned_at, total_findings, report_path) VALUES (?, ?, ?, ?)",
        (file.filename, datetime.utcnow().isoformat(), len(findings), report_path)
    )
    scan_id = cursor.lastrowid
    for f in findings:
        cursor.execute(
            "INSERT INTO findings (scan_id, file, rule, message) VALUES (?, ?, ?, ?)",
            (scan_id, f.get("file", ""), f.get("rule", ""), f.get("message", ""))
        )
    conn.commit()
    conn.close()

    return jsonify({"scan_id": scan_id, "total_findings": len(findings)})

# ── Download raw report .txt ───────────────────────────────────────────────
@app.route("/download/<int:scan_id>")
def download(scan_id):
    conn = get_connection()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if scan and os.path.exists(scan["report_path"]):
        return send_file(scan["report_path"], as_attachment=True)
    return jsonify({"error": "Report not found"}), 404

# ── Startup ────────────────────────────────────────────────────────────────
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)
init_db()

if __name__ == "__main__":
    app.run(debug=True)