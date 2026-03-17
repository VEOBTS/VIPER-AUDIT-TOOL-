import os
import zipfile
import shutil
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from database import init_db, get_connection
from viper import run_scan

app = Flask(__name__)
app.secret_key = "viper-secret-key-change-this"  # needed for flash messages

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
ALLOWED_EXTENSIONS = {"move", "zip", "toml"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ── Home page: upload form + scan history ──────────────────────────────────
@app.route("/")
def index():
    conn = get_connection()
    scans = conn.execute(
        "SELECT * FROM scans ORDER BY scanned_at DESC"
    ).fetchall()
    conn.close()
    return render_template("index.html", scans=scans)

# ── Handle file upload and trigger scan ───────────────────────────────────
@app.route("/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        flash("No file uploaded.")
        return redirect(url_for("index"))

    file = request.files["file"]

    if file.filename == "":
        flash("No file selected.")
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        flash("Only .move, .toml, or .zip files are allowed.")
        return redirect(url_for("index"))

    # Save the uploaded file
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_name = f"{timestamp}_{file.filename}"
    upload_path = os.path.join(UPLOAD_FOLDER, safe_name)
    file.save(upload_path)

    # If it's a zip, extract it to a subfolder
    if file.filename.endswith(".zip"):
        extract_dir = os.path.join(UPLOAD_FOLDER, f"{timestamp}_extracted")
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(upload_path, "r") as z:
            z.extractall(extract_dir)
        scan_target = extract_dir
    else:
        # Single file — put it in its own folder so viper can walk it
        single_dir = os.path.join(UPLOAD_FOLDER, f"{timestamp}_single")
        os.makedirs(single_dir, exist_ok=True)
        shutil.copy(upload_path, single_dir)
        scan_target = single_dir

    # Define where the report goes
    report_filename = f"report_{timestamp}.txt"
    report_path = os.path.join(REPORT_FOLDER, report_filename)

    # Run the scan
    findings = run_scan(scan_target, report_path)

    # Save scan + findings to SQLite
    conn = get_connection()
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

    return redirect(url_for("results", scan_id=scan_id))

# ── Results page for a specific scan ──────────────────────────────────────
@app.route("/results/<int:scan_id>")
def results(scan_id):
    conn = get_connection()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    findings = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
    conn.close()

    if not scan:
        flash("Scan not found.")
        return redirect(url_for("index"))

    return render_template("results.html", scan=scan, findings=findings)

# ── Download raw report .txt ───────────────────────────────────────────────
@app.route("/download/<int:scan_id>")
def download(scan_id):
    conn = get_connection()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if scan and os.path.exists(scan["report_path"]):
        return send_file(scan["report_path"], as_attachment=True)
    flash("Report file not found.")
    return redirect(url_for("index"))

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)
init_db()

# ── App entry point ────────────────────────────────────────────────────────
if __name__ == "__main__":

    app.run(debug=True)