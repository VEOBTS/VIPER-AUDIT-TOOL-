#!/usr/bin/env python3
"""
Viper - Simple Move/Sui heuristic auditor (by Demeji)
Usage:
  python viper_scan.py /path/to/move/package --output report.txt [--csv] [--online]

Notes:
 - This is a heuristic scanner (regex + simple body parsing). It will have false positives/negatives.
 - Use --online to attempt fetching extra heuristic hints from community/security pages (optional).
"""

import os, sys, re, argparse, json, csv, time
from datetime import datetime

try:
    import pyfiglet
except Exception:
    pyfiglet = None

# Optional online fetching
try:
    import requests
except Exception:
    requests = None

# ------------------ banner & helpers ------------------
BANNER_TEXT = "VIPER"
BANNER_BY = "by DEMEJI"

DEFAULT_OUTPUT = "viper_report.txt"

def print_banner_to_file(f):
    if pyfiglet:
        f.write(pyfiglet.figlet_format(BANNER_TEXT) + "\n")
    else:
        f.write("== VIPER ==\n")
    f.write(f"{BANNER_BY}\n")
    f.write(f"Scan time: {datetime.utcnow().isoformat()} UTC\n")
    f.write("="*60 + "\n\n")

def short_summary_line(msg):
    # Only used for terminal summary; main output goes to report file
    print(msg)

# ------------------ find files ------------------
def collect_move_files(root):
    files = []
    for r, dirs, fns in os.walk(root):
        for fn in fns:
            if fn.endswith(".move") or fn.lower() in ("move.toml", "move_manifest.toml", "move-package.toml"):
                files.append(os.path.join(r, fn))
    return sorted(files)

# ------------------ simple parser helpers ------------------
def read_text(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except Exception as e:
        return ""

def find_structs(src):
    """Find basic struct declarations and whether 'has key' is present."""
    out = []
    # naive struct matcher: struct Name [has key] { ... }
    for m in re.finditer(r'\bstruct\s+([A-Za-z_]\w*)(?:\s+has\s+key)?', src):
        name = m.group(1)
        has_key = bool(re.search(r'\bstruct\s+' + re.escape(name) + r'\s+has\s+key', src[m.start():m.start()+128]))
        # extract body by brace counting
        brace_pos = src.find("{", m.end())
        if brace_pos == -1:
            body = ""
        else:
            i = brace_pos
            depth = 0
            while i < len(src):
                if src[i] == "{":
                    depth += 1
                elif src[i] == "}":
                    depth -= 1
                    if depth == 0:
                        body = src[brace_pos+1:i]
                        break
                i += 1
            else:
                body = ""
        out.append({"name": name, "has_key": has_key, "fields": body})
    return out

def find_functions(src):
    """Find 'entry fun' and 'public fun' definitions with params and bodies (naive)."""
    funcs = []
    for m in re.finditer(r'\b(entry|public)\s+fun\s+([A-Za-z_]\w*)\s*\(', src):
        kind = m.group(1)
        name = m.group(2)
        # find parameter block
        start = m.end()-1
        i = start
        depth = 0
        end_params = None
        while i < len(src):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
                if depth == 0:
                    end_params = i
                    break
            i += 1
        params_text = src[start+1:end_params] if end_params else ""
        # find body block
        brace_pos = src.find("{", end_params or start)
        if brace_pos == -1:
            continue
        j = brace_pos
        depth = 0
        body = ""
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    body = src[brace_pos+1:j]
                    break
            j += 1
        funcs.append({"kind": kind, "name": name, "params": params_text.strip(), "body": body})
    return funcs

# ------------------ heuristic rules (based on your list) ------------------
BUILT_IN_RULES = [
    # rule id, short message, checker function (file_src, structs, funcs) -> list of messages
    ("struct_missing_has_key",
     "Struct contains 'id: UID' but missing 'has key'",
     lambda src, structs, funcs: [
         f"Struct '{s['name']}' has 'id: UID' but no 'has key'." 
         for s in structs
         if re.search(r'\bid\s*:\s*(?:UID|object::UID)\b', s.get("fields","")) and not s.get("has_key", False)
     ]),
    ("public_internal_set_balance",
     "Public mutation function that should be private",
     lambda src, structs, funcs: [
         f"Public function '{f['name']}' mutates a resource but may be overly visible (check if should be private)." 
         for f in funcs 
         if f['kind']=="public" and re.search(r'\b:\s*&?mut\b|\&mut', f['params'] + f['body']) and not re.search(r'\bassert\s*\(|\bsender\s*\(|\babort\s*\(', f['body'])
     ]),
    ("entry_mutation_no_perm",
     "Entry function mutates resources with no permission validation",
     lambda src, structs, funcs: [
         f"Entry '{f['name']}' takes &mut and lacks sender/assert checks. Verify access control." 
         for f in funcs
         if f['kind']=="entry" and re.search(r'&mut', f['params']) and not re.search(r'\bsender\s*\(|\bassert\s*\(|\bassert!\s*\(|\babort\s*\(', f['body'])
     ]),
    ("public_entry_burn_without_check",
     "Public entry burn/delete with no ownership check",
     lambda src, structs, funcs: (
         ["Function uses object::delete or object::destroy without ownership/assert checks"]
         if re.search(r'\bobject::delete\b|\bobject::destroy\b|\bmove_to\b', src) and not re.search(r'\bsender\s*\(|\bassert\s*\(|\bassert!\s*\(', src)
         else []
     )),
    ("init_no_guard",
     "Init or public entry creates shared object without guard (possible reinit / init race)",
     lambda src, structs, funcs: [
         "Module has entry/init that constructs and share_object/move_to without init-guards or capability checks"
     ] if re.search(r'\bshare_object\b|\btransfer::share_object\b', src) and re.search(r'\bentry\s+fun\s+init\b|\binit\s*\(|\bpublic\s+entry\s+fun\s+init\b', src) else []
    ),
    ("dynamic_field_unchecked",
     "Dynamic field access/remove without signer/ownership check",
     lambda src, structs, funcs: [
         "dynamic_field::remove or direct dynamic_field access found — ensure signer/owner verified"
     ] if re.search(r'dynamic_field::remove|dynamic_field::borrow', src) and not re.search(r'\baddress_of\s*\(|\bsigner\b', src) else []
    ),
    ("oracle_no_sig_validation",
     "Oracle update uses signatures without cryptographic validation",
     lambda src, structs, funcs: [
         "Oracle update found that checks only signature count or length — ensure signatures are validated"
     ] if re.search(r'\bvector::length\(&signatures\)|signatures', src) and re.search(r'price|oracle', src, re.I) else []
    ),
    ("singleton_weak_init",
     "Singleton init allows reinitialization",
     lambda src, structs, funcs: [
         "Module allows reinitialization/overwriting of singleton global state — add assert to prevent reinit"
     ] if re.search(r'\bexists<.+>\(|borrow_global_mut<', src) and re.search(r'if\s*\(|else', src) else []
    )
]

# ------------------ optional online patterns (simple) ------------------
ONLINE_SOURCES = [
    # light set of pages that discuss Move/Sui security (used only for heuristics / notes)
    "https://sui.io/security",
    "https://github.com/slowmist/Sui-MOVE-Smart-Contract-Auditing-Primer",
    "https://movebit.xyz/blog/post/Sui-Objects-Security-Principles-and-Best-Practices.html"
]

def fetch_online_rules():
    hints = []
    if requests is None:
        return ["requests not installed; skipping online fetch."]
    for url in ONLINE_SOURCES:
        try:
            r = requests.get(url, timeout=8)
            if r.status_code == 200:
                # keep short snippet for report (no heavy scraping)
                txt = re.sub(r'\s+', ' ', r.text)[:800]
                hints.append(f"Fetched {url} (snippet): {txt[:300]}...")
            else:
                hints.append(f"Could not fetch {url}: status {r.status_code}")
        except Exception as e:
            hints.append(f"Error fetching {url}: {e}")
    return hints

# ------------------ main audit per file ------------------
def audit_file(path, do_online=False):
    src = read_text(path)
    structs = find_structs(src)
    funcs = find_functions(src)
    findings = []
    for rule_id, msg, checker in BUILT_IN_RULES:
        try:
            res = checker(src, structs, funcs)
            for r in res:
                findings.append({"rule": rule_id, "msg": r})
        except Exception as e:
            findings.append({"rule": rule_id, "msg": f"Checker error: {e}"})
    # optional online notes per file
    online_notes = []
    if do_online:
        online_notes = fetch_online_rules()
    return findings, online_notes

# ------------------ runner ------------------
def run_scan(root, out_path, csv_out=None, do_online=False):
    files = collect_move_files(root)
    report_entries = []
    with open(out_path, "w", encoding="utf-8") as fout:
        print_banner_to_file(fout)
        fout.write(f"Scanned path: {root}\n")
        fout.write(f"Found {len(files)} Move-related files\n\n")
        for p in files:
            fout.write(f"--- FILE: {p}\n")
            src = read_text(p)
            findings, online_notes = audit_file(p, do_online=do_online)
            if not findings:
                fout.write("No heuristic issues found (quick scan)\n\n")
            else:
                for f in findings:
                    fout.write(f"- {f['rule']}: {f['msg']}\n")
                    report_entries.append({"file": p, "rule": f['rule'], "message": f['msg']})
                fout.write("\n")
            if online_notes:
                fout.write("Online notes:\n")
                for n in online_notes:
                    fout.write(f"  * {n}\n")
                fout.write("\n")
        fout.write("\nScan finished.\n")
    short_summary_line(f"Wrote report: {out_path}")
    if csv_out:
        with open(csv_out, "w", newline='', encoding="utf-8") as cf:
            writer = csv.DictWriter(cf, fieldnames=["file","rule","message"])
            writer.writeheader()
            for r in report_entries:
                writer.writerow(r)
        short_summary_line(f"Wrote csv: {csv_out}")

# ------------------ CLI ------------------
def main_cli():
    p = argparse.ArgumentParser(prog="viper_scan", description="Viper - simple Move/Sui heuristic auditor")
    p.add_argument("path", help="path to Move package or folder")
    p.add_argument("--output", "-o", default=DEFAULT_OUTPUT, help="output TXT report file")
    p.add_argument("--csv", help="optional CSV output path")
    p.add_argument("--online", action="store_true", help="attempt to fetch extra heuristics/notes from web")
    args = p.parse_args()
    root = args.path
    if not os.path.exists(root):
        print("Path not found:", root)
        sys.exit(1)
    run_scan(root, args.output, csv_out=args.csv, do_online=args.online)

if __name__ == "__main__":
    main_cli()
