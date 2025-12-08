import os
import sys
import time
import hashlib
import logging
from datetime import datetime
import csv

import requests
from dotenv import load_dotenv



load_dotenv()


MONITOR_DIR = os.getenv("MONITOR_DIR", "").strip()
SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", ""))

RESULTS_CSV = os.getenv("RESULTS_CSV", "fim_changes.csv")


JIRA_URL = os.getenv("JIRA_URL", "").strip()
JIRA_USER = os.getenv("JIRA_USER", "").strip()
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN", "").strip()
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY", "").strip()
JIRA_ISSUE_TYPE = os.getenv("JIRA_ISSUE_TYPE", "Task").strip()


config_errors = []

if not MONITOR_DIR:
    config_errors.append("MONITOR_DIR is not set in .env")

missing_jira = []
for name, value in [
    ("JIRA_URL", JIRA_URL),
    ("JIRA_USER", JIRA_USER),
    ("JIRA_API_TOKEN", JIRA_API_TOKEN),
    ("JIRA_PROJECT_KEY", JIRA_PROJECT_KEY),
]:
    if not value:
        missing_jira.append(name)

if missing_jira:
    config_errors.append("Missing Jira config in .env: " + ", ".join(missing_jira))

if config_errors:
    print("CONFIG ERROR:")
    for err in config_errors:
        print("  -", err)
    sys.exit(1)


logging.basicConfig(
    filename='fim.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def load_known_hashes():

    hashes = {}
    if not os.path.exists(RESULTS_CSV):
        return hashes

    try:
        with open(RESULTS_CSV, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                change_type = row.get("change_type")
                if change_type not in ("baseline", "added", "modified"):
                    continue
                file_path = row.get("file")
                new_hash = row.get("new_hash")
                if file_path and new_hash:
                    hashes[file_path] = new_hash
    except Exception as e:
        logging.error(f"Failed to load known hashes from {RESULTS_CSV}: {e}")

    return hashes



def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
    
        return None



def write_csv_record(event):
    fieldnames = ["timestamp", "change_type", "file", "new_hash"]
    file_exists = os.path.exists(RESULTS_CSV)

    try:
        with open(RESULTS_CSV, "a", newline="") as cf:
            writer = csv.DictWriter(cf, fieldnames=fieldnames)
            if not file_exists:
                writer.writeheader()

            writer.writerow({
                "timestamp": event.get("timestamp"),
                "change_type": event.get("change_type"),
                "file": event.get("file"),
                "new_hash": event.get("new_hash")
            })
    except Exception as e:
        logging.error(f"Failed to write CSV record: {e}")




def trigger_alert(change_type, file_path, old_hash, new_hash, timestamp):
    message = ( 
        f"[ALERT] {timestamp} | {change_type.upper()} | {file_path} | "
        f"old_hash={old_hash} | new_hash={new_hash}"
    )
    print(message)
    logging.warning(message)

def log_file_change(change_type, file_path, old_hash, new_hash, timestamp):
    log_data = {
        "timestamp": timestamp,
        "change_type": change_type,
        "file": file_path,
        "old_hash": old_hash,
        "new_hash": new_hash
    }

    logging.info(f"FIM_EVENT: {log_data}")

    
    write_csv_record(log_data)



def build_jira_payload(change_type, file_path, old_hash, new_hash, timestamp):
    summary = f"[FIM] {change_type.upper()} detected for {file_path}"

    description = (
        "File Integrity Monitoring Alert:\n\n"
        f"*Change Type:* {change_type}\n"
        f"*File:* {file_path}\n"
        f"*Old Hash:* {old_hash}\n"
        f"*New Hash:* {new_hash}\n"
        f"*Detected At:* {timestamp}\n\n"
        "Please investigate."
    )

    return {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": summary,
            "description": description,
            "issuetype": {"name": JIRA_ISSUE_TYPE},
            "labels": ["FIM", "security"]
        }
    }

def create_jira_issue(payload):
    try:
        r = requests.post(
            f"{JIRA_URL}/rest/api/2/issue",
            json=payload,
            auth=(JIRA_USER, JIRA_API_TOKEN),
            headers={"Content-Type": "application/json"}
        )
        if r.status_code not in (200, 201):
            print(f"Jira error: {r.status_code} - {r.text}")
            logging.error(f"Jira error: {r.status_code} - {r.text}")
            return None

        data = r.json()
        issue_key = data.get("key")
        print("Jira issue created:", issue_key)
        logging.info(f"Jira issue created: {issue_key}")
        return issue_key

    except Exception as e:
        print("Jira connection error:", e)
        logging.error(f"Jira connection error: {e}")
        return None



def handle_detected_changes(changes):
    for change in changes:
        timestamp = datetime.utcnow().isoformat()
        change_type = change["type"]
        file_path = change["path"]
        old_hash = change.get("old_hash")
        new_hash = change.get("new_hash")

        log_file_change(change_type, file_path, old_hash, new_hash, timestamp)
        trigger_alert(change_type, file_path, old_hash, new_hash, timestamp)

        payload = build_jira_payload(change_type, file_path, old_hash, new_hash, timestamp)
        create_jira_issue(payload)



def scan_directory(path, known_hashes):
    changes = []

    # Detect new or modified files
    for root, dirs, files in os.walk(path):
        for name in files:
            full_path = os.path.join(root, name)
            new_hash = calculate_hash(full_path)
            if new_hash is None:
                continue

            old_hash = known_hashes.get(full_path)

            if old_hash is None:
                changes.append({
                    "type": "added",
                    "path": full_path,
                    "old_hash": None,
                    "new_hash": new_hash
                })
            elif old_hash != new_hash:
                changes.append({
                    "type": "modified",
                    "path": full_path,
                    "old_hash": old_hash,
                    "new_hash": new_hash
                })

            known_hashes[full_path] = new_hash

    
    existing_paths = {
        os.path.join(root, name)
        for root, dirs, files in os.walk(path)
        for name in files
    }

    removed = [p for p in list(known_hashes.keys()) if p not in existing_paths]

    for p in removed:
        changes.append({
            "type": "removed",
            "path": p,
            "old_hash": known_hashes[p],
            "new_hash": None
        })
        del known_hashes[p]

    return changes



def main():
    if not os.path.isdir(MONITOR_DIR):
        print("Monitor directory does not exist:", MONITOR_DIR)
        sys.exit(1)

    print("Starting FIM on:", MONITOR_DIR)
    print("Scan interval:", SCAN_INTERVAL_SECONDS, "seconds")

   
    known_hashes = load_known_hashes()

    print("Initial scan...")
    initial_changes = scan_directory(MONITOR_DIR, known_hashes)
    initial_changes = [c for c in initial_changes if c["type"] != "removed"]
    
    if not os.path.exists(RESULTS_CSV) or os.path.getsize(RESULTS_CSV) == 0:
        
        for path, h in known_hashes.items():
            baseline_event = {
                "timestamp": datetime.utcnow().isoformat(),
                "change_type": "baseline",
                "file": path,
                "old_hash": None,
                "new_hash": h
            }
            write_csv_record(baseline_event)
        print("Baseline created in CSV.")
    else:
        
        if initial_changes:
            print("Handling initial detected changes")
            handle_detected_changes(initial_changes)
        else:
            print("Initial scan: no changes.")

    print("Monitoring ")
    while True:
        time.sleep(SCAN_INTERVAL_SECONDS)
        scan_time = datetime.utcnow().isoformat()
        print(f"\n Scan started at {scan_time} ")

        changes = scan_directory(MONITOR_DIR, known_hashes)
        if changes:
            print(len(changes), "change(s) detected.")
            handle_detected_changes(changes)
        else:
            print("No changes detected.")

if __name__ == "__main__":
    main()
