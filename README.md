# FIM
file integrity monitor 
<img width="1024" height="1024" alt="Gemini_Generated_Image_8s63xt8s63xt8s63" src="https://github.com/user-attachments/assets/d2950783-1d51-4a5c-ad8a-3d6598b0ba91" />
<img width="1440" height="900" alt="jira2" src="https://github.com/user-attachments/assets/a3c3d165-679b-4911-806c-c35ecfe420e8" />
# File Integrity Monitoring (FIM) Script

A lightweight Python File Integrity Monitoring (FIM) script that scans a directory tree, computes SHA-256 hashes of files, detects added/modified/removed files, writes events to a CSV log, logs to `fim.log`, prints alerts to stdout, and can create Jira issues for detected changes.

---

## Table of contents

* [Features](#features)
* [Prerequisites](#prerequisites)
* [Files](#files)
* [Configuration (.env)](#configuration-env)
* [Installation](#installation)
* [Usage](#usage)
* [CSV output format](#csv-output-format)
* [Logging](#logging)
* [Jira integration](#jira-integration)
* [Behavior details](#behavior-details)
* [Troubleshooting & common fixes](#troubleshooting--common-fixes)
* [Extending the script](#extending-the-script)
* [License](#license)

---

## Features

* Recursively scans a configured directory and computes SHA-256 hashes for files.
* Detects `added`, `modified`, and `removed` file events.
* Persists a human-readable CSV (`fim_changes.csv` by default) containing a history of events.
* Writes structured logs to `fim.log` and prints alerts on the console.
* Optional Jira issue creation for every detected change.
* Configurable scan interval and monitored directory via environment variables.

## Prerequisites

* Python 3.8+ recommended.
* `pip` available to install dependencies.

Required Python packages (the script imports):

* `requests`
* `python-dotenv`

Install dependencies:

```bash
pip install -r requirements.txt
# or
pip install requests python-dotenv
```

## Files

* `fim.py` (the main script)
* `.env` (environment configuration file; **not** checked into source control)
* `fim_changes.csv` (generated/appended by the script to store events)
* `fim.log` (script log file)

## Configuration (.env)

Create a `.env` file in the same directory as the script with the following variables. Example and explanation included.

```
# Directory to monitor (absolute or relative path)
MONITOR_DIR=/path/to/monitor

# Number of seconds between scans (integer)
SCAN_INTERVAL_SECONDS=30

# Path to CSV file that stores events (default: fim_changes.csv)
RESULTS_CSV=fim_changes.csv

# Jira configuration (optional, but if any Jira var is missing the script will exit)
JIRA_URL=https://your-jira-instance.atlassian.net
JIRA_USER=your.email@example.com
JIRA_API_TOKEN=your_api_token_here
JIRA_PROJECT_KEY=PROJ
JIRA_ISSUE_TYPE=Task
```

**Notes**

* If `MONITOR_DIR` or any required Jira variable is missing, the script prints a configuration error and exits. Make sure `.env` is valid.
* If you don’t want Jira integration, you can still provide *dummy* values or modify the script to make Jira optional.

## Usage

1. Ensure `.env` is configured and dependencies installed.
2. Start the script:

```bash
python3 fim.py
```

The script performs an initial scan. If `fim_changes.csv` does not exist or is empty, a `baseline` entry for each discovered file will be written to the CSV. On subsequent runs it will detect `added`, `modified`, and `removed` events.

### Example run output

* `Baseline created in CSV.` — first-time baseline saved.
* `Handling initial detected changes` — if initial scan found changes compared to existing CSV.
* During monitoring, you will see alert lines like:

```
[ALERT] 2025-12-08T12:00:00 | MODIFIED | /path/to/file.txt | old_hash=... | new_hash=...
```

## CSV output format

The CSV (default `fim_changes.csv`) is appended to over time and contains the following columns (header written on first creation):

* `timestamp` — ISO8601 UTC time when the event was recorded.
* `change_type` — one of: `baseline`, `added`, `modified` (the code also creates `removed` internally but the CSV writer only records baseline/added/modified entries by default behavior; see "Behavior details" below).
* `file` — absolute path to the file.
* `new_hash` — SHA-256 hex digest for the file at the time of the event.

> Tip: If you need `old_hash` in the CSV as well, see "Extending the script".

## Logging

* `fim.log` contains structured INFO/WARNING entries for events and any errors encountered.
* Alerts are printed to stdout and duplicated to `fim.log` at the `WARNING` level.

## Jira integration

When a change is detected the script builds a Jira issue payload and posts it to `${JIRA_URL}/rest/api/2/issue` using basic auth with `JIRA_USER` and `JIRA_API_TOKEN`.

If Jira returns a non-2xx status code the script logs the error and prints the response.

**Security note:** Store `JIRA_API_TOKEN` securely. Avoid committing `.env` to source control.

## Behavior details & important implementation notes

* On startup the script loads known hashes from `RESULTS_CSV`. It only reads rows that include `change_type` values `baseline`, `added`, or `modified`.
* The script treats every file discovered during the initial scan as a `baseline` entry **only if** the CSV file does not exist or is empty. If a CSV already exists, the initial scan is compared against the known CSV hashes and any differences are treated as `added` or `modified` events.
* The current CSV writer uses `fieldnames = ["timestamp", "change_type", "file", "new_hash"]` and writes only those fields. The in-memory `known_hashes` dictionary stores file→hash mappings used as the authoritative state during runtime.
* When files are removed the script appends a `removed` event to the `changes` list but the CSV writer currently does not include `removed` events by default (the script's `load_known_hashes` ignores other change types). If you want `removed` entries in CSV, modify the `write_csv_record` `fieldnames` and the code paths that call it.

## Troubleshooting & common fixes

* **Script exits with `CONFIG ERROR`** — check `.env` and ensure `MONITOR_DIR` and Jira variables are set as required by the script. If you want Jira optional, change the script to skip the Jira checks.
* **`Monitor directory does not exist`** — confirm the `MONITOR_DIR` path is correct and accessible to the user running the script.
* **Large directories cause high CPU/disk I/O** — increase `SCAN_INTERVAL_SECONDS` or scope `MONITOR_DIR` to a smaller subtree.
* **Permissions errors reading files** — run the script with a user that has read access to all files you wish to monitor or selectively exclude unreadable paths.
* **You see repeated `modified` events for unchanged files** — check for processes that rewrite files (touch, editors, atomic write patterns). Also verify your environment isn’t normalizing line endings differently between runs.

## Extending the script (ideas)

* Persist `old_hash` into the CSV so each event records both old and new values.
* Add an optional HMAC/signature to the CSV header to detect tampering with the CSV itself.
* Make Jira integration optional via a `ENABLE_JIRA=true/false` env var.
* Add file glob excludes, size limits, or ignore patterns for temporary files.
* Add unit tests and a systemd/service unit to run the script as a daemon.

## Example `.env` (sanitized)

```
MONITOR_DIR=/home/fim/monitor
SCAN_INTERVAL_SECONDS=60
RESULTS_CSV=fim_changes.csv
JIRA_URL=https://your-jira.atlassian.net
JIRA_USER=you@example.com
JIRA_API_TOKEN=xxxxxxxxxxxxxxxxxxxx
JIRA_PROJECT_KEY=SEC
JIRA_ISSUE_TYPE=Task
```

## License

This script is provided as-is under no explicit license. Add a license file (e.g., MIT) if you plan to publish it.

---

If you want, I can:

* produce a shorter `README.md` suitable for including in a Git repo;
* generate a sample `.env` file and a `requirements.txt`;
* modify the script to make Jira optional or to include `removed` events in the CSV.

Tell me which of those you'd like next and I’ll add it directly.
