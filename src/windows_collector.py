import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests
import win32evtlog
import win32con
import pywintypes

# API endpoint to send collected security logs
API_BASE = "http://localhost:8000/ingest-logs"

# Windows Security Event IDs to monitor:
# 4624 = Successful logon
# 4625 = Failed logon
# 4672 = Privileged logon
EVENT_FILTER = {4624, 4625, 4672}


def latest_record(handle):
    """
    Retrieve the most recent record number from the Windows Security Event Log.
    This is used to avoid reprocessing old log entries when the collector starts.
    """
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    recs = win32evtlog.ReadEventLog(handle, flags, 0)
    return recs[0].RecordNumber if recs else 0


def map_severity(eid, etype):
    """
    Map Windows Event ID and Event Type to a normalized severity level.
    This severity value is later used in the security analysis pipeline.
    """
    if eid == 4625:  # Failed logon attempt
        return "high"
    if eid == 4672:  # Privileged (administrator) logon
        return "critical"
    if eid == 4624:  # Successful logon
        return "medium"
    if etype in (win32con.EVENTLOG_ERROR_TYPE, win32con.EVENTLOG_AUDIT_FAILURE):
        return "high"
    return "low"


def map_category(eid):
    """
    Assign a high-level event category based on the Event ID.
    Authentication-related events are separated from general system events.
    """
    return "auth" if eid in (4624, 4625, 4672) else "system"


def convert_event(r):
    """
    Convert a raw Windows Event Log record into a normalized JSON-format
    event that can be processed by the detection pipeline.
    """
    eid = r.EventID & 0xFFFF
    ts = r.TimeGenerated.replace(tzinfo=timezone.utc).isoformat()

    # 'failed_attempts' field is used directly in detection rules
    failed = 1 if eid == 4625 else 0

    return {
        "id": f"win-{eid}-{r.RecordNumber}",           # Unique event ID
        "host": r.ComputerName or socket.gethostname(), # Source host name
        "severity": map_severity(eid, r.EventType),    # Normalized severity
        "category": map_category(eid),                 # Event category
        "@timestamp": ts,                              # UTC timestamp
        "source": f"windows_security",                 # Log source
        "failed_attempts": failed,                     # Failed login counter
        "event_id": eid,                               # Original Windows Event ID
        "record_number": r.RecordNumber,               # Windows log record number
    }


def send_batch(batch):
    """
    Send a batch of normalized events to the backend ingestion API.
    The API processes the events through the detection pipeline.
    """
    if not batch:
        return
    try:
        resp = requests.post(API_BASE, json=batch, timeout=10)
        js = resp.json()
        print(f"[collector] sent={len(batch)}  events={len(js.get('events', []))}  alerts={len(js.get('alerts', []))}")
    except Exception as e:
        print("[collector] send failed:", e)


def run_collector():
    """
    Main loop of the Windows Security Log collector.
    Continuously monitors new security events and forwards them
    to the backend detection system in near real-time.
    """
    try:
        handle = win32evtlog.OpenEventLog(None, "Security")
    except pywintypes.error as e:
        print("[collector] cannot open Security log:", e)
        print("관리자 권한 PowerShell에서 실행했는지 확인")
        return

    last = latest_record(handle)
    print(f"[collector] Watching Security log starting from #{last}")

    while True:
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        recs = win32evtlog.ReadEventLog(handle, flags, 0)
        batch = []

        if recs:
            for r in recs:
                eid = r.EventID & 0xFFFF

                # Filter only security-relevant events
                if eid not in EVENT_FILTER:
                    continue

                # Skip already processed records
                if r.RecordNumber <= last:
                    continue

                batch.append(convert_event(r))
                last = r.RecordNumber

        if batch:
            send_batch(batch)

        time.sleep(1)


if __name__ == "__main__":
    run_collector()
