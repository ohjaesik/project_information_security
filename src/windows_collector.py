import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests
import win32evtlog
import win32con
import pywintypes

API_BASE = "http://localhost:8000/ingest-logs"

EVENT_FILTER = {4624, 4625, 4672}


def latest_record(handle):
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    recs = win32evtlog.ReadEventLog(handle, flags, 0)
    return recs[0].RecordNumber if recs else 0


def map_severity(eid, etype):
    if eid == 4625:  # failed logon
        return "high"
    if eid == 4672:  # privilege logon
        return "critical"
    if eid == 4624:  # login success
        return "medium"
    if etype in (win32con.EVENTLOG_ERROR_TYPE, win32con.EVENTLOG_AUDIT_FAILURE):
        return "high"
    return "low"


def map_category(eid):
    return "auth" if eid in (4624, 4625, 4672) else "system"


def convert_event(r):
    eid = r.EventID & 0xFFFF
    ts = r.TimeGenerated.replace(tzinfo=timezone.utc).isoformat()

    # failed_attempts — detection rule에서 사용
    failed = 1 if eid == 4625 else 0

    return {
        "id": f"win-{eid}-{r.RecordNumber}",
        "host": r.ComputerName or socket.gethostname(),
        "severity": map_severity(eid, r.EventType),
        "category": map_category(eid),
        "@timestamp": ts,
        "source": f"windows_security",
        "failed_attempts": failed,
        "event_id": eid,
        "record_number": r.RecordNumber,
    }


def send_batch(batch):
    if not batch:
        return
    try:
        resp = requests.post(API_BASE, json=batch, timeout=10)
        js = resp.json()
        print(f"[collector] sent={len(batch)}  events={len(js.get('events', []))}  alerts={len(js.get('alerts', []))}")
    except Exception as e:
        print("[collector] send failed:", e)


def run_collector():
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
                if eid not in EVENT_FILTER:
                    continue
                if r.RecordNumber <= last:
                    continue

                batch.append(convert_event(r))
                last = r.RecordNumber

        if batch:
            send_batch(batch)

        time.sleep(1)


if __name__ == "__main__":
    run_collector()
