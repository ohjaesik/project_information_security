import json
from datetime import datetime
import requests

API_BASE =  "http://localhost:8000"

def load_windows_security_events(path: str):
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if isinstance(raw, dict):
        records = [raw]
    else:
        records = raw