from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from security_dashboard import InMemoryEventSource, default_pipeline

class EventIn(BaseModel):
    id: str
    asset_id: str
    serverity: str
    category: str
    timestamp : str
    source: Optional[str] = None
    failed_attempts: Optional[int] = Field(default = None)

def to_jsonable(obj: Any) -> Any:

    if is_dataclass(obj):
        d = asdict(obj)
        return {k: to_jsonable(v) for k, v in d.items()}
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(v) for v in obj]
    return obj

app = FastAPI(title="Security Dashboard API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers={"*"},
)

@app.post("/run-pipeline")
def run_pipeline(events: List[EventIn]) -> Dict[str, Any]:

    raw_events: List[Dict[str, Any]] = [e.model_dump() for e in events]

    pipeline = default_pipeline(InMemoryEventSource(raw_events))
    result = pipeline.run()

    return to_jsonable(result)

@app.get("/health")
def health():
    return {"status" : "ok"}
                                