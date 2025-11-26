from typing import Any, Dict, List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from dataclasses import asdict, is_dataclass

from security_dashboard import InMemoryEventSource, default_pipeline
from security_dashboard.anomalies import (
    RuleBasedAnomalyDetector,
    IsolationForestAnomalyDetector,
)
from security_dashboard.risk import RiskScorer
from security_dashboard.scenarios import list_scenarios, run_scenario
from security_dashboard.notifications import build_recommendations


# FastAPI application instance for the Security Dashboard backend
app = FastAPI(title="Security Dashboard API", version="0.2.0")

# Enable CORS to allow requests from frontend dashboards (React/Grafana)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Stores the most recent real-time pipeline execution result (used by collector)
last_result: Optional[Dict[str, Any]] = None


def to_jsonable(obj: Any) -> Any:
    """
    Convert arbitrary Python objects (dataclasses, datetime, lists, dicts)
    into JSON-serializable formats for API responses.
    """
    if is_dataclass(obj):
        d = asdict(obj)
        return {k: to_jsonable(v) for k, v in d.items()}
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    return obj


def run_pipeline_core(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Execute the full security analysis pipeline:
    - Event ingestion
    - Rule-based anomaly detection
    - ML-based anomaly detection (Isolation Forest)
    - RiskScore calculation
    - Incident-level response recommendation generation

    This function is shared by both:
    - /run-pipeline (dataset & testing)
    - /ingest-logs (real-time collector input)
    """
    pipeline = default_pipeline(InMemoryEventSource(events))
    result = pipeline.run()

    events_out = result.get("events", [])
    alerts_out = result.get("alerts", [])
    incidents_out = result.get("incidents", [])

    # 1) Anomaly Detection Stage
    rule_detector = RuleBasedAnomalyDetector()
    iso_detector = IsolationForestAnomalyDetector()

    rule_anoms = rule_detector.detect(events_out)
    iso_detector.fit(events_out)
    iso_anoms = iso_detector.detect(events_out)

    anomalies = {
        "rule_based": [to_jsonable(a) for a in rule_anoms],
        "isolation_forest": [to_jsonable(a) for a in iso_anoms],
    }

    # 2) RiskScore Calculation Stage
    scorer = RiskScorer()
    incident_scores = [scorer.score_incident(inc) for inc in incidents_out]
    incident_risk_summary = scorer.build_risk_summary(incident_scores)

    # 3) Automated Response Recommendation Stage
    recommendations = []
    for inc, score in zip(incidents_out, incident_scores):
        rec = build_recommendations(inc, score.score)
        recommendations.append(to_jsonable(rec))

    enriched = {
        "events": [to_jsonable(e) for e in events_out],
        "alerts": [to_jsonable(a) for a in alerts_out],
        "incidents": [to_jsonable(i) for i in incidents_out],
        "reports": [to_jsonable(r) for r in result.get("reports", [])],
        "executed_actions": result.get("executed_actions", []),
        "anomalies": anomalies,
        "risk": {
            "incidents": [to_jsonable(s) for s in incident_scores],
            "summary": incident_risk_summary,
        },
        "recommendations": recommendations,
    }
    return enriched


def normalize_logs(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize raw logs received from the collector into
    the unified event schema used by the pipeline.
    """
    events: List[Dict[str, Any]] = []
    for i, log in enumerate(logs, start=1):
        ev: Dict[str, Any] = {
            "id": str(log.get("id", f"log-{i}")),
            "asset_id": str(log.get("host", "unknown")),
            "severity": str(log.get("severity", "low")),
            "category": str(log.get("category", "system")),
            "timestamp": str(log.get("@timestamp", datetime.utcnow().isoformat())),
            "source": str(log.get("source", "log_ingest")),
            "failed_attempts": log.get("failed_attempts"),
            "prompt": log.get("prompt"),
            "dataset": log.get("dataset"),
        }
        events.append(ev)
    return events


# 1) Dataset / Scenario / UI Testing Endpoint
#    This endpoint does NOT update last_result
@app.post("/run-pipeline")
def run_pipeline(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    return run_pipeline_core(events)


# 2) Real-time Collector Endpoint
#    This endpoint updates last_result for UI polling
@app.post("/ingest-logs")
def ingest_logs(logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    global last_result
    events = normalize_logs(logs)
    last_result = run_pipeline_core(events)
    return last_result


# 3) Real-time Result Fetching Endpoint
#    Used by the frontend dashboard through polling
@app.get("/last-result")
def get_last_result() -> Dict[str, Any]:
    return last_result or {}


# Scenario Management APIs
@app.get("/scenarios")
def get_scenarios():
    """
    Return the list of available cyber wargaming scenarios.
    """
    return list_scenarios()


@app.post("/scenarios/{key}/run")
def run_scenario_api(key: str):
    """
    Execute a selected cyber wargaming scenario and return
    the generated attack logs and detection results.
    """
    try:
        result = run_scenario(key)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return to_jsonable(result)
