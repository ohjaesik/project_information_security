from typing import Any, Dict, List
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from security_dashboard import InMemoryEventSource, default_pipeline
from security_dashboard.anomalies import (
    RuleBasedAnomalyDetector,
    IsolationForestAnomalyDetector,
)
from security_dashboard.risk import RiskScorer
from security_dashboard.scenarios import list_scenarios, run_scenario
from security_dashboard.notifications import build_recommendations
from dataclasses import asdict, is_dataclass


app = FastAPI(title="Security Dashboard API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def to_jsonable(obj: Any) -> Any:
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


@app.post("/run-pipeline")
def run_pipeline(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    프론트/수집기에서 넘어온 이벤트 dict 리스트를 그대로 받아서
    파이프라인 실행 + 이상탐지 + RiskScore + 대응 권고까지 붙여서 반환.
    """
    pipeline = default_pipeline(InMemoryEventSource(events))
    result = pipeline.run()

    events_out = result.get("events", [])
    alerts_out = result.get("alerts", [])
    incidents_out = result.get("incidents", [])

    # 1) 이상 탐지 (규칙 + IsolationForest)
    rule_detector = RuleBasedAnomalyDetector()
    iso_detector = IsolationForestAnomalyDetector()

    rule_anoms = rule_detector.detect(events_out)
    iso_detector.fit(events_out)
    iso_anoms = iso_detector.detect(events_out)

    anomalies = {
        "rule_based": [to_jsonable(a) for a in rule_anoms],
        "isolation_forest": [to_jsonable(a) for a in iso_anoms],
    }

    # 2) RiskScore 계산
    scorer = RiskScorer()
    incident_scores = [scorer.score_incident(inc) for inc in incidents_out]
    incident_risk_summary = scorer.build_risk_summary(incident_scores)

    # 3) 인시던트별 대응 권고
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


# 1.2.1: Filebeat/Fluentd 등에서 JSON 로그를 바로 보낼 수 있는 엔드포인트 (v1: 메모리 처리)
@app.post("/ingest-logs")
def ingest_logs(logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Filebeat/Fluentd에서 HTTP JSON 배열로 로그 전송한다고 가정하고,
    logs를 pipeline이 기대하는 이벤트 dict 형태로 매핑해서 실행.
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

    # run_pipeline은 List[Dict[str, Any]] 그대로 받도록 되어 있으므로 재사용
    return run_pipeline(events)


# 1.2.2: 디지털 트윈 / 워게이밍 시나리오
@app.get("/scenarios")
def get_scenarios():
    return list_scenarios()


@app.post("/scenarios/{key}/run")
def run_scenario_api(key: str):
    try:
        result = run_scenario(key)
    except KeyError:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return to_jsonable(result)
