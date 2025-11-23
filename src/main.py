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

app = FastAPI(title="Security Dashboard API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# collector가 돌린 "실시간" 결과를 저장
last_result: Optional[Dict[str, Any]] = None


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


def run_pipeline_core(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    공통 파이프라인 실행 + 이상탐지 + RiskScore + 대응 권고까지 묶은 함수.
    /run-pipeline (데이터셋용), /ingest-logs (collector용) 에서 공통 사용.
    """
    pipeline = default_pipeline(InMemoryEventSource(events))
    result = pipeline.run()

    events_out = result.get("events", [])
    alerts_out = result.get("alerts", [])
    incidents_out = result.get("incidents", [])

    # 1) 이상 탐지
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


def normalize_logs(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    collector가 보내는 원시 로그 → 파이프라인용 이벤트 dict로 정규화.
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


# 1) 데이터셋 / 시나리오 / UI 테스트용: last_result 갱신 안 함
@app.post("/run-pipeline")
def run_pipeline(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    return run_pipeline_core(events)


# 2) collector(실시간)용: 여기서만 last_result 갱신
@app.post("/ingest-logs")
def ingest_logs(logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    global last_result
    events = normalize_logs(logs)
    last_result = run_pipeline_core(events)
    return last_result


# 3) 실시간 결과 조회용: UI가 polling
@app.get("/last-result")
def get_last_result() -> Dict[str, Any]:
    return last_result or {}


# 시나리오 관련 API
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
