from __future__ import annotations

import json
import os
import textwrap
from typing import Any

from .database import execute, fetch_one, get_setting, setting_enabled


SEVERITY_BASE = {"Low": 25, "Medium": 50, "High": 72, "Critical": 88}
ATTACK_RISK = {
    "SQL Injection": 94,
    "XSS Attempt": 78,
    "Directory Traversal": 82,
    "Brute Force Attempt": 80,
    "High Request Rate": 62,
    "Network Port Scan": 78,
    "Network Host Sweep": 74,
    "TCP SYN Flood": 92,
    "ICMP Host Sweep": 72,
    "ICMP Flood": 64,
}
CLASSIFICATION_MAP = {
    "SQL Injection": "Web Application Attack / SQL Injection",
    "XSS Attempt": "Web Application Attack / Cross-Site Scripting",
    "Directory Traversal": "Web Application Attack / Path Traversal",
    "Brute Force Attempt": "Authentication Attack / Brute Force",
    "High Request Rate": "Availability / Request-Rate Anomaly",
    "Network Port Scan": "Network Reconnaissance / Port Scan",
    "Network Host Sweep": "Network Reconnaissance / Host Sweep",
    "TCP SYN Flood": "Network Availability Attack / SYN Flood",
    "ICMP Host Sweep": "Network Reconnaissance / ICMP Sweep",
    "ICMP Flood": "Network Availability Anomaly / ICMP Flood",
}


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _severity_for_score(score: int) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 45:
        return "Medium"
    return "Low"


def build_risk_prediction(incident: dict[str, Any]) -> dict[str, Any]:
    """Create a transparent defensive classification and risk prediction.

    This is the always-available local hybrid layer. It combines the detector's
    classification with risk scoring, recent recurrence, request context, and
    preserved evidence. If Ollama is enabled, its narrative analysis is added on
    top of these deterministic results; the risk fields remain explainable.
    """
    attack_type = str(incident.get("attack_type") or "Suspicious Activity")
    severity = str(incident.get("severity") or "Medium")
    source_ip = str(incident.get("source_ip") or "unknown")
    method = str(incident.get("method") or "GET").upper()

    recent_source = fetch_one(
        "SELECT COUNT(*) AS c FROM incidents WHERE source_ip=? AND created_at >= datetime('now','-1 hour')",
        (source_ip,),
    ) or {"c": 0}
    recent_same_type = fetch_one(
        "SELECT COUNT(*) AS c FROM incidents WHERE source_ip=? AND attack_type=? AND created_at >= datetime('now','-24 hours')",
        (source_ip, attack_type),
    ) or {"c": 0}
    evidence = fetch_one("SELECT id FROM digital_evidence WHERE incident_id=? LIMIT 1", (incident.get("id"),))

    base = max(SEVERITY_BASE.get(severity, 50), ATTACK_RISK.get(attack_type, 55))
    recurrence_count = max(0, int(recent_source.get("c") or 0) - 1)
    same_type_count = max(0, int(recent_same_type.get("c") or 0) - 1)
    score = float(base)
    score += min(8, recurrence_count * 2.0)
    score += min(7, same_type_count * 1.5)
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 2
    if evidence:
        score += 1
    score = int(round(_clamp(score, 0, 100)))

    threat_probability = round(_clamp(0.30 + score / 145.0 + min(recurrence_count, 5) * 0.025, 0.05, 0.99), 3)
    predicted_severity = _severity_for_score(score)
    classification = CLASSIFICATION_MAP.get(attack_type, f"Suspicious Security Activity / {attack_type}")

    if recurrence_count >= 4 or score >= 88:
        recurrence_label = "High"
    elif recurrence_count >= 1 or score >= 65:
        recurrence_label = "Medium"
    else:
        recurrence_label = "Low"

    prediction = (
        f"{recurrence_label} near-term recurrence risk. Current defensive risk score is {score}/100 "
        f"with an estimated threat likelihood of {threat_probability * 100:.1f}%. "
        f"The recommended operational priority is {predicted_severity}."
    )
    factors = {
        "detector_severity": severity,
        "attack_type": attack_type,
        "source_incidents_last_hour": int(recent_source.get("c") or 0),
        "same_attack_from_source_last_24h": int(recent_same_type.get("c") or 0),
        "state_changing_http_method": method in {"POST", "PUT", "PATCH", "DELETE"},
        "evidence_preserved": bool(evidence),
        "recurrence_risk": recurrence_label,
    }
    return {
        "classification": classification,
        "risk_score": score,
        "predicted_severity": predicted_severity,
        "threat_probability": threat_probability,
        "prediction": prediction,
        "factors": factors,
    }


def analyze_incident(incident_id: int, automatic: bool = False, force: bool = True) -> dict:
    incident = fetch_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if not incident:
        raise ValueError("Incident not found")

    if automatic and not force:
        existing = fetch_one(
            "SELECT * FROM ai_analysis WHERE incident_id=? AND automatic=1 ORDER BY id DESC LIMIT 1",
            (incident_id,),
        )
        if existing:
            return existing

    evidence = fetch_one("SELECT * FROM digital_evidence WHERE incident_id=? ORDER BY id DESC LIMIT 1", (incident_id,))
    risk = build_risk_prediction(incident)
    model = str(get_setting("ollama_model", os.getenv("OLLAMA_MODEL", "llama3.1:8b")))
    enabled = setting_enabled("ollama_enabled", os.getenv("OLLAMA_ENABLED", "false"))

    if enabled:
        try:
            import ollama  # type: ignore

            prompt = build_prompt(incident, evidence, risk)
            client = ollama.Client(host=str(get_setting("ollama_host", os.getenv("OLLAMA_HOST", "http://localhost:11434"))))
            result = client.generate(model=model, prompt=prompt)
            text = result.get("response", "").strip()
            if text:
                summary, recommendations = split_ai_text(text)
                confidence = max(0.90, float(risk["threat_probability"]))
                source = "ollama+ness-risk-engine"
            else:
                raise RuntimeError("Empty Ollama response")
        except Exception as exc:
            summary, recommendations = fallback_analysis(incident, risk)
            summary += f"\n\nLocal Ollama was enabled but unavailable at runtime ({exc.__class__.__name__}); NESS completed the automatic analysis using its local hybrid risk engine."
            model = "NESS Hybrid AI Risk Engine"
            confidence = max(0.76, float(risk["threat_probability"]) * 0.9)
            source = "local-hybrid-fallback"
    else:
        summary, recommendations = fallback_analysis(incident, risk)
        model = "NESS Hybrid AI Risk Engine"
        confidence = max(0.78, float(risk["threat_probability"]) * 0.92)
        source = "local-hybrid"

    analysis_id = execute(
        """
        INSERT INTO ai_analysis(
            incident_id,model_name,analysis_summary,recommendations,confidence,generated_at,source,
            classification,risk_score,predicted_severity,threat_probability,prediction,factors,automatic
        ) VALUES(?,?,?,?,?,datetime('now'),?,?,?,?,?,?,?,?)
        """,
        (
            incident_id,
            model,
            summary,
            recommendations,
            round(float(confidence), 3),
            source,
            risk["classification"],
            risk["risk_score"],
            risk["predicted_severity"],
            risk["threat_probability"],
            risk["prediction"],
            json.dumps(risk["factors"], ensure_ascii=False),
            1 if automatic else 0,
        ),
    )
    row = fetch_one("SELECT * FROM ai_analysis WHERE id=?", (analysis_id,)) or {}
    try:
        row["factors"] = json.loads(row.get("factors") or "{}")
    except Exception:
        pass
    return row


def build_prompt(incident: dict, evidence: dict | None, risk: dict[str, Any]) -> str:
    return textwrap.dedent(
        f"""
        You are a defensive cybersecurity analyst working inside NESS.
        Analyze the detected incident below. Do not provide offensive instructions.
        NESS has already produced an explainable local classification and risk prediction.
        Use those fields as context and provide a concise defensive summary, why it is suspicious,
        possible impact, severity justification, and prioritized defensive recommendations.

        Incident ID: {incident.get('incident_code')}
        Detector Attack Type: {incident.get('attack_type')}
        Detector Severity: {incident.get('severity')}
        Automatic Classification: {risk.get('classification')}
        Risk Score: {risk.get('risk_score')}/100
        Predicted Severity: {risk.get('predicted_severity')}
        Threat Likelihood: {float(risk.get('threat_probability') or 0) * 100:.1f}%
        Prediction: {risk.get('prediction')}
        Source IP: {incident.get('source_ip')}
        Target: {incident.get('target')}
        Path: {incident.get('path')}
        Method: {incident.get('method')}
        Payload/Query: {incident.get('payload') or incident.get('query_string')}
        User-Agent: {incident.get('user_agent')}
        Evidence Hash: {(evidence or {}).get('hash_value')}
        """
    ).strip()


def split_ai_text(text: str) -> tuple[str, str]:
    lowered = text.lower()
    for marker in ("recommendations", "recommended actions", "recommended"):
        idx = lowered.find(marker)
        if idx > 0:
            return text[:idx].strip(), text[idx:].strip()
    return text.strip(), "Review the affected endpoint, preserve evidence, correlate related events, contain repeated malicious activity, and continue real-time monitoring."


def fallback_analysis(incident: dict, risk: dict[str, Any]) -> tuple[str, str]:
    attack_type = incident.get("attack_type", "Suspicious Request")
    severity = incident.get("severity", "Medium")
    payload = incident.get("payload") or incident.get("query_string") or "No payload captured"
    is_network_event = attack_type.startswith("Network ") or attack_type.startswith("TCP ") or attack_type.startswith("ICMP ")
    context_label = "Captured network metadata" if is_network_event else "Captured request context"
    summary = (
        f"NESS automatically detected and classified this event as {risk['classification']}. "
        f"The detector identified {attack_type} with {severity} severity from {incident.get('source_ip')} "
        f"against {incident.get('target') or incident.get('path')}. The automatic risk engine calculated "
        f"{risk['risk_score']}/100 and predicted {risk['predicted_severity']} operational priority. "
        f"{context_label}: {payload}. {risk['prediction']}"
    )
    if is_network_event:
        recs = "\n".join(
            [
                "1. Preserve the captured flow evidence and maintain the SHA-256 integrity record.",
                "2. Review the source device, destination service, and same-window network flows to confirm whether the behavior is expected in the lab.",
                "3. If the behavior is unauthorized, apply defensive rate limiting, firewall restrictions, or host isolation according to the lab response policy.",
                "4. Correlate the source IP with recent incidents, device history, server logs, and INTS tracking events.",
                "5. Continue automatic monitoring and escalate if the activity repeats or the predicted severity increases.",
            ]
        )
    else:
        recs = "\n".join(
            [
                "1. Preserve the captured evidence and maintain the SHA-256 integrity record.",
                "2. Review the affected endpoint and apply strict input validation/output encoding as relevant to the detected class.",
                "3. Correlate this source IP with recent incidents and apply rate limiting or containment when repeated malicious behavior is confirmed.",
                "4. Review application/server logs in the same time window and compare them with INTS tracking events.",
                "5. Continue automatic monitoring; escalate immediately if the predicted severity or recurrence risk increases.",
            ]
        )
    return summary, recs
