from __future__ import annotations

from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

from .database import REPORTS_DIR, execute, fetch_all, fetch_one, next_code, setting_enabled


def generate_incident_report(incident_id: int, user_id: int | None = None) -> dict:
    incident = fetch_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if not incident:
        raise ValueError("Incident not found")
    evidence = fetch_all("SELECT * FROM digital_evidence WHERE incident_id=? ORDER BY id DESC", (incident_id,)) if setting_enabled("report_include_evidence", "true") else []
    analysis = fetch_one("SELECT * FROM ai_analysis WHERE incident_id=? ORDER BY id DESC LIMIT 1", (incident_id,)) if setting_enabled("report_include_ai", "true") else None
    history = fetch_all("SELECT * FROM incident_status_history WHERE incident_id=? ORDER BY id", (incident_id,))
    report_code = next_code("RPT", "incident_reports", "report_code")
    filename = f"{report_code}_{incident['incident_code']}.pdf"
    path = REPORTS_DIR / filename
    build_pdf(path, report_code, incident, evidence, analysis, history)
    report_id = execute(
        """
        INSERT INTO incident_reports(report_code,incident_id,generated_by,report_path,report_format,generated_at,status)
        VALUES(?,?,?,?, 'PDF', datetime('now'), 'Ready')
        """,
        (report_code, incident_id, user_id, str(path)),
    )
    return fetch_one("SELECT * FROM incident_reports WHERE id=?", (report_id,)) or {}


def build_pdf(path: Path, report_code: str, incident: dict, evidence: list[dict], analysis: dict | None, history: list[dict]) -> None:
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = []
    story.append(Paragraph("NESS Incident Report", styles["Title"]))
    story.append(Paragraph(f"Report Code: {report_code}", styles["Normal"]))
    story.append(Spacer(1, 12))
    rows = [
        ["Incident ID", incident.get("incident_code")],
        ["Attack Type", incident.get("attack_type")],
        ["Severity", incident.get("severity")],
        ["Status", incident.get("status")],
        ["Source IP", incident.get("source_ip")],
        ["Location", f"{incident.get('source_country') or ''} {incident.get('source_city') or ''}".strip()],
        ["Target", incident.get("target")],
        ["Path", incident.get("path")],
        ["Method", incident.get("method")],
        ["Payload", incident.get("payload") or incident.get("query_string") or "-"],
        ["Detected At", incident.get("created_at")],
    ]
    table = Table(rows, colWidths=[110, 360])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E5EEF9")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#B7C2D0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
    ]))
    story.append(table)
    story.append(Spacer(1, 14))
    story.append(Paragraph("Digital Evidence", styles["Heading2"]))
    if evidence:
        for ev in evidence:
            story.append(Paragraph(f"{ev['evidence_code']} — {ev['evidence_type']} — SHA256: {ev['hash_value']}", styles["Normal"]))
    else:
        story.append(Paragraph("No evidence records found.", styles["Normal"]))
    story.append(Spacer(1, 14))
    story.append(Paragraph("AI / Defensive Analysis", styles["Heading2"]))
    if analysis:
        story.append(Paragraph(str(analysis.get("analysis_summary", "")), styles["BodyText"]))
        story.append(Spacer(1, 8))
        story.append(Paragraph(str(analysis.get("recommendations", "")), styles["BodyText"]))
        story.append(Paragraph(f"Confidence: {float(analysis.get('confidence') or 0):.2f}", styles["Normal"]))
    else:
        story.append(Paragraph("No AI analysis has been generated yet.", styles["Normal"]))
    story.append(Spacer(1, 14))
    story.append(Paragraph("Status History", styles["Heading2"]))
    for h in history:
        story.append(Paragraph(f"{h.get('changed_at')} — {h.get('old_status') or '-'} → {h.get('new_status')} — {h.get('remarks') or ''}", styles["Normal"]))
    doc.build(story)
