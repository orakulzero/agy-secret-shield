"""Tier L4 Standalone FastAPI Workstation & Cross-L4 Root Telemetry for AGY Secret Shield."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .l1_primitives import (
    SECRET_SIGNATURE_CATALOG,
    dpapi_seal_secret,
    dpapi_unseal_secret,
    is_dpapi_available,
)
from .l3_pipeline import SecretShieldPipeline

app = FastAPI(
    title="AGY Secret Shield L4 Workstation",
    version="1.0.0",
    description="4-Tier Secret, Cookie & Privacy Quarantine Workstation with Windows DPAPI",
)


@app.get("/health")
@app.get("/healthz")
async def health_check() -> dict[str, str]:
    """Standard health check endpoint."""
    return {"status": "ok", "station": "secret_shield", "tier": "L4"}

_pipeline = SecretShieldPipeline()


class AuditRequest(BaseModel):
    profile: str = "clean_repo"
    custom_text: Optional[str] = None
    repo_path: Optional[str] = None
    extra_pii_tokens: Optional[list[str]] = None
    ignore_tests: bool = False


class DPAPISealRequest(BaseModel):
    plaintext: str
    description: str = "agy-secret"


class ReportToRootRequest(BaseModel):
    profile: str = "clean_repo"
    target_root_dir: Optional[str] = None
    summary: Optional[str] = None


WORKSTATION_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>AGY Secret Shield — Tier L4 Privacy & DPAPI Quarantine Station</title>
  <style>
    body { background: #0b0f19; color: #e2e8f0; font-family: system-ui, sans-serif; margin: 0; padding: 24px; }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 20px; max-width: 960px; margin: 0 auto; }
    .badge { display: inline-block; background: #065f46; color: #a7f3d0; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
    .controls { display: flex; gap: 12px; margin-top: 16px; align-items: center; }
    select, button { background: #1f2937; color: #f8fafc; border: 1px solid #374151; padding: 8px 14px; border-radius: 8px; cursor: pointer; }
    button.primary { background: #2563eb; border-color: #3b82f6; font-weight: 600; }
    pre { background: #030712; padding: 14px; border-radius: 8px; overflow-x: auto; font-size: 13px; border: 1px solid #1e293b; }
  </style>
</head>
<body>
  <div class="card" data-testid="shield-l4-workstation">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <h2>AGY Secret Shield — L4 Privacy &amp; DPAPI Workstation</h2>
      <span class="badge" data-testid="shield-dpapi-badge">Windows DPAPI Active</span>
    </div>
    <p>5-Stage Secret, Session Cookie, Entropy &amp; PII Quarantine Pipeline (L1 &rarr; L2 &rarr; L3 &rarr; L4)</p>
    <div class="controls">
      <select id="profileSelect" data-testid="shield-profile-select">
        <option value="clean_repo">clean_repo (Zero-Leak Baseline)</option>
        <option value="leaked_cookies">leaked_cookies (Session Cookie &amp; GitHub PAT)</option>
        <option value="pii_contaminant">pii_contaminant (Personal Path &amp; Locale)</option>
      </select>
      <button class="primary" data-testid="shield-audit-btn" onclick="runAudit()">Run 5-Stage Audit</button>
      <button data-testid="shield-report-root-btn" onclick="reportRoot()">Report to AGY Mission Control</button>
    </div>
    <pre id="outputBox">Ready for 5-Stage DPAPI Privacy Audit...</pre>
  </div>
  <script>
    async function runAudit() {
      const profile = document.getElementById('profileSelect').value;
      const res = await fetch('/api/shield/audit', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({profile})
      });
      const data = await res.json();
      document.getElementById('outputBox').textContent = JSON.stringify(data, null, 2);
    }
    async function reportRoot() {
      const profile = document.getElementById('profileSelect').value;
      const res = await fetch('/api/shield/report-to-root', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({profile})
      });
      const data = await res.json();
      document.getElementById('outputBox').textContent = JSON.stringify(data, null, 2);
    }
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def get_workstation_ui() -> HTMLResponse:
    return HTMLResponse(content=WORKSTATION_HTML, status_code=200)


@app.get("/api/shield/catalog")
def get_catalog() -> dict[str, Any]:
    return {
        "ok": True,
        "rule_count": len(SECRET_SIGNATURE_CATALOG),
        "rules": SECRET_SIGNATURE_CATALOG,
        "profiles": ["clean_repo", "leaked_cookies", "pii_contaminant"],
        "dpapi_available": is_dpapi_available(),
    }


@app.post("/api/shield/audit")
def post_audit(req: AuditRequest) -> dict[str, Any]:
    try:
        repo_path_obj = Path(req.repo_path) if req.repo_path else None
        return _pipeline.audit_target(
            profile=req.profile,
            custom_text=req.custom_text,
            repo_path=repo_path_obj,
            extra_pii_tokens=req.extra_pii_tokens,
            ignore_tests=req.ignore_tests,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/shield/dpapi-seal")
def post_dpapi_seal(req: DPAPISealRequest) -> dict[str, Any]:
    try:
        envelope = dpapi_seal_secret(req.plaintext, description=req.description)
        unsealed = dpapi_unseal_secret(envelope)
        return {
            "ok": True,
            "envelope": envelope,
            "roundtrip_verified": unsealed == req.plaintext,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/shield/report-to-root")
def post_report_to_root(req: ReportToRootRequest) -> dict[str, Any]:
    try:
        audit_result = _pipeline.audit_target(profile=req.profile)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    target_dir = (
        Path(req.target_root_dir).resolve()
        if req.target_root_dir
        else Path(__file__).resolve().parent.parent / ".reports"
    )
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).isoformat()
    record = {
        "timestamp": timestamp,
        "project": "agy-secret-shield",
        "tier": "L4",
        "status": "PASS",
        "profile": req.profile,
        "clean": audit_result["clean"],
        "finding_count": audit_result["finding_count"],
        "risk_score": audit_result["risk_score"],
        "severity": audit_result["severity"],
        "certificate_sha256": audit_result["certificate_sha256"],
        "summary": req.summary or f"5-Stage Secret Shield audit completed for {req.profile}",
    }

    jsonl_path = target_dir / "child_session_reports.jsonl"
    with jsonl_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

    md_path = target_dir / "SECRET_SHIELD_HANDOFF_REPORT.md"
    md_content = (
        "# AGY Secret Shield — Tier L4 Telemetry Handoff Report\n\n"
        f"- **Timestamp**: `{timestamp}`\n"
        f"- **Profile**: `{req.profile}`\n"
        f"- **Clean**: `{audit_result['clean']}`\n"
        f"- **Finding Count**: `{audit_result['finding_count']}`\n"
        f"- **Risk Score**: `{audit_result['risk_score']}` (`{audit_result['severity']}`)\n"
        f"- **Certificate SHA-256**: `{audit_result['certificate_sha256']}`\n"
    )
    md_path.write_text(md_content, encoding="utf-8")

    return {
        "ok": True,
        "project": "agy-secret-shield",
        "jsonl_path": str(jsonl_path),
        "handoff_markdown_path": str(md_path),
        "record": record,
    }
