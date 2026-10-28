"""NVIDIA SkillSpector Adaptation: Rule Scanner, Risk Scoring, and Skill Auditing.

Traceability: REQ-SS-202 (NVIDIA SkillSpector adaptation, rules, models, detections).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import NamedTuple, Sequence


@dataclass(frozen=True)
class SkillVulnerability:
    rule_id: str
    severity: str
    category: str
    line_number: int
    matched_text: str
    description: str


@dataclass(frozen=True)
class SkillAuditResult:
    target_path: str
    total_findings: int
    risk_score: float
    is_safe: bool
    vulnerabilities: list[SkillVulnerability]


SEVERITY_WEIGHTS = {
    "CRITICAL": 35.0,
    "HIGH": 25.0,
    "MEDIUM": 15.0,
    "LOW": 5.0,
}


class _SkillRule(NamedTuple):
    rule_id: str
    severity: str
    category: str
    pattern: re.Pattern[str]
    description: str


SKILL_RULES: list[_SkillRule] = [
    # PROMPT_INJECTION
    _SkillRule("RULE-INJ-001", "CRITICAL", "PROMPT_INJECTION", re.compile(r"ignore\s+all\s+previous\s+instructions", re.IGNORECASE), "Prompt injection: ignore previous instructions"),
    _SkillRule("RULE-INJ-002", "CRITICAL", "PROMPT_INJECTION", re.compile(r"disregard\s+(?:all\s+)?safety\s+guidelines", re.IGNORECASE), "Prompt injection: disregard safety guidelines"),
    _SkillRule("RULE-INJ-003", "CRITICAL", "PROMPT_INJECTION", re.compile(r"system\s+override", re.IGNORECASE), "Prompt injection: system override directive"),
    _SkillRule("RULE-INJ-004", "HIGH", "PROMPT_INJECTION", re.compile(r"extract\s+system\s+prompt", re.IGNORECASE), "Prompt injection: extract system prompt"),
    _SkillRule("RULE-INJ-005", "CRITICAL", "PROMPT_INJECTION", re.compile(r"\bjailbreak\b", re.IGNORECASE), "Prompt injection: jailbreak trigger"),
    _SkillRule("RULE-INJ-006", "HIGH", "PROMPT_INJECTION", re.compile(r"developer\s+command:", re.IGNORECASE), "Prompt injection: developer command simulation"),
    _SkillRule("RULE-INJ-007", "HIGH", "PROMPT_INJECTION", re.compile(r"print\s+secrets", re.IGNORECASE), "Prompt injection: print secrets directive"),
    _SkillRule("RULE-INJ-008", "HIGH", "PROMPT_INJECTION", re.compile(r"reveal\s+internal\s+system\s+state", re.IGNORECASE), "Prompt injection: probe internal system state"),
    _SkillRule("RULE-INJ-009", "HIGH", "PROMPT_INJECTION", re.compile(r"hidden\s+context", re.IGNORECASE), "Prompt injection: extract hidden context"),
    _SkillRule("RULE-INJ-010", "HIGH", "PROMPT_INJECTION", re.compile(r"\bdan\s+mode\b|do\s+anything\s+now", re.IGNORECASE), "Prompt injection: DAN persona override"),
    _SkillRule("RULE-INJ-011", "CRITICAL", "PROMPT_INJECTION", re.compile(r"disregard\s+prior\s+instructions", re.IGNORECASE), "Prompt injection: disregard prior instructions"),
    _SkillRule("RULE-INJ-012", "HIGH", "PROMPT_INJECTION", re.compile(r"bypass\s+(?:all\s+)?safety", re.IGNORECASE), "Prompt injection: bypass safety controls"),

    # DANGEROUS_COMMAND
    _SkillRule("RULE-CMD-001", "CRITICAL", "DANGEROUS_COMMAND", re.compile(r"\brm\s+-rf\s+[/~*a-zA-Z0-9_\.]+", re.IGNORECASE), "Dangerous command: recursive force file removal"),
    _SkillRule("RULE-CMD-002", "CRITICAL", "DANGEROUS_COMMAND", re.compile(r"\bInvoke-Expression\b|\biex\s+", re.IGNORECASE), "Dangerous command: PowerShell Invoke-Expression evaluation"),
    _SkillRule("RULE-CMD-003", "CRITICAL", "DANGEROUS_COMMAND", re.compile(r"\bformat\s+[a-zA-Z]:", re.IGNORECASE), "Dangerous command: disk volume format"),
    _SkillRule("RULE-CMD-004", "CRITICAL", "DANGEROUS_COMMAND", re.compile(r"(?:curl|wget)\s+[^|\n]+\|\s*(?:bash|sh|zsh|powershell|pwsh)", re.IGNORECASE), "Dangerous command: remote payload execution via pipe to shell"),
    _SkillRule("RULE-CMD-005", "HIGH", "DANGEROUS_COMMAND", re.compile(r"\bpowershell(?:\.exe)?\s+-[a-zA-Z]*e(?:nc(?:odedcommand)?)?\b", re.IGNORECASE), "Dangerous command: encoded PowerShell execution"),
    _SkillRule("RULE-CMD-006", "CRITICAL", "DANGEROUS_COMMAND", re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b", re.IGNORECASE), "Dangerous command: filesystem format"),
    _SkillRule("RULE-CMD-007", "CRITICAL", "DANGEROUS_COMMAND", re.compile(r"\bdd\s+if=[^\n]+of=/dev/[a-zA-Z0-9]+", re.IGNORECASE), "Dangerous command: direct raw block device write"),
    _SkillRule("RULE-CMD-008", "HIGH", "DANGEROUS_COMMAND", re.compile(r"\bchmod\s+(?:-R\s+)?777\s+[/~]", re.IGNORECASE), "Dangerous command: root 777 permissions"),
    _SkillRule("RULE-CMD-009", "CRITICAL", "DANGEROUS_COMMAND", re.compile(r"\b(?:del|erase)\s+/[fF]\s+/[sS]\s+/[qQ]", re.IGNORECASE), "Dangerous command: Windows recursive force deletion"),
    _SkillRule("RULE-CMD-010", "HIGH", "DANGEROUS_COMMAND", re.compile(r"\bnetsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off\b", re.IGNORECASE), "Dangerous command: firewall disabling"),

    # EXFILTRATION & CREDENTIAL_LEAK
    _SkillRule("RULE-EXF-001", "CRITICAL", "EXFILTRATION", re.compile(r"curl\s+.*-[XFfd]\s+.*@(?:id_rsa|\.env|etc/passwd)", re.IGNORECASE), "Exfiltration: credential file upload via curl"),
    _SkillRule("RULE-EXF-002", "HIGH", "EXFILTRATION", re.compile(r"https?://(?:webhook\.site|requestbin\.(?:net|com)|pipedream\.net|hookbin\.com)/[a-zA-Z0-9_-]+", re.IGNORECASE), "Exfiltration: suspicious webhook data collector endpoint"),
    _SkillRule("RULE-EXF-003", "CRITICAL", "EXFILTRATION", re.compile(r"fetch\s*\(\s*['\"]https?://(?:requestbin|webhook|pipedream|hookbin|badactor|attacker)[^'\"]*['\"]", re.IGNORECASE), "Exfiltration: JavaScript fetch to untrusted receiver"),
    _SkillRule("RULE-EXF-004", "HIGH", "EXFILTRATION", re.compile(r"document\.cookie|window\.localStorage", re.IGNORECASE), "Exfiltration: browser session storage/cookie access"),
    _SkillRule("RULE-EXF-005", "CRITICAL", "EXFILTRATION", re.compile(r"(?:cat|type)\s+[^\n|]+\|\s*(?:base64\s*\|)?\s*curl\s+.*-(?:d|F)", re.IGNORECASE), "Exfiltration: piped file exfiltration via curl"),
    _SkillRule("RULE-EXF-006", "CRITICAL", "EXFILTRATION", re.compile(r"curl\s+.*-(?:d|F)\s+@-?\s+https?://[^\s]+", re.IGNORECASE), "Exfiltration: curl data upload to remote destination"),
    _SkillRule("RULE-EXF-007", "CRITICAL", "CREDENTIAL_LEAK", re.compile(r"\b(?:mimikatz|sekurlsa::logonpasswords)\b", re.IGNORECASE), "Credential leak: LSASS memory credential harvester"),
    _SkillRule("RULE-EXF-008", "CRITICAL", "CREDENTIAL_LEAK", re.compile(r"\bprocdump(?:\.exe)?\s+-[a-zA-Z]*\s+lsass", re.IGNORECASE), "Credential leak: LSASS process memory dump"),
]


class SkillSpectorScanner:
    """NVIDIA SkillSpector-adapted AST and regex pattern security scanner for skills."""

    def __init__(self, rules: Sequence[_SkillRule] | None = None) -> None:
        self._rules = list(rules) if rules is not None else list(SKILL_RULES)

    def scan_text(self, content: str, filename: str = "SKILL.md") -> SkillAuditResult:
        if not content:
            return SkillAuditResult(
                target_path=filename,
                total_findings=0,
                risk_score=0.0,
                is_safe=True,
                vulnerabilities=[],
            )

        vulnerabilities: list[SkillVulnerability] = []
        seen_detections: set[tuple[str, int]] = set()

        for rule in self._rules:
            for match in rule.pattern.finditer(content):
                line_no = content.count("\n", 0, match.start()) + 1
                key = (rule.rule_id, line_no)
                if key in seen_detections:
                    continue
                seen_detections.add(key)

                matched_str = match.group(0).strip()
                vulnerabilities.append(
                    SkillVulnerability(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        line_number=line_no,
                        matched_text=matched_str,
                        description=rule.description,
                    )
                )

        vulnerabilities.sort(key=lambda v: (v.line_number, v.rule_id))

        total_findings = len(vulnerabilities)
        is_safe = (total_findings == 0)
        if is_safe:
            risk_score = 0.0
        else:
            raw_score = sum(SEVERITY_WEIGHTS.get(v.severity, 10.0) for v in vulnerabilities)
            risk_score = min(100.0, float(raw_score))

        return SkillAuditResult(
            target_path=filename,
            total_findings=total_findings,
            risk_score=risk_score,
            is_safe=is_safe,
            vulnerabilities=vulnerabilities,
        )

    def scan_file(self, file_path: Path | str) -> SkillAuditResult:
        path_obj = Path(file_path)
        if not path_obj.is_file():
            raise FileNotFoundError(f"Skill file not found: {path_obj}")
        content = path_obj.read_text(encoding="utf-8", errors="ignore")
        return self.scan_text(content, filename=str(path_obj))

    def scan_directory(self, dir_path: Path | str) -> list[SkillAuditResult]:
        root = Path(dir_path)
        if not root.is_dir():
            raise NotADirectoryError(f"Directory not found: {root}")

        results: list[SkillAuditResult] = []
        candidates = sorted(
            [
                p for p in root.rglob("*")
                if p.is_file() and (
                    p.suffix.lower() in (".md", ".markdown")
                    or p.name.upper().startswith("SKILL")
                )
            ],
            key=lambda p: str(p),
        )
        for cand in candidates:
            results.append(self.scan_file(cand))
        return results
