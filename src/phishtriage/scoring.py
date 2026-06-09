from __future__ import annotations

from phishtriage.models import AnalysisResult, Finding


def _verdict(score: int) -> str:
    if score >= 71:
        return "Dangerous"
    if score >= 46:
        return "High Risk"
    if score >= 21:
        return "Suspicious"
    return "Low"


def score_findings(findings: list[Finding]) -> AnalysisResult:
    score = min(sum(finding.points for finding in findings), 100)
    actions = ["No immediate action needed"]
    if score >= 21:
        actions = [
            "Do not reply",
            "Do not click links or open attachments",
            "Report the email to IT/security",
        ]
    if score >= 46:
        actions.append("If you already replied or clicked, contact security/helpdesk immediately")

    return AnalysisResult(
        verdict=_verdict(score),
        score=score,
        findings=findings,
        recommended_actions=actions,
    )
