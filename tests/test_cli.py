from pathlib import Path

from phishtriage.cli import _print_result, analyze_email
from phishtriage.models import AnalysisResult, Finding


def test_analyze_email_returns_plain_english_summary_for_suspicious_reply_to():
    sample = Path("samples/suspicious-reply-to-bec.eml")

    result = analyze_email(sample)

    assert result.verdict == "High Risk"
    assert result.score >= 45
    assert any("replies go to" in finding.message.lower() for finding in result.findings)
    assert "Do not reply" in result.recommended_actions


def test_cli_print_result_separates_positive_evidence_from_suspicious_findings(capsys):
    result = AnalysisResult(
        verdict="Suspicious",
        score=25,
        findings=[
            Finding(category="auth", severity="info", message="SPF passed for sender infrastructure.", points=0),
            Finding(category="reply", severity="medium", message="Reply-To differs from From domain.", points=25),
        ],
        recommended_actions=["Review before interacting"],
    )

    _print_result(result)

    output = capsys.readouterr().out
    assert "Positive evidence:" in output
    assert "SPF passed" in output
    suspicious_section = output.split("Why this is suspicious:", 1)[1].split("Recommended action:", 1)[0]
    assert "Reply-To differs" in suspicious_section
    assert "SPF passed" not in suspicious_section
