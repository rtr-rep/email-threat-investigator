from pathlib import Path

from phishtriage.cli import _print_result, analyze_email
from phishtriage.models import AnalysisResult, Finding, ParsedEmail


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
    assert "Verdict: Suspicious" in output
    assert "Score: 25/100" in output
    assert "Positive evidence:" in output
    assert "Top risks:" not in output
    assert "SPF passed" in output
    suspicious_section = output.split("Why this is suspicious:", 1)[1].split("Recommended action:", 1)[0]
    assert "Reply-To differs" in suspicious_section
    assert "SPF passed" not in suspicious_section


def test_cli_print_result_includes_email_server_path(capsys):
    result = AnalysisResult(verdict="Low", score=0, findings=[], recommended_actions=["No immediate action needed"])
    parsed = ParsedEmail(
        from_address="alerts@example.test",
        from_display_name="Alerts",
        reply_to="alerts@example.test",
        return_path="bounce@example.test",
        subject="Notice",
        message_id="<notice@example.test>",
        body_text="Hello",
        received_headers=["from mail.example.test ([203.0.113.10]) by mx.example.net; Fri, 12 Jun 2026 10:00:00 +0000"],
        authentication_results=[],
        attachments=[],
    )

    _print_result(result, parsed)

    output = capsys.readouterr().out
    assert "Email server path:" in output
    assert "mail.example.test [203.0.113.10] -> mx.example.net" in output
    assert "visible Received headers" in output
