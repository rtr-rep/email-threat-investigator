from pathlib import Path

from phishtriage.cli import analyze_email


def test_benign_newsletter_scores_low():
    result = analyze_email(Path("samples/benign-newsletter.eml"))

    assert result.verdict == "Low"
    assert result.score == 0


def test_legitimate_company_email_scores_low():
    result = analyze_email(Path("samples/legitimate-company-email.eml"))

    assert result.verdict == "Low"
    assert result.score == 0


def test_bec_reply_only_scam_scores_high_risk_without_links_or_attachments():
    result = analyze_email(Path("samples/bec-reply-only-scam.eml"))

    assert result.verdict in {"High Risk", "Dangerous"}
    assert result.score >= 45
    assert any(f.category == "reply" for f in result.findings)
    assert any(f.category == "auth" for f in result.findings)
