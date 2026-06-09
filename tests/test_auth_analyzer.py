from pathlib import Path

from phishtriage.auth_analyzer import analyze_authentication
from phishtriage.parser import parse_email


def test_authentication_analyzer_flags_spf_dkim_dmarc_failures():
    parsed = parse_email(Path("samples/fake-microsoft-login.eml"))

    findings = analyze_authentication(parsed)

    messages = "\n".join(f.message for f in findings).lower()
    assert "spf failed" in messages
    assert "dkim failed" in messages
    assert "dmarc failed" in messages


def test_authentication_analyzer_reports_positive_pass_evidence_without_risk_points():
    parsed = parse_email(Path("samples/legitimate-company-email.eml"))
    parsed.authentication_results[:] = [
        "mx.google.com; dkim=pass header.i=@notifications.galaxus.ch; spf=pass smtp.mailfrom=em9954.notifications.galaxus.ch; dmarc=pass header.from=galaxus.ch"
    ]

    findings = analyze_authentication(parsed)

    messages = "\n".join(f.message for f in findings).lower()
    assert "spf passed" in messages
    assert "dkim passed" in messages
    assert "dmarc passed" in messages
    assert all(finding.points == 0 for finding in findings)


def test_authentication_analyzer_flags_dkim_permerror_and_missing_dmarc():
    parsed = parse_email(Path("samples/synthetic-iptv-cloud-storage-spam.eml"))

    findings = analyze_authentication(parsed)

    messages = "\n".join(f.message for f in findings).lower()
    assert "spf passed" in messages
    assert "dkim permanent error" in messages
    assert "dmarc result is missing" in messages
    risk_points = sum(f.points for f in findings)
    assert risk_points >= 20


def test_authentication_analyzer_preserves_forwarding_arc_context():
    parsed = parse_email(Path("samples/synthetic-forwarded-arc-legitimate.eml"))

    findings = analyze_authentication(parsed)

    messages = "\n".join(f.message for f in findings).lower()
    assert "forwarding indicators" in messages
    assert "arc-authentication-results" in messages
    assert "original authentication passed" in messages
    assert any(finding.points == 0 and "forwarding" in finding.message.lower() for finding in findings)
