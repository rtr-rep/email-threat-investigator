from pathlib import Path

from phishtriage.cli import analyze_email
from phishtriage.models import ParsedEmail
from phishtriage.sender_analyzer import analyze_sender_identity


def _email(**overrides) -> ParsedEmail:
    values = {
        "from_address": "sender@example.com",
        "from_display_name": "Sender",
        "reply_to": "",
        "return_path": "bounce@example.com",
        "subject": "Test message",
        "message_id": "test@example.com",
        "body_text": "Hello",
        "received_headers": ["from mail.example.com by mx.example.net; Tue, 9 Jun 2026 10:00:00 +0000"],
        "authentication_results": [],
        "attachments": [],
        "body_html": "",
        "list_unsubscribe": [],
        "delivered_to": [],
        "forwarded_headers": [],
        "arc_authentication_results": [],
        "raw_headers": [],
    }
    values.update(overrides)
    return ParsedEmail(**values)


def test_random_from_and_generated_return_path_are_high_risk_sender_findings():
    email = _email(
        from_address="WgKkvjPM@8iE3TfaL8iE3TfaL.fr",
        return_path="return2798@3140157.173.125.17380oecjto2uwmkj4157.173.125.1732u36kxshnjnq0dc157.173.125.173iccezqfp3575n4n157.173.125.1737rvcs9rbc3e3183.christmasingloucestershire.com",
    )

    findings = analyze_sender_identity(email)
    risk_messages = "\n".join(finding.message for finding in findings if finding.points > 0)

    assert sum(finding.points for finding in findings) >= 55
    assert "From address appears randomly generated" in risk_messages
    assert "Return-Path uses an unusually long/generated domain" in risk_messages
    assert "Return-Path domain" in risk_messages
    assert {finding.category for finding in findings} == {"sender"}


def test_plain_return_path_mismatch_is_not_scored_without_sender_anomaly_or_auth_failure():
    email = _email(
        from_address="finance@contoso.example",
        return_path="bounce@mailer.example",
    )

    findings = analyze_sender_identity(email)

    assert findings == []


def test_return_path_mismatch_is_context_for_authenticated_known_esp_mail():
    email = _email(
        from_address="news@brand.example",
        return_path="bounce@sendgrid.net",
        authentication_results=[
            "mx.example.net; spf=pass smtp.mailfrom=sendgrid.net; dkim=pass header.d=brand.example; dmarc=pass header.from=brand.example"
        ],
        raw_headers=["X-SG-EID: abc123"],
    )

    findings = analyze_sender_identity(email)

    assert not [finding for finding in findings if finding.points > 0]
    assert any("Return-Path differs" in finding.message and finding.points == 0 for finding in findings)


def test_generated_sender_sample_fixture_is_safe_and_demo_ready():
    sample = Path("samples/synthetic-generated-sender-spam.eml")

    result = analyze_email(sample)
    sender_messages = "\n".join(finding.message for finding in result.findings if finding.category == "sender")

    assert result.score == 70
    assert result.verdict == "High Risk"
    assert "From address appears randomly generated" in sender_messages
    assert "Return-Path uses an unusually long/generated domain" in sender_messages
    assert "christmasingloucestershire.com" in sender_messages


def test_full_analysis_includes_sender_anomalies(tmp_path):
    sample = tmp_path / "generated-sender.eml"
    sample.write_text(
        "\n".join(
            [
                "From: WgKkvjPM <WgKkvjPM@8iE3TfaL8iE3TfaL.fr>",
                "Return-Path: <return2798@3140157.173.125.17380oecjto2uwmkj4157.173.125.1732u36kxshnjnq0dc157.173.125.173iccezqfp3575n4n157.173.125.1737rvcs9rbc3e3183.christmasingloucestershire.com>",
                "Subject: Account notice",
                "Message-ID: <generated@example.test>",
                "Received: from unknown.example by mx.example.net; Tue, 9 Jun 2026 10:00:00 +0000",
                "",
                "Please review your account.",
            ]
        ),
        encoding="utf-8",
    )

    result = analyze_email(Path(sample))
    sender_messages = "\n".join(finding.message for finding in result.findings if finding.category == "sender")

    assert result.score >= 55
    assert result.verdict in {"High Risk", "Dangerous"}
    assert "From address appears randomly generated" in sender_messages
    assert "Return-Path uses an unusually long/generated domain" in sender_messages
