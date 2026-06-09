from pathlib import Path

from phishtriage.parser import parse_email


def test_parse_email_extracts_core_fields_and_body():
    parsed = parse_email(Path("samples/suspicious-reply-to-bec.eml"))

    assert parsed.from_address == "finance@contoso.example"
    assert parsed.from_display_name == "Contoso Finance"
    assert parsed.reply_to == "contoso-payments-helpdesk@gmail.com"
    assert parsed.return_path == "bounce@mailer.example"
    assert parsed.subject == "Urgent payment confirmation required"
    assert parsed.message_id == "20260603.123456@contoso.example"
    assert "Please reply urgently" in parsed.body_text


def test_parse_email_extracts_forwarding_and_arc_headers():
    parsed = parse_email(Path("samples/synthetic-forwarded-arc-legitimate.eml"))

    assert len(parsed.delivered_to) == 2
    assert parsed.forwarded_headers
    assert parsed.arc_authentication_results
    assert "dmarc=pass" in parsed.arc_authentication_results[0]


def test_parse_email_preserves_raw_headers_for_platform_detection():
    parsed = parse_email(Path("samples/synthetic-salesforce-marketing-email.eml"))

    raw_headers = "\n".join(parsed.raw_headers).lower()
    assert "x-sfmc-stack" in raw_headers
    assert "feedback-id" in raw_headers
    assert "x-job" in raw_headers
