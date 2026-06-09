from pathlib import Path

from phishtriage.parser import parse_email


def test_parse_email_extracts_authentication_headers_html_and_attachments():
    parsed = parse_email(Path("samples/fake-microsoft-login.eml"))

    assert parsed.from_address == "security@microsoft.com"
    assert parsed.reply_to == "microsoft-helpdesk-verify@gmail.com"
    assert len(parsed.received_headers) == 2
    assert len(parsed.authentication_results) == 1
    assert "verify your password" in parsed.body_text.lower()
    assert parsed.body_html
    assert parsed.attachments[0].filename == "invoice.pdf.exe"
    assert parsed.attachments[0].sha256
