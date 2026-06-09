from pathlib import Path

from phishtriage.attachment_analyzer import analyze_attachments
from phishtriage.parser import parse_email


def test_attachment_analyzer_flags_double_extension_and_executable():
    parsed = parse_email(Path("samples/fake-microsoft-login.eml"))

    findings = analyze_attachments(parsed)

    messages = "\n".join(f.message for f in findings).lower()
    assert "double extension" in messages
    assert "executable" in messages
