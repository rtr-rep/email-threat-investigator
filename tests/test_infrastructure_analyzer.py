from pathlib import Path

from phishtriage.infrastructure_analyzer import analyze_infrastructure
from phishtriage.parser import parse_email


def test_infrastructure_analyzer_recognizes_salesforce_marketing_cloud():
    parsed = parse_email(Path("samples/synthetic-salesforce-marketing-email.eml"))

    findings = analyze_infrastructure(parsed)

    messages = "\n".join(f.message for f in findings).lower()
    assert "salesforce marketing cloud" in messages
    assert "marketing/esp infrastructure" in messages
    assert all(finding.points == 0 for finding in findings)
