from phishtriage.models import Finding
from phishtriage.scoring import score_findings


def test_score_findings_caps_score_and_assigns_verdict():
    findings = [
        Finding(category="reply", severity="high", message="Replies go elsewhere", points=25),
        Finding(category="reply", severity="high", message="Free-mail Reply-To", points=25),
        Finding(category="content", severity="medium", message="Urgent reply language", points=10),
    ]

    result = score_findings(findings)

    assert result.score == 60
    assert result.verdict == "High Risk"
    assert "Do not reply" in result.recommended_actions
