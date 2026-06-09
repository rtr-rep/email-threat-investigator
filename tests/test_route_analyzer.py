from dataclasses import replace
from pathlib import Path

from phishtriage.parser import parse_email
from phishtriage.route_analyzer import analyze_route, build_hop_timeline


def test_route_analyzer_builds_hop_timeline_and_flags_unknown_infrastructure():
    parsed = parse_email(Path("samples/fake-microsoft-login.eml"))

    hops = build_hop_timeline(parsed)
    findings = analyze_route(parsed)

    assert len(hops) == 2
    assert hops[0].from_host == "unknown-vps-host.test"
    assert hops[0].ip_address == "198.51.100.23"
    assert hops[0].likely_role == "MTA"
    messages = "\n".join(f.message for f in findings).lower()
    assert "first visible sending server" in messages
    assert "not obviously related" in messages


def test_route_analyzer_does_not_flag_related_galaxus_transactional_infrastructure():
    parsed = replace(
        parse_email(Path("samples/legitimate-company-email.eml")),
        from_address="noreply@notifications.galaxus.ch",
        received_headers=[
            "from o4.transactional.digitecgalaxus.ch (o4.transactional.digitecgalaxus.ch. [168.245.116.150]) by mx.google.com with ESMTPS id abc; Wed, 03 Jun 2026 01:36:30 -0700 (PDT)"
        ],
    )

    findings = analyze_route(parsed)

    assert findings == []


def test_route_analyzer_softens_known_esp_route_when_authentication_passes():
    parsed = parse_email(Path("samples/synthetic-salesforce-marketing-email.eml"))

    findings = analyze_route(parsed)

    assert findings == []
