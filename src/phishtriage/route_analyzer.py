from __future__ import annotations

import re

from phishtriage.email_utils import domain_from_email, sender_identity_authentication_passed
from phishtriage.infrastructure_analyzer import analyze_infrastructure
from phishtriage.models import Finding, ParsedEmail, RouteHop

RECEIVED_RE = re.compile(
    r"from\s+(?P<from_host>[^\s(]+)(?:\s+\([^\[]*\[(?P<ip>[^\]]+)\]\))?\s+by\s+(?P<by_host>[^\s]+).*?(?:;\s*(?P<timestamp>.+))?$",
    re.IGNORECASE | re.DOTALL,
)


def _domain_labels(value: str) -> list[str]:
    return [label for label in value.lower().split(".") if label]


def _looks_related_to_sender(host: str, from_domain: str) -> bool:
    host = host.lower()
    from_domain = from_domain.lower()
    if not host or not from_domain:
        return False
    if from_domain in host:
        return True
    labels = _domain_labels(from_domain)
    if len(labels) >= 2 and labels[-2] in host:
        return True
    return False


def _has_known_esp_context(email: ParsedEmail) -> bool:
    return bool(analyze_infrastructure(email))


def build_hop_timeline(email: ParsedEmail) -> list[RouteHop]:
    # Received headers are stored newest-first. Reverse for journey order.
    hops: list[RouteHop] = []
    for header in reversed(email.received_headers):
        normalized = " ".join(str(header).split())
        match = RECEIVED_RE.search(normalized)
        if not match:
            continue
        hops.append(
            RouteHop(
                from_host=match.group("from_host") or "unknown",
                by_host=(match.group("by_host") or "unknown").rstrip(";"),
                ip_address=match.group("ip") or "",
                timestamp=(match.group("timestamp") or "").strip(),
                likely_role="MTA",
            )
        )
    return hops


def analyze_route(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    hops = build_hop_timeline(email)
    from_domain = domain_from_email(email.from_address)

    if not hops:
        findings.append(Finding("route", "medium", "No parseable Received headers were found, so the email route could not be reconstructed.", 10))
        return findings

    first = hops[0]
    if from_domain and first.from_host and not _looks_related_to_sender(first.from_host, from_domain):
        # Known ESPs often send from platform-owned hosts that differ from the visible brand domain.
        # If authentication passed, keep that as context instead of scoring a route mismatch.
        if sender_identity_authentication_passed(email) and _has_known_esp_context(email):
            return findings
        findings.append(
            Finding(
                "route",
                "medium",
                f"The first visible sending server is `{first.from_host}`, which is not obviously related to the claimed sender domain `{from_domain}`.",
                15,
            )
        )

    return findings
