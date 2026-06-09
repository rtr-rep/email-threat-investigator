from __future__ import annotations

from phishtriage.models import Finding, ParsedEmail

# These indicators identify common Email Service Provider (ESP) infrastructure.
# Treating them as context, not risk, helps reduce false positives for bulk and
# transactional mail while still leaving auth/reply/URL checks to score abuse.
ESP_INDICATORS = {
    "Salesforce Marketing Cloud": (
        "x-sfmc-stack",
        "s1.y.mc.salesforce.com",
        "mta.email",
        "x-job:",
    ),
    "SendGrid": (
        "sendgrid.net",
        "x-sg-eid",
        "smtpapi",
    ),
    "Mailchimp": (
        "mailchimpapp.net",
        "list-manage.com",
        "x-mailchimp",
    ),
    "Omnisend/Soundest": (
        "omnisend.email",
        "soundest.email",
        "soundestlink.com",
        "soundestlink.example",
        "feedback-id: campaign:omnisend",
    ),
    "Amazon SES": (
        "amazonses.com",
        "x-ses-",
    ),
    "Mailgun": (
        "mailgun.org",
        "x-mailgun-",
    ),
    "Postmark": (
        "postmarkapp.com",
        "x-pm-",
    ),
}


def _evidence_text(email: ParsedEmail) -> str:
    parts = []
    parts.extend(email.raw_headers)
    parts.extend(email.received_headers)
    parts.extend(email.authentication_results)
    parts.extend(email.arc_authentication_results)
    parts.extend(email.list_unsubscribe)
    parts.append(email.return_path)
    parts.append(email.body_text)
    parts.append(email.body_html)
    return "\n".join(str(part) for part in parts if part).lower()


def analyze_infrastructure(email: ParsedEmail) -> list[Finding]:
    evidence = _evidence_text(email)
    findings: list[Finding] = []

    for platform, indicators in ESP_INDICATORS.items():
        if any(indicator in evidence for indicator in indicators):
            findings.append(
                Finding(
                    "infrastructure",
                    "info",
                    f"{platform} marketing/ESP infrastructure indicators were found. Treat related bounce, tracking, and unsubscribe domains as context rather than automatic phishing evidence.",
                    0,
                )
            )

    return findings
