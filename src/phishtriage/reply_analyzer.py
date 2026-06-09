from __future__ import annotations

from phishtriage.infrastructure_analyzer import analyze_infrastructure
from phishtriage.models import Finding, ParsedEmail

FREE_MAIL_DOMAINS = {
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
}

REPLY_URGENCY_PHRASES = (
    "reply urgently",
    "reply immediately",
    "confirm bank details",
    "confirmation of the bank details",
    "send payment proof",
    "confirm payment",
)


def _domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].lower()


def _auth_passed(email: ParsedEmail) -> bool:
    text = "\n".join(email.authentication_results + email.arc_authentication_results).lower()
    return "spf=pass" in text and "dkim=pass" in text and "dmarc=pass" in text


def _has_known_esp_context(email: ParsedEmail) -> bool:
    return bool(analyze_infrastructure(email))


def _is_esp_marketing_reply_context(email: ParsedEmail, reply_domain: str) -> bool:
    return bool(reply_domain and reply_domain not in FREE_MAIL_DOMAINS and _auth_passed(email) and _has_known_esp_context(email))


def analyze_reply_path(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    from_domain = _domain(email.from_address)
    reply_domain = _domain(email.reply_to)

    if email.reply_to and from_domain and reply_domain and from_domain != reply_domain:
        if _is_esp_marketing_reply_context(email, reply_domain):
            findings.append(
                Finding(
                    "reply",
                    "info",
                    f"Reply-To uses `{reply_domain}` while the visible sender uses ESP domain `{from_domain}`; authenticated marketing platforms often route replies to the brand or campaign operator.",
                    0,
                )
            )
        else:
            findings.append(
                Finding(
                    category="reply",
                    severity="high",
                    message=(
                        f"Replies go to `{email.reply_to}`, but the visible sender uses "
                        f"`{email.from_address}`. The reply destination is a different domain."
                    ),
                    points=20,
                )
            )

    if reply_domain in FREE_MAIL_DOMAINS and from_domain and from_domain not in FREE_MAIL_DOMAINS:
        findings.append(
            Finding(
                category="reply",
                severity="high",
                message=(
                    f"Free-mail Reply-To detected: replies go to `{reply_domain}` even though "
                    f"the email appears to come from `{from_domain}`."
                ),
                points=25,
            )
        )

    body = email.body_text.lower()
    if any(phrase in body for phrase in REPLY_URGENCY_PHRASES):
        findings.append(
            Finding(
                category="content",
                severity="medium",
                message="Urgent reply/payment language detected in the email body.",
                points=10,
            )
        )

    return findings
