from __future__ import annotations

import re

from phishtriage.models import Finding, ParsedEmail

# Small, explainable allow-list for high-abuse brand display names. This is
# evidence of possible impersonation only; authentication/URL/route checks still
# decide the final score.
BRAND_DOMAIN_HINTS: dict[str, tuple[str, ...]] = {
    "amazon": ("amazon.", "amazonses.com"),
    "apple": ("apple.",),
    "chronopost": ("chronopost.", "laposte.", "laposte.fr"),
    "dhl": ("dhl.",),
    "facebook": ("facebook.", "meta."),
    "fedex": ("fedex.",),
    "google": ("google.",),
    "instagram": ("instagram.", "meta."),
    "linkedin": ("linkedin.",),
    "microsoft": ("microsoft.", "office.", "office365.", "outlook."),
    "netflix": ("netflix.",),
    "paypal": ("paypal.",),
    "ups": ("ups.",),
}

_TITLE_TAG_RE = re.compile(r"<\s*title\b", re.IGNORECASE)


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[1].lower() if "@" in address else ""


def _display_text(email: ParsedEmail) -> str:
    return f"{email.from_display_name} {email.subject}".lower()


def _domain_matches_brand(sender_domain: str, hints: tuple[str, ...]) -> bool:
    return any(hint in sender_domain for hint in hints)


def _title_tag_count(html: str) -> int:
    return len(_TITLE_TAG_RE.findall(html))


def _has_title_after_body_or_html_close(html: str) -> bool:
    lower = html.lower()
    title_pos = lower.find("<title", lower.find("</head>") + len("</head>") if "</head>" in lower else 0)
    return title_pos != -1 and ("</body>" in lower[:title_pos] or "</html>" in lower[:title_pos] or "</head>" in lower[:title_pos])


def analyze_content(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    sender_domain = _domain(email.from_address)
    display_text = _display_text(email)

    for brand, hints in BRAND_DOMAIN_HINTS.items():
        if brand in display_text and sender_domain and not _domain_matches_brand(sender_domain, hints):
            findings.append(
                Finding(
                    "content",
                    "high",
                    f"Display name or subject references `{brand}`, but the sender domain `{sender_domain}` is not obviously related to that brand.",
                    20,
                )
            )
            break

    if email.body_html:
        title_count = _title_tag_count(email.body_html)
        if title_count > 1 or _has_title_after_body_or_html_close(email.body_html):
            findings.append(
                Finding(
                    "content",
                    "medium",
                    "HTML contains abnormal title-tag padding, which is commonly used to hide or dilute spam/phishing content.",
                    15,
                )
            )

    return findings
