from __future__ import annotations

from email.utils import parseaddr

from phishtriage.models import ParsedEmail


def authentication_text(email: ParsedEmail) -> str:
    return "\n".join(email.authentication_results + email.arc_authentication_results).lower()


def full_authentication_passed(email: ParsedEmail) -> bool:
    text = authentication_text(email)
    return "spf=pass" in text and "dkim=pass" in text and "dmarc=pass" in text


def sender_identity_authentication_passed(email: ParsedEmail) -> bool:
    text = authentication_text(email)
    return "spf=pass" in text and ("dkim=pass" in text or "dmarc=pass" in text)


def domain_from_email(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].lower().rstrip(".")


def parsed_address_domain(address: str) -> str:
    _, parsed = parseaddr(address or "")
    value = parsed or address or ""
    value = value.strip().removeprefix("<").removesuffix(">").strip()
    return domain_from_email(value)


def has_forwarding_indicators(email: ParsedEmail) -> bool:
    return bool(email.forwarded_headers or len(email.delivered_to) > 1 or email.arc_authentication_results)
