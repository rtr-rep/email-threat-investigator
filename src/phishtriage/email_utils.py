from __future__ import annotations

from email.utils import parseaddr

from phishtriage.models import ParsedEmail


def authentication_text(email: ParsedEmail) -> str:
    return "\n".join(email.authentication_results + email.arc_authentication_results).lower()


def visible_sender_authenticated(email: ParsedEmail) -> bool:
    """Whether the visible sender identity is authenticated well enough to suppress warnings.

    Policy: DMARC must pass AND at least one of SPF or DKIM must pass.

    DMARC is mandatory because it is the alignment signal for the visible From
    domain; SPF or DKIM alone is not enough to trust the displayed sender. A
    missing or failing DMARC deliberately keeps warnings visible, since that is
    exactly the pattern this triage tool exists to surface.
    """
    text = authentication_text(email)
    dmarc_passed = "dmarc=pass" in text
    spf_passed = "spf=pass" in text
    dkim_passed = "dkim=pass" in text
    return dmarc_passed and (spf_passed or dkim_passed)


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
