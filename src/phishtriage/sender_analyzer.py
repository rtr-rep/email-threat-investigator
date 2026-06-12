from __future__ import annotations

import re
from email.utils import parseaddr

from phishtriage.email_utils import has_forwarding_indicators, parsed_address_domain, sender_identity_authentication_passed
from phishtriage.infrastructure_analyzer import analyze_infrastructure
from phishtriage.models import Finding, ParsedEmail
from phishtriage.reply_analyzer import FREE_MAIL_DOMAINS

_IP_FRAGMENT_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_KNOWN_LOCAL_PARTS = {
    "admin",
    "billing",
    "bounce",
    "contact",
    "hello",
    "info",
    "mailer-daemon",
    "news",
    "newsletter",
    "no-reply",
    "noreply",
    "notifications",
    "postmaster",
    "return",
    "returns",
    "security",
    "service",
    "support",
}


def _address_domain(address: str) -> str:
    return parsed_address_domain(address)


def _address_local(address: str) -> str:
    _, parsed = parseaddr(address or "")
    value = parsed or address or ""
    value = value.strip().removeprefix("<").removesuffix(">").strip()
    if "@" not in value:
        return ""
    return value.rsplit("@", 1)[0]


def _base_domain(domain: str) -> str:
    labels = [label for label in domain.lower().split(".") if label]
    if len(labels) < 2:
        return domain.lower()
    return ".".join(labels[-2:])


def _domains_align(first: str, second: str) -> bool:
    if not first or not second:
        return False
    first = first.lower()
    second = second.lower()
    return first == second or first.endswith(f".{second}") or second.endswith(f".{first}") or _base_domain(first) == _base_domain(second)


def _has_known_esp_context(email: ParsedEmail) -> bool:
    return bool(analyze_infrastructure(email))


def _random_token_score(value: str) -> int:
    token = value.strip("._-+")
    if len(token) < 8:
        return 0
    lowered = token.lower()
    if lowered in _KNOWN_LOCAL_PARTS or any(lowered.startswith(f"{known}-") for known in _KNOWN_LOCAL_PARTS):
        return 0

    alnum = "".join(character for character in token if character.isalnum())
    if len(alnum) < 8:
        return 0

    score = 0
    if any(character.islower() for character in token) and any(character.isupper() for character in token):
        score += 1
    if any(character.isalpha() for character in token) and any(character.isdigit() for character in token):
        score += 1
    vowels = sum(1 for character in lowered if character in "aeiou")
    if vowels / max(sum(1 for character in lowered if character.isalpha()), 1) < 0.25:
        score += 1
    if re.search(r"[bcdfghjklmnpqrstvwxyz\d]{5,}", lowered):
        score += 1
    if len(alnum) % 2 == 0 and alnum[: len(alnum) // 2].lower() == alnum[len(alnum) // 2 :].lower():
        score += 2
    return score


def _looks_generated_token(value: str) -> bool:
    return _random_token_score(value) >= 2


def _looks_random_from_address(email: ParsedEmail) -> bool:
    local = _address_local(email.from_address)
    domain = _address_domain(email.from_address)
    labels = domain.split(".")[:-1]
    return _looks_generated_token(local) or any(_looks_generated_token(label) for label in labels)


def _generated_return_path_reasons(return_domain: str) -> list[str]:
    labels = [label for label in return_domain.split(".") if label]
    ip_like_fragments = _IP_FRAGMENT_RE.findall(return_domain)
    generated_labels = [label for label in labels[:-2] if _looks_generated_token(label)]
    reasons: list[str] = []
    if len(return_domain) > 80 or len(labels) > 6:
        reasons.append("excessive length/depth")
    if len(ip_like_fragments) >= 1:
        reasons.append("IP-like fragments")
    if len(generated_labels) >= 2:
        reasons.append("random-looking labels")
    return reasons


def analyze_sender_identity(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    from_domain = _address_domain(email.from_address)
    return_domain = _address_domain(email.return_path)
    esp_context = _has_known_esp_context(email)
    forwarding_context = has_forwarding_indicators(email)
    auth_passed = sender_identity_authentication_passed(email)

    if _looks_random_from_address(email):
        findings.append(
            Finding(
                "sender",
                "high",
                f"From address appears randomly generated: `{email.from_address}`. Random-looking sender local-parts or domains are common in spam/phishing campaigns.",
                20,
            )
        )

    if return_domain:
        reasons = _generated_return_path_reasons(return_domain)
        if reasons and not esp_context:
            findings.append(
                Finding(
                    "sender",
                    "high",
                    f"Return-Path uses an unusually long/generated domain with {', '.join(reasons)}: `{return_domain}`.",
                    25,
                )
            )

    if from_domain and return_domain and not _domains_align(from_domain, return_domain):
        if (auth_passed and esp_context) or forwarding_context:
            findings.append(
                Finding(
                    "sender",
                    "info",
                    f"Return-Path differs from visible From domain (`{return_domain}` vs `{from_domain}`), but authentication, ESP, or forwarding context explains the mismatch.",
                    0,
                )
            )
        elif return_domain in FREE_MAIL_DOMAINS and from_domain not in FREE_MAIL_DOMAINS:
            findings.append(
                Finding(
                    "sender",
                    "high",
                    f"Return-Path uses free-mail domain `{return_domain}` while the visible From domain is `{from_domain}`.",
                    15,
                )
            )
        elif not auth_passed and not esp_context and any(finding.points > 0 for finding in findings):
            findings.append(
                Finding(
                    "sender",
                    "medium",
                    f"Return-Path domain `{return_domain}` does not align with visible From domain `{from_domain}`, and no passing authentication or trusted ESP/forwarding context explains the difference.",
                    10,
                )
            )

    return findings
