from __future__ import annotations

from phishtriage.email_utils import has_forwarding_indicators
from phishtriage.models import Finding, ParsedEmail


def _has_any_result(text: str, mechanism: str) -> bool:
    return f"{mechanism}=" in text or f"{mechanism} " in text


def _all_major_auth_passed(text: str) -> bool:
    return ("spf=pass" in text or "spf pass" in text) and ("dkim=pass" in text or "dkim pass" in text) and ("dmarc=pass" in text or "dmarc pass" in text)


def analyze_authentication(email: ParsedEmail) -> list[Finding]:
    text = "\n".join(email.authentication_results).lower()
    arc_text = "\n".join(email.arc_authentication_results).lower()
    findings: list[Finding] = []

    if has_forwarding_indicators(email):
        message = "Forwarding indicators detected"
        if email.arc_authentication_results:
            message += "; ARC-Authentication-Results preserves upstream authentication context"
        if _all_major_auth_passed(arc_text):
            message += ", and original authentication passed before forwarding"
        message += "."
        findings.append(Finding("auth", "info", message, 0))

    if "spf=fail" in text or "spf fail" in text:
        findings.append(Finding("auth", "high", "SPF failed: the sending server was not authorized for the envelope sender domain.", 15))
    elif "spf=pass" in text or "spf pass" in text:
        findings.append(Finding("auth", "info", "SPF passed: the sending server was authorized for the envelope sender domain.", 0))

    if "dkim=fail" in text or "dkim fail" in text:
        findings.append(Finding("auth", "medium", "DKIM failed: the message signature could not be validated.", 10))
    elif "dkim=permerror" in text or "dkim permerror" in text:
        findings.append(Finding("auth", "medium", "DKIM permanent error: the message had a signature, but the receiver could not validate it because of a permanent configuration/key problem.", 10))
    elif "dkim=temperror" in text or "dkim temperror" in text:
        findings.append(Finding("auth", "low", "DKIM temporary error: the message signature could not be checked due to a temporary receiver or DNS issue.", 5))
    elif "dkim=pass" in text or "dkim pass" in text:
        findings.append(Finding("auth", "info", "DKIM passed: at least one message signature validated successfully.", 0))

    if "dmarc=fail" in text or "dmarc fail" in text:
        findings.append(Finding("auth", "high", "DMARC failed: the visible From domain did not pass domain-alignment checks.", 20))
    elif "dmarc=pass" in text or "dmarc pass" in text:
        findings.append(Finding("auth", "info", "DMARC passed: the visible From domain passed domain-alignment checks.", 0))
    elif email.authentication_results and not _has_any_result(text, "dmarc") and not _has_any_result(arc_text, "dmarc"):
        findings.append(Finding("auth", "medium", "DMARC result is missing: SPF may have passed for the envelope sender, but the visible From domain did not show a DMARC alignment result.", 10))

    return findings
