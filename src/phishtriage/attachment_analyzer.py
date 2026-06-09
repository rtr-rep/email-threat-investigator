from __future__ import annotations

from pathlib import Path

from phishtriage.models import Finding, ParsedEmail

SUSPICIOUS_EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".hta",
    ".lnk",
    ".iso",
    ".img",
    ".docm",
    ".xlsm",
}

COMMON_DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"}


def analyze_attachments(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    for attachment in email.attachments:
        suffixes = [suffix.lower() for suffix in Path(attachment.filename).suffixes]
        final_suffix = suffixes[-1] if suffixes else ""
        if len(suffixes) >= 2 and suffixes[-2] in COMMON_DECOY_EXTENSIONS and final_suffix in SUSPICIOUS_EXECUTABLE_EXTENSIONS:
            findings.append(
                Finding(
                    "attachment",
                    "high",
                    f"Attachment `{attachment.filename}` uses a suspicious double extension.",
                    25,
                )
            )
        if final_suffix in SUSPICIOUS_EXECUTABLE_EXTENSIONS:
            findings.append(
                Finding(
                    "attachment",
                    "high",
                    f"Attachment `{attachment.filename}` appears to be executable or script-like content.",
                    30,
                )
            )
    return findings
