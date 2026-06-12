from __future__ import annotations

import re
from urllib.parse import urlparse

from phishtriage.guidance import AUTH_REVIEW_GUIDANCE, URL_REVIEW_GUIDANCE
from phishtriage.models import AnalysisResult, ParsedEmail
from phishtriage.route_analyzer import build_hop_timeline
from phishtriage.url_analyzer import categorize_url, extract_urls

_URL_RE = re.compile(r"\bhttps?://[^\s<>)\]}`]+", re.IGNORECASE)


def defang_indicators(text: str) -> str:
    """Make URLs/IPs safe for reports without hiding the evidence."""

    def _defang_url(match: re.Match[str]) -> str:
        url = match.group(0)
        url = re.sub(r"^https://", "hxxps://", url, flags=re.IGNORECASE)
        url = re.sub(r"^http://", "hxxp://", url, flags=re.IGNORECASE)
        return url.replace(".", "[.]")

    return _URL_RE.sub(_defang_url, text)


def _input_quality_warnings(parsed: ParsedEmail) -> list[str]:
    warnings: list[str] = []
    if not parsed.from_address:
        warnings.append("From header is missing")
    if not parsed.subject:
        warnings.append("Subject header is missing")
    if not parsed.message_id:
        warnings.append("Message-ID header is missing")
    if not parsed.received_headers:
        warnings.append("No Received headers found")
    if not parsed.authentication_results:
        warnings.append("No Authentication-Results headers found")
    return warnings


def _evidence_completeness_section(parsed: ParsedEmail) -> str:
    warnings = _input_quality_warnings(parsed)
    if not warnings:
        return "Core email headers are present."
    warning_lines = "\n".join(f"- {warning}" for warning in warnings)
    return f"Limited email header data was found, so this result may be incomplete.\n\n{warning_lines}"


def _url_host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _sender_domain(parsed: ParsedEmail) -> str:
    return parsed.from_address.rsplit("@", 1)[-1].lower() if "@" in parsed.from_address else ""


def _domains_align(host: str, sender_domain: str) -> bool:
    return bool(host and sender_domain and (host == sender_domain or host.endswith(f".{sender_domain}")))


def _markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _url_evidence_table(parsed: ParsedEmail) -> str:
    sender_domain = _sender_domain(parsed)
    rows: list[str] = []
    seen: set[str] = set()
    for url in extract_urls(parsed):
        host = _url_host(url.href)
        if not host or url.href in seen:
            continue
        seen.add(url.href)
        alignment = "Aligned with sender domain" if _domains_align(host, sender_domain) else "External/review manually"
        visible_text = defang_indicators(url.visible_text) if url.visible_text else "Not present"
        rows.append(
            "| "
            + " | ".join(
                [
                    _markdown_cell(host),
                    categorize_url(parsed, url),
                    alignment,
                    _markdown_cell(visible_text),
                    _markdown_cell(defang_indicators(url.href)),
                ]
            )
            + " |"
        )
    return "\n".join(rows) or "| No URLs detected in the email body | - | - | - | - |"


def render_markdown_report(parsed: ParsedEmail, result: AnalysisResult) -> str:
    positive_evidence = "\n".join(
        f"- [{finding.category}] {defang_indicators(finding.message)}" for finding in result.findings if finding.points == 0
    )
    if not positive_evidence:
        positive_evidence = "- No explicit positive evidence extracted yet."

    findings = "\n".join(
        f"- [{finding.category}] {defang_indicators(finding.message)} (+{finding.points})"
        for finding in result.findings
        if finding.points > 0
    )
    if not findings:
        findings = "- No suspicious findings detected by the current checks."

    actions = "\n".join(f"- {action}" for action in result.recommended_actions)
    evidence_completeness = _evidence_completeness_section(parsed)
    route_rows = []
    for index, hop in enumerate(build_hop_timeline(parsed), start=1):
        route_rows.append(f"| {index} | {hop.from_host} | {hop.ip_address or 'Unknown'} | {hop.by_host} | {hop.likely_role} |")
    route_table = "\n".join(route_rows) or "| - | No parseable route hops | - | - | - |"

    attachment_rows = []
    for attachment in parsed.attachments:
        attachment_rows.append(
            f"| {attachment.filename} | {attachment.content_type} | {attachment.size} | `{attachment.sha256}` |"
        )
    attachment_table = "\n".join(attachment_rows) or "| No attachments detected | - | - | - |"
    url_table = _url_evidence_table(parsed)

    return f"""# Email Threat Investigation Report

## Executive Summary

Verdict: {result.verdict}
Score: {result.score}/100

## Positive Evidence

{positive_evidence}

## Authentication quick guide

{AUTH_REVIEW_GUIDANCE}

## Evidence Completeness

{evidence_completeness}

## Why this is suspicious

{findings}

## What to do now

{actions}

## Sender and Reply Evidence

| Field | Value |
| --- | --- |
| From | {parsed.from_display_name} <{parsed.from_address}> |
| Reply-To | {parsed.reply_to or "Not present"} |
| Return-Path | {parsed.return_path or "Not present"} |
| Subject | {parsed.subject} |
| Message-ID | {parsed.message_id or "Not present"} |

## Email Journey / Header Hop Timeline

| # | From server | IP | By server | Likely role |
| --- | --- | --- | --- | --- |
{route_table}

## URL Evidence

{URL_REVIEW_GUIDANCE} Destinations are defanged for safer reporting.

| Host | Category | Alignment | Visible text | Destination |
| --- | --- | --- | --- | --- |
{url_table}

## Attachment Evidence

| Filename | Content type | Size bytes | SHA256 |
| --- | --- | --- | --- |
{attachment_table}

## Technical Notes

This MVP performs local, explainable analysis only. It does not open attachments, detonate files, click links, quarantine messages, or connect to a live mailbox.
"""
