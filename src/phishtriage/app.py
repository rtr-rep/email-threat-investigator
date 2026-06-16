from __future__ import annotations

import html
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from phishtriage.cli import analyze_email
from phishtriage.guidance import AUTH_REVIEW_GUIDANCE, URL_REVIEW_GUIDANCE
from phishtriage.models import AnalysisResult, ParsedEmail
from phishtriage.parser import parse_email
from phishtriage.report import defang_indicators, render_markdown_report
from phishtriage.route_analyzer import build_hop_timeline
from phishtriage.url_analyzer import categorize_url, extract_urls

AUTH_QUICK_GUIDE = [
    (
        "SPF",
        "Checks whether the sending mail server is allowed to send for the envelope/Return-Path domain. SPF alone does not prove the visible From address is genuine.",
    ),
    (
        "DMARC",
        "Checks whether SPF or DKIM aligns with the visible From domain — the brand/domain the user actually sees.",
    ),
    (
        "DKIM",
        "Checks for a valid domain signature and whether key parts of the email changed after signing. The signing domain still matters.",
    ),
]
AUTH_HELP = {
    "spf": "SPF checks whether the sending server is authorized for the envelope sender domain. Useful, but SPF alone does not prove the visible From brand.",
    "dkim": "DKIM checks whether the message was signed and not changed in transit. The signing domain still matters.",
    "dmarc": "DMARC connects SPF/DKIM to the visible From domain. A pass is strong positive identity evidence; missing/fail needs context.",
}
_DEFANGED_URL_RE = re.compile(r"hxxps?://[^\s`]+", re.IGNORECASE)
_MAX_UI_URL_LENGTH = 88


def _url_host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _sender_domain(parsed: ParsedEmail) -> str:
    return parsed.from_address.rsplit("@", 1)[-1].lower() if "@" in parsed.from_address else ""


def _url_evidence(parsed: ParsedEmail) -> list[dict[str, str]]:
    sender_domain = _sender_domain(parsed)
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for url in extract_urls(parsed):
        host = _url_host(url.href)
        key = url.href
        if not host or key in seen:
            continue
        seen.add(key)
        aligns = bool(sender_domain and (host == sender_domain or host.endswith(f".{sender_domain}")))
        alignment = "Aligned with sender domain" if aligns else "External/review manually"
        rows.append(
            {
                "host": host,
                "category": categorize_url(parsed, url),
                "alignment": alignment,
                "visible_text": defang_indicators(url.visible_text) if url.visible_text else "Not present",
                "destination": defang_indicators(url.href),
            }
        )
    return rows


def _input_quality(parsed: ParsedEmail) -> dict[str, Any]:
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

    return {
        "status": "limited" if warnings else "complete",
        "warnings": warnings,
        "summary": "Limited email header data was found, so this result may be incomplete." if warnings else "Core email headers are present.",
    }


def _shorten_url_for_ui(url: str) -> str:
    if len(url) <= _MAX_UI_URL_LENGTH:
        return url
    keep_start = 56
    keep_end = 18
    return f"{url[:keep_start]}…{url[-keep_end:]}"


def _display_message(message: str) -> str:
    return _DEFANGED_URL_RE.sub(lambda match: _shorten_url_for_ui(match.group(0)), defang_indicators(message))


def _auth_help_for_message(message: str) -> str:
    lowered = message.lower()
    if "spf" in lowered:
        return AUTH_HELP["spf"]
    if "dkim" in lowered:
        return AUTH_HELP["dkim"]
    if "dmarc" in lowered:
        return AUTH_HELP["dmarc"]
    return ""


def _display_items(category: str, messages: list[str]) -> list[dict[str, str]]:
    return [
        {
            "message": message,
            "help": _auth_help_for_message(message) if category == "auth" else "",
        }
        for message in messages
    ]


def _render_message_item(st: Any, item: dict[str, str]) -> None:
    st.write(f"- {item['message']}")


def _render_auth_quick_guide(st: Any, guide_items: list[tuple[str, str]]) -> None:
    lines = [f"- **{label}**: {description}" for label, description in guide_items]
    lines.append("")
    lines.append("Pass = useful positive evidence. Missing/fail = context, not automatic phishing, unless paired with other suspicious signs.")
    with st.expander("Authentication quick guide", expanded=False):
        st.markdown("\n".join(lines))


def _score_badge(verdict: str, score: int) -> dict[str, str]:
    colors = {
        "Low": {"background": "#166534", "border": "#22c55e"},
        "Suspicious": {"background": "#92400e", "border": "#f59e0b"},
        "High Risk": {"background": "#9a3412", "border": "#f97316"},
        "Dangerous": {"background": "#991b1b", "border": "#ef4444"},
    }
    selected = colors.get(verdict, colors["Suspicious"])
    return {
        "label": f"Risk score {score}/100",
        "background": selected["background"],
        "border": selected["border"],
    }


def _score_breakdown(result: AnalysisResult) -> list[dict[str, int | str]]:
    totals: dict[str, int] = {}
    for finding in result.findings:
        if finding.points <= 0:
            continue
        totals[finding.category.upper()] = totals.get(finding.category.upper(), 0) + finding.points
    return [
        {"category": category, "points": points}
        for category, points in sorted(totals.items(), key=lambda item: item[1], reverse=True)
    ]


def _render_score_breakdown(st: Any, breakdown: list[dict[str, int | str]]) -> None:
    if not breakdown:
        return
    with st.expander("Why this score?", expanded=False):
        st.dataframe(breakdown, hide_index=True, use_container_width=True)
        st.caption("Only scored risk findings are included here. Positive/context evidence is excluded. Total score is capped at 100.")


def _render_verdict_summary(st: Any, display: dict[str, Any]) -> None:
    badge = display["score_badge"]
    st.markdown(
        f"""
        <div style="margin: 0 0 1.1rem 0;">
            <div style="font-size: 0.9rem; color: rgba(250,250,250,0.68); margin-bottom: 0.2rem;">Verdict</div>
            <div style="font-size: 2.45rem; line-height: 1.08; font-weight: 500; margin-bottom: 0.45rem;">{html.escape(display["verdict"])}</div>
            <span style="display: inline-block; border: 1px solid {badge['border']}; background: {badge['background']}; color: #fff; border-radius: 999px; padding: 0.18rem 0.58rem; font-size: 0.82rem; font-weight: 600;">
                {html.escape(badge["label"])}
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def build_display_model(parsed: ParsedEmail, result: AnalysisResult) -> dict[str, Any]:
    findings_by_category: dict[str, list[str]] = {}
    positive_evidence_by_category: dict[str, list[str]] = {}
    for finding in result.findings:
        target = positive_evidence_by_category if finding.points == 0 else findings_by_category
        target.setdefault(finding.category, []).append(_display_message(finding.message))

    findings_items_by_category = {
        category: _display_items(category, messages) for category, messages in findings_by_category.items()
    }
    positive_evidence_items_by_category = {
        category: _display_items(category, messages) for category, messages in positive_evidence_by_category.items()
    }

    return {
        "verdict": result.verdict,
        "score": result.score,
        "score_badge": _score_badge(result.verdict, result.score),
        "score_breakdown": _score_breakdown(result),
        "primary_actions": result.recommended_actions,
        "findings_by_category": findings_by_category,
        "positive_evidence_by_category": positive_evidence_by_category,
        "findings_items_by_category": findings_items_by_category,
        "positive_evidence_items_by_category": positive_evidence_items_by_category,
        "auth_review_guidance": AUTH_REVIEW_GUIDANCE,
        "auth_quick_guide": AUTH_QUICK_GUIDE,
        "input_quality": _input_quality(parsed),
        "sender": {
            "from": f"{parsed.from_display_name} <{parsed.from_address}>",
            "reply_to": parsed.reply_to or "Not present",
            "return_path": parsed.return_path or "Not present",
            "subject": parsed.subject,
            "message_id": parsed.message_id or "Not present",
        },
        "email_journey": [
            {
                "from_server": hop.from_host,
                "ip": hop.ip_address or "Unknown",
                "by_server": hop.by_host,
                "role": hop.likely_role,
                "timestamp": hop.timestamp,
            }
            for hop in build_hop_timeline(parsed)
        ],
        "url_review_guidance": URL_REVIEW_GUIDANCE,
        "url_evidence": _url_evidence(parsed),
        "attachments": [
            {
                "filename": attachment.filename,
                "content_type": attachment.content_type,
                "size": attachment.size,
                "sha256": attachment.sha256,
            }
            for attachment in parsed.attachments
        ],
        "report_markdown": render_markdown_report(parsed, result),
    }


def _apply_theme_styles(st: Any) -> None:
    st.markdown(
        """
        <style>
        /* Inline technical evidence chips: domains, hosts, hashes, and defanged URLs.
           Cyan/blue reads as neutral evidence, avoiding green's "safe/pass" signal. */
        code:not(pre code) {
            color: #7dd3fc !important;
            background-color: rgba(14, 116, 144, 0.16) !important;
            border: 1px solid rgba(125, 211, 252, 0.22) !important;
            border-radius: 0.28rem !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def run_streamlit_app() -> None:
    import streamlit as st

    st.set_page_config(page_title="PhishTriage", page_icon="🛡️", layout="wide")
    _apply_theme_styles(st)
    st.title("PhishTriage — Email Threat Investigator")
    st.caption("Upload a suspicious .eml file and get a plain-English phishing investigation report.")

    uploaded = st.file_uploader("Choose a .eml file", type=["eml"])
    if not uploaded:
        st.info("Start by uploading a suspicious email file. The tool analyzes it locally and does not click links or open attachments.")
        return

    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as handle:
        handle.write(uploaded.getvalue())
        temp_path = Path(handle.name)

    parsed = parse_email(temp_path)
    result = analyze_email(temp_path)
    display = build_display_model(parsed, result)

    _render_verdict_summary(st, display)
    if display["input_quality"]["status"] == "limited":
        st.warning(display["input_quality"]["summary"])
        with st.expander("Input quality details", expanded=True):
            for warning in display["input_quality"]["warnings"]:
                st.write(f"- {warning}")

    if display["verdict"] in {"High Risk", "Dangerous"}:
        st.error("This email has strong suspicious indicators. Do not interact with it until reviewed.")
    elif display["verdict"] == "Suspicious":
        st.warning("This email has suspicious indicators. Review before interacting.")
    else:
        st.success("No major suspicious indicators were detected by the current checks.")

    left, right = st.columns([2, 1])
    with left:
        st.subheader("Positive evidence")
        if display["positive_evidence_items_by_category"]:
            for category, items in display["positive_evidence_items_by_category"].items():
                with st.expander(category.upper(), expanded=True):
                    for item in items:
                        _render_message_item(st, item)
        else:
            st.write("No explicit positive evidence extracted yet.")

        st.subheader("Risk findings")
        if display["findings_items_by_category"]:
            for category, items in display["findings_items_by_category"].items():
                with st.expander(category.upper(), expanded=True):
                    for item in items:
                        _render_message_item(st, item)
        else:
            st.write("No suspicious findings detected by the current checks.")

    with right:
        st.subheader("What to do now")
        for action in display["primary_actions"]:
            st.write(f"- {action}")
        _render_score_breakdown(st, display["score_breakdown"])
        _render_auth_quick_guide(st, display["auth_quick_guide"])

    st.subheader("Sender and reply evidence")
    st.table(display["sender"])

    st.subheader("Email journey / Header Hop Timeline")
    st.caption("Shows only the Received headers present in the .eml export. Many Gmail exports expose the sending ESP/MTA and Gmail MX hop, but not the full MUA → MSA → MTA → MDA chain.")
    if display["email_journey"]:
        st.table(display["email_journey"])
    else:
        st.write("No parseable route hops found.")

    st.subheader("URL evidence")
    st.caption(display["url_review_guidance"])
    if display["url_evidence"]:
        st.table(display["url_evidence"])
    else:
        st.write("No URLs detected in the email body.")

    st.subheader("Attachments")
    if display["attachments"]:
        st.table(display["attachments"])
    else:
        st.write("No attachments detected.")

    st.download_button(
        "Download Markdown report",
        data=display["report_markdown"],
        file_name="email-threat-investigation-report.md",
        mime="text/markdown",
    )


if __name__ == "__main__":
    run_streamlit_app()
