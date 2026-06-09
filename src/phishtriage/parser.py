from __future__ import annotations

import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path

from phishtriage.models import AttachmentInfo, ParsedEmail


def _clean_angle_value(value: str | None) -> str:
    if not value:
        return ""
    return value.strip().removeprefix("<").removesuffix(">").strip()


def _content_as_text(part) -> str:
    try:
        content = part.get_content()
    except LookupError:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return str(content)


def _extract_bodies(message) -> tuple[str, str]:
    text_parts: list[str] = []
    html_parts: list[str] = []

    if message.is_multipart():
        iterable = message.walk()
    else:
        iterable = [message]

    for part in iterable:
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_filename():
            continue
        if part.get_content_type() == "text/plain":
            text_parts.append(_content_as_text(part))
        elif part.get_content_type() == "text/html":
            html = _content_as_text(part)
            html_parts.append(html)
            # Preserve enough text for content heuristics without adding BeautifulSoup.
            text_parts.append(html.replace("<", " ").replace(">", " "))

    return "\n".join(text_parts).strip(), "\n".join(html_parts).strip()


def _extract_attachments(message) -> list[AttachmentInfo]:
    attachments: list[AttachmentInfo] = []
    for part in message.walk() if message.is_multipart() else []:
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            AttachmentInfo(
                filename=filename,
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    return attachments


def parse_email(path: Path | str) -> ParsedEmail:
    with Path(path).open("rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)

    from_display_name, from_address = parseaddr(message.get("From", ""))
    _, reply_to = parseaddr(message.get("Reply-To", ""))
    body_text, body_html = _extract_bodies(message)

    return ParsedEmail(
        from_address=from_address,
        from_display_name=from_display_name,
        reply_to=reply_to,
        return_path=_clean_angle_value(message.get("Return-Path")),
        subject=message.get("Subject", ""),
        message_id=_clean_angle_value(message.get("Message-ID")),
        body_text=body_text,
        received_headers=list(message.get_all("Received", [])),
        authentication_results=list(message.get_all("Authentication-Results", [])),
        attachments=_extract_attachments(message),
        body_html=body_html,
        list_unsubscribe=list(message.get_all("List-Unsubscribe", [])),
        delivered_to=list(message.get_all("Delivered-To", [])),
        forwarded_headers=list(message.get_all("X-Forwarded-To", [])) + list(message.get_all("X-Forwarded-For", [])),
        arc_authentication_results=list(message.get_all("ARC-Authentication-Results", [])),
        raw_headers=[f"{name}: {value}" for name, value in message.items()],
    )
