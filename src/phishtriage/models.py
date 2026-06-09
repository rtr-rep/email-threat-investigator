from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ParsedEmail:
    from_address: str
    from_display_name: str
    reply_to: str
    return_path: str
    subject: str
    message_id: str
    body_text: str
    received_headers: list[str]
    authentication_results: list[str]
    attachments: list[AttachmentInfo]
    body_html: str = ""
    list_unsubscribe: list[str] = field(default_factory=list)
    delivered_to: list[str] = field(default_factory=list)
    forwarded_headers: list[str] = field(default_factory=list)
    arc_authentication_results: list[str] = field(default_factory=list)
    raw_headers: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RouteHop:
    from_host: str
    by_host: str
    ip_address: str
    timestamp: str
    likely_role: str


@dataclass(frozen=True)
class ExtractedUrl:
    href: str
    visible_text: str


@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    message: str
    points: int


@dataclass(frozen=True)
class AnalysisResult:
    verdict: str
    score: int
    findings: list[Finding]
    recommended_actions: list[str]
