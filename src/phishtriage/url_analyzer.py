from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from phishtriage.email_utils import domain_from_email, full_authentication_passed
from phishtriage.infrastructure_analyzer import analyze_infrastructure
from phishtriage.models import ExtractedUrl, Finding, ParsedEmail

URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
CLOUD_LANDING_HOSTS = {
    "storage.googleapis.com",
    "s3.amazonaws.com",
    "blob.core.windows.net",
}
ESP_TRACKING_HOST_PARTS = (
    "soundestlink.",
    "list-manage.com",
    "mailchimpapp.net",
    "sendgrid.net",
    "click.mailgun.com",
    "postmarkapp.com",
)
SOCIAL_HOSTS = {
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "youtube.com",
}
STATIC_ASSET_EXTENSIONS = (".css", ".gif", ".ico", ".jpg", ".jpeg", ".js", ".png", ".svg", ".webp")
PRIMARY_ACTION_WORDS = (
    "account",
    "approve",
    "download",
    "login",
    "open",
    "pay",
    "review",
    "reset",
    "security",
    "shop",
    "sign in",
    "verify",
    "view",
    "wishlist",
)


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[ExtractedUrl] = []
        self._current_href = ""
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() == "a":
            attrs_dict = dict(attrs)
            self._current_href = attrs_dict.get("href", "")
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href:
            self.links.append(ExtractedUrl(href=self._current_href, visible_text="".join(self._current_text).strip()))
            self._current_href = ""
            self._current_text = []


class _LargeClickableAreaParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
        self._href_stack: list[str] = []
        self._body_seen = False
        self._in_body = False
        self._body_visible_chars = 0
        self._anchor_visible_chars: dict[str, int] = {}

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        if tag == "body":
            self._body_seen = True
            self._in_body = True
        elif tag == "a":
            attrs_dict = dict(attrs)
            self._href_stack.append(str(attrs_dict.get("href") or ""))

    def handle_data(self, data: str) -> None:
        if self._body_seen and not self._in_body:
            return
        visible_text = " ".join(data.split())
        if not visible_text:
            return
        text_length = len(visible_text)
        self._body_visible_chars += text_length
        for href in self._href_stack:
            if href:
                self._anchor_visible_chars[href] = self._anchor_visible_chars.get(href, 0) + text_length

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "body":
            self._in_body = False
        elif tag == "a" and self._href_stack:
            self._href_stack.pop()

    def close(self) -> None:
        super().close()
        if self._body_visible_chars < 80:
            return
        for href, anchor_chars in self._anchor_visible_chars.items():
            if anchor_chars / self._body_visible_chars >= 0.6:
                self.urls.append(href)


def extract_urls(email: ParsedEmail) -> list[ExtractedUrl]:
    urls: list[ExtractedUrl] = []
    seen_values: set[str] = set()
    if email.body_html:
        parser = _LinkParser()
        parser.feed(email.body_html)
        urls.extend(parser.links)
        for url in parser.links:
            seen_values.add(url.href)
            if url.visible_text:
                seen_values.add(url.visible_text)
    for match in URL_RE.findall(email.body_text):
        if match in seen_values:
            continue
        urls.append(ExtractedUrl(href=match, visible_text=match))
        seen_values.add(match)
    return urls


def _extract_header_urls(values: list[str]) -> list[str]:
    urls: list[str] = []
    for value in values:
        for match in URL_RE.findall(value):
            urls.append(match.rstrip(">,;"))
    return urls


def _large_clickable_body_urls(email: ParsedEmail) -> list[str]:
    if not email.body_html:
        return []
    parser = _LargeClickableAreaParser()
    parser.feed(email.body_html)
    parser.close()
    return parser.urls


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _domains_align(host: str, sender_domain: str) -> bool:
    if not host or not sender_domain:
        return False
    return host == sender_domain or host.endswith(f".{sender_domain}")


def _is_cloud_html_landing(url: str, host: str) -> bool:
    path = urlparse(url).path.lower()
    return host in CLOUD_LANDING_HOSTS and path.endswith((".html", ".htm"))


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_known_esp_tracking_host(email: ParsedEmail, host: str) -> bool:
    return bool(
        host
        and full_authentication_passed(email)
        and analyze_infrastructure(email)
        and any(part in host for part in ESP_TRACKING_HOST_PARTS)
    )


def categorize_url(email: ParsedEmail, url: ExtractedUrl) -> str:
    """Label links for manual review without turning categories into risk by themselves."""

    href_host = _host(url.href)
    visible_text = url.visible_text.strip().lower()
    href_lower = url.href.lower()
    path = urlparse(url.href).path.lower()

    if href_host and _is_cloud_html_landing(url.href, href_host):
        return "Cloud-hosted landing page"
    if "unsubscribe" in href_lower or "preferences" in href_lower or "unsubscribe" in visible_text or "preferences" in visible_text:
        return "Unsubscribe/preferences"
    if any(href_host == host or href_host.endswith(f".{host}") for host in SOCIAL_HOSTS):
        return "Social/footer"
    if path.endswith(STATIC_ASSET_EXTENSIONS) or "/image/" in path or "/assets/" in path:
        return "CDN/static asset"
    if href_host in {"w3.org", "www.w3.org"}:
        return "Technical/template reference"
    if any(word in visible_text for word in PRIMARY_ACTION_WORDS):
        return "Primary action"
    if href_host and (_is_known_esp_tracking_host(email, href_host) or any(part in href_host for part in ESP_TRACKING_HOST_PARTS)):
        return "ESP tracking/redirect"
    return "Unknown external"


def analyze_urls(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    sender_domain = domain_from_email(email.from_address)
    flagged_cloud_hosts: set[str] = set()

    for url in extract_urls(email):
        href_host = _host(url.href)
        visible_host = _host(url.visible_text) if url.visible_text.startswith(("http://", "https://")) else ""
        if visible_host and href_host and visible_host != href_host:
            findings.append(
                Finding(
                    "url",
                    "high",
                    f"Visible link text shows `{url.visible_text}`, but the actual destination is `{url.href}`.",
                    25,
                )
            )
        if href_host and _is_ip(href_host):
            findings.append(Finding("url", "high", f"Link destination uses a raw IP address: `{url.href}`.", 20))
        if href_host and _is_cloud_html_landing(url.href, href_host) and href_host not in flagged_cloud_hosts:
            flagged_cloud_hosts.add(href_host)
            findings.append(
                Finding(
                    "url",
                    "high",
                    f"Cloud-hosted landing page detected at `{href_host}`: `{url.href}`.",
                    25,
                )
            )
    for unsubscribe_url in _extract_header_urls(email.list_unsubscribe):
        href_host = _host(unsubscribe_url)
        if href_host and not _domains_align(href_host, sender_domain) and not _is_known_esp_tracking_host(email, href_host):
            findings.append(
                Finding(
                    "url",
                    "medium",
                    f"List-Unsubscribe URL host `{href_host}` does not align with sender domain `{sender_domain}`: `{unsubscribe_url}`.",
                    15,
                )
            )
            break
    for wrapper_url in _large_clickable_body_urls(email):
        href_host = _host(wrapper_url)
        if href_host:
            findings.append(
                Finding(
                    "url",
                    "medium",
                    f"Large clickable email body detected; much of the message links to `{href_host}`: `{wrapper_url}`.",
                    15,
                )
            )
            break
    return findings
