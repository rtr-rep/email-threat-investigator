from pathlib import Path

from phishtriage.models import ParsedEmail
from phishtriage.parser import parse_email
from phishtriage.url_analyzer import analyze_urls, extract_urls


def test_url_analyzer_flags_visible_text_mismatch_and_ip_url():
    parsed = parse_email(Path("samples/fake-microsoft-login.eml"))

    urls = extract_urls(parsed)
    findings = analyze_urls(parsed)

    assert urls[0].visible_text == "https://microsoft.com/security"
    assert urls[0].href == "http://198.51.100.77/login"
    assert not any(url.href == "https://microsoft.com/security" for url in urls)
    messages = "\n".join(f.message for f in findings).lower()
    assert "visible link text" in messages
    assert "ip address" in messages


def test_url_analyzer_flags_cloud_storage_links_unrelated_to_sender():
    parsed = parse_email(Path("samples/synthetic-iptv-cloud-storage-spam.eml"))

    urls = extract_urls(parsed)
    findings = analyze_urls(parsed)

    assert any("storage.googleapis.com" in url.href for url in urls)
    messages = "\n".join(f.message for f in findings).lower()
    assert "cloud-hosted landing page" in messages
    assert "storage.googleapis.com" in messages
    assert "does not align with sender domain" in messages
    assert sum(f.points for f in findings) >= 30


def test_url_analyzer_flags_list_unsubscribe_domain_mismatch():
    parsed = parse_email(Path("samples/synthetic-iptv-cloud-storage-spam.eml"))

    findings = analyze_urls(parsed)

    messages = "\n".join(f.message for f in findings).lower()
    assert "list-unsubscribe" in messages
    assert "storage.googleapis.com" in messages
    assert "does not align with sender domain" in messages


def test_url_analyzer_flags_large_clickable_body_wrapper():
    parsed = parse_email(Path("samples/synthetic-iptv-cloud-storage-spam.eml"))

    findings = analyze_urls(parsed)

    messages = "\n".join(f.message for f in findings).lower()
    assert "large clickable" in messages
    assert "storage.googleapis.com" in messages


def test_url_analyzer_flags_valid_html_large_clickable_body_wrapper():
    parsed = ParsedEmail(
        from_address="billing@example-alerts.test",
        from_display_name="Billing Notice",
        reply_to="billing@example-alerts.test",
        return_path="bounce@example-alerts.test",
        subject="Review your invoice",
        message_id="<wrapper@example-alerts.test>",
        body_text="Review your invoice and payment status immediately before access is suspended.",
        body_html="""
        <html>
          <body>
            <a href="https://storage.googleapis.com/example-alerts/invoice.html">
              <div>
                <h1>Review your invoice</h1>
                <p>Your payment method needs attention. Review your invoice and payment status immediately.</p>
                <p>Failure to respond may interrupt access to your account and billing portal.</p>
              </div>
            </a>
          </body>
        </html>
        """,
        received_headers=[],
        authentication_results=[],
        attachments=[],
    )

    findings = analyze_urls(parsed)

    messages = "\n".join(f.message for f in findings).lower()
    assert "large clickable" in messages
    assert "storage.googleapis.com" in messages


def test_extract_urls_deduplicates_repeated_plain_text_urls():
    parsed = ParsedEmail(
        from_address="alerts@example.test",
        from_display_name="Alerts",
        reply_to="alerts@example.test",
        return_path="alerts@example.test",
        subject="Links",
        message_id="<links@example.test>",
        body_text=(
            "Review https://example.test/login then review https://example.test/login again. "
            "Backup link: https://example.test/support"
        ),
        received_headers=[],
        authentication_results=[],
        attachments=[],
    )

    urls = extract_urls(parsed)

    assert [url.href for url in urls] == ["https://example.test/login", "https://example.test/support"]


def test_url_analyzer_does_not_score_plain_marketing_url_mismatches():
    parsed = ParsedEmail(
        from_address="noreply@steampowered.com",
        from_display_name="Steam",
        reply_to="noreply@steampowered.com",
        return_path="noreply@steampowered.com",
        subject="Wishlist item on sale",
        message_id="<sale@smtp.steampowered.com>",
        body_text="Visit https://store.steampowered.com/app/1608230/Planet_of_Lana/",
        body_html="""
        <a href="https://store.steampowered.com/wishlist/">View your Wishlist</a>
        <a href="https://www.valvesoftware.com/en/">Valve</a>
        <a href="https://twitter.com/steam">Follow us on X</a>
        <img src="https://shared.fastly.steamstatic.com/store_item_assets/capsule.jpg" />
        """,
        received_headers=[],
        authentication_results=[
            "mx.google.com; dkim=pass header.i=@steampowered.com; spf=pass smtp.mailfrom=noreply@steampowered.com; dmarc=pass header.from=steampowered.com"
        ],
        arc_authentication_results=[],
        attachments=[],
    )

    findings = analyze_urls(parsed)

    messages = "\n".join(f.message for f in findings).lower()
    assert "does not align with sender domain" not in messages
    assert sum(f.points for f in findings) == 0
