from phishtriage.content_analyzer import analyze_content
from phishtriage.models import ParsedEmail


def _email(**overrides):
    defaults = dict(
        from_address="alerts@random-us-domain.example",
        from_display_name="Chronopost📦",
        reply_to="",
        return_path="",
        subject="Suivez votre colis maintenant",
        message_id="20260604@example.test",
        body_text="Bonjour cher client, votre colis est suspendu.",
        body_html="<html><head><title>Delivery</title></head><body>Pay customs fees now.</body></html>",
        received_headers=[],
        authentication_results=[],
        attachments=[],
    )
    defaults.update(overrides)
    return ParsedEmail(**defaults)


def test_content_analyzer_flags_known_brand_display_name_with_unrelated_sender_domain():
    findings = analyze_content(_email())

    messages = "\n".join(f.message for f in findings).lower()
    assert "brand" in messages
    assert "chronopost" in messages
    assert sum(f.points for f in findings) >= 20


def test_content_analyzer_allows_brand_display_name_when_sender_domain_matches_brand():
    findings = analyze_content(_email(from_address="tracking@chronopost.fr"))

    messages = "\n".join(f.message for f in findings).lower()
    assert "chronopost" not in messages


def test_content_analyzer_flags_html_noise_padding_title_tags_outside_normal_head():
    email = _email(
        from_display_name="Random Sender",
        body_html=(
            "<html><head><title>Delivery</title></head><body>Pay fees</body></html>"
            "<center><title>Unrelated gardening article and random filler text used as padding</title></center>"
        ),
    )

    findings = analyze_content(email)

    messages = "\n".join(f.message for f in findings).lower()
    assert "padding" in messages or "hidden" in messages
    assert "title" in messages
