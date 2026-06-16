from phishtriage.email_utils import visible_sender_authenticated
from phishtriage.models import ParsedEmail


def _email(auth: str) -> ParsedEmail:
    return ParsedEmail(
        from_address="sender@example.com",
        from_display_name="Sender",
        reply_to="",
        return_path="bounce@example.com",
        subject="Test message",
        message_id="test@example.com",
        body_text="Hello",
        received_headers=[],
        authentication_results=[auth] if auth else [],
        attachments=[],
    )


def test_spf_dkim_pass_dmarc_fail_is_not_authenticated_enough():
    # DMARC is mandatory: warnings should NOT be suppressed when DMARC fails,
    # even with SPF and DKIM passing.
    email = _email("spf=pass dkim=pass dmarc=fail")
    assert visible_sender_authenticated(email) is False


def test_spf_pass_dkim_missing_dmarc_pass_is_authenticated_enough():
    email = _email("spf=pass dmarc=pass")
    assert visible_sender_authenticated(email) is True


def test_spf_missing_dkim_pass_dmarc_pass_is_authenticated_enough():
    email = _email("dkim=pass dmarc=pass")
    assert visible_sender_authenticated(email) is True


def test_spf_pass_only_is_not_authenticated_enough():
    # SPF alone is not enough to trust the visible sender identity.
    email = _email("spf=pass")
    assert visible_sender_authenticated(email) is False


def test_all_pass_is_authenticated_enough():
    email = _email("spf=pass dkim=pass dmarc=pass")
    assert visible_sender_authenticated(email) is True


def test_all_fail_is_not_authenticated_enough():
    email = _email("spf=fail dkim=fail dmarc=fail")
    assert visible_sender_authenticated(email) is False
