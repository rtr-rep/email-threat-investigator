from phishtriage.models import ParsedEmail
from phishtriage.reply_analyzer import analyze_reply_path


def test_flags_free_mail_reply_to_for_corporate_sender():
    email = ParsedEmail(
        from_address="finance@contoso.example",
        from_display_name="Contoso Finance",
        reply_to="contoso-payments-helpdesk@gmail.com",
        return_path="bounce@mailer.example",
        subject="Urgent payment confirmation required",
        message_id="20260603.123456@contoso.example",
        body_text="Please reply urgently with confirmation of the bank details.",
        received_headers=[],
        authentication_results=[],
        attachments=[],
    )

    findings = analyze_reply_path(email)

    messages = [finding.message for finding in findings]
    assert any("replies go to" in message.lower() for message in messages)
    assert any("free-mail" in message.lower() for message in messages)
    assert any("urgent reply" in message.lower() for message in messages)
