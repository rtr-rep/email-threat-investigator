from phishtriage.models import AnalysisResult, Finding, ParsedEmail
from phishtriage.report import defang_indicators, render_markdown_report


def test_markdown_report_is_plain_english_and_includes_evidence():
    parsed = ParsedEmail(
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
    result = AnalysisResult(
        verdict="High Risk",
        score=60,
        findings=[Finding(category="reply", severity="high", message="Replies go to Gmail", points=25)],
        recommended_actions=["Do not reply", "Report the email to IT/security"],
    )

    report = render_markdown_report(parsed, result)

    assert "# Email Threat Investigation Report" in report
    assert "Verdict: High Risk" in report
    assert "Why this is suspicious" in report
    assert "Replies go to Gmail" in report
    assert "Do not reply" in report
    assert "contoso-payments-helpdesk@gmail.com" in report


def test_markdown_report_defangs_url_findings():
    parsed = ParsedEmail(
        from_address="security@example.com",
        from_display_name="Security",
        reply_to="",
        return_path="",
        subject="Security alert",
        message_id="",
        body_text="",
        received_headers=[],
        authentication_results=[],
        attachments=[],
    )
    result = AnalysisResult(
        verdict="Dangerous",
        score=95,
        findings=[
            Finding(
                category="url",
                severity="high",
                message="Visible link text shows `https://example.com/security`, but the actual destination is `http://198.51.100.77/login`.",
                points=25,
            )
        ],
        recommended_actions=["Do not click links"],
    )

    report = render_markdown_report(parsed, result)

    assert "hxxps://example[.]com/security" in report
    assert "hxxp://198[.]51[.]100[.]77/login" in report
    assert "https://example.com/security" not in report
    assert "http://198.51.100.77/login" not in report


def test_markdown_report_separates_positive_evidence_from_risk_findings():
    parsed = ParsedEmail(
        from_address="updates@example.com",
        from_display_name="Example Updates",
        reply_to="",
        return_path="bounce@example.com",
        subject="Account update",
        message_id="20260604@example.com",
        body_text="Your account was updated.",
        received_headers=[],
        authentication_results=[],
        attachments=[],
    )
    result = AnalysisResult(
        verdict="Low",
        score=0,
        findings=[
            Finding(category="auth", severity="info", message="SPF passed for sender infrastructure.", points=0),
            Finding(category="auth", severity="info", message="DKIM passed for sender domain.", points=0),
            Finding(category="auth", severity="info", message="DMARC passed for header From domain.", points=0),
        ],
        recommended_actions=["No immediate action needed"],
    )

    report = render_markdown_report(parsed, result)

    assert "## Positive Evidence" in report
    assert "SPF passed" in report
    suspicious_section = report.split("## Why this is suspicious", 1)[1].split("## What to do now", 1)[0]
    assert "SPF passed" not in suspicious_section
    assert "No suspicious findings detected by the current checks." in suspicious_section


def test_markdown_report_explains_spf_dkim_dmarc_relationship():
    parsed = ParsedEmail(
        from_address="updates@example.com",
        from_display_name="Example Updates",
        reply_to="",
        return_path="bounce@example.com",
        subject="Account update",
        message_id="20260604@example.com",
        body_text="Your account was updated.",
        received_headers=[],
        authentication_results=[],
        attachments=[],
    )
    result = AnalysisResult(verdict="Low", score=0, findings=[], recommended_actions=["No immediate action needed"])

    report = render_markdown_report(parsed, result)

    assert "## Authentication quick guide" in report
    assert "SPF checks whether the sending server is authorized" in report
    assert "DKIM checks whether the message was signed" in report
    assert "DMARC connects SPF/DKIM to the visible From domain" in report
    assert "not every legitimate organization has perfect SPF/DKIM/DMARC" in report


def test_markdown_report_warns_when_core_email_headers_are_missing():
    parsed = ParsedEmail(
        from_address="",
        from_display_name="",
        reply_to="",
        return_path="",
        subject="",
        message_id="",
        body_text="Renamed body-only text samples can look deceptively clean.",
        received_headers=[],
        authentication_results=[],
        attachments=[],
    )
    result = AnalysisResult(
        verdict="Low",
        score=0,
        findings=[],
        recommended_actions=["Review manually because header evidence is limited"],
    )

    report = render_markdown_report(parsed, result)

    assert "## Evidence Completeness" in report
    assert "Limited email header data was found" in report
    assert "From header is missing" in report
    assert "No Received headers found" in report
    assert "No Authentication-Results headers found" in report


def test_markdown_report_includes_defanged_url_evidence_table():
    parsed = ParsedEmail(
        from_address="alerts@brand.example",
        from_display_name="Brand Alerts",
        reply_to="alerts@brand.example",
        return_path="alerts@brand.example",
        subject="Review account notice",
        message_id="<notice@brand.example>",
        body_text="Visit https://storage.googleapis.com/brand-login/index.html",
        received_headers=[],
        authentication_results=[],
        attachments=[],
    )
    result = AnalysisResult(
        verdict="Suspicious",
        score=40,
        findings=[],
        recommended_actions=["Do not click links"],
    )

    report = render_markdown_report(parsed, result)

    assert "## URL Evidence" in report
    assert "Links are extracted for investigation only" in report
    assert "Different domains are common in legitimate marketing emails" in report
    assert "| Host | Category | Alignment | Visible text | Destination |" in report
    assert "storage.googleapis.com" in report
    assert "Cloud-hosted landing page" in report
    assert "External/review manually" in report
    assert "hxxps://storage[.]googleapis[.]com/brand-login/index[.]html" in report
    assert "https://storage.googleapis.com" not in report


def test_defang_indicators_makes_urls_and_ips_safe_to_display():
    text = "Visit https://evil.example/login or http://198.51.100.77/pay now."

    safe_text = defang_indicators(text)

    assert "hxxps://evil[.]example/login" in safe_text
    assert "hxxp://198[.]51[.]100[.]77/pay" in safe_text
    assert "https://evil.example/login" not in safe_text
    assert "http://198.51.100.77/pay" not in safe_text
