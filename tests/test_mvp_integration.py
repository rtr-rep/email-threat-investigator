from pathlib import Path

from phishtriage.cli import analyze_email


def test_full_mvp_analysis_combines_major_email_threat_signals():
    result = analyze_email(Path("samples/fake-microsoft-login.eml"))

    assert result.verdict == "Dangerous"
    assert result.score >= 90
    categories = {finding.category for finding in result.findings}
    assert {"reply", "auth", "route", "url", "attachment"}.issubset(categories)


def test_full_analysis_surfaces_known_esp_context_as_positive_evidence():
    result = analyze_email(Path("samples/synthetic-salesforce-marketing-email.eml"))

    messages = "\n".join(finding.message for finding in result.findings).lower()
    assert "salesforce marketing cloud" in messages
    assert any(finding.category == "infrastructure" and finding.points == 0 for finding in result.findings)


def test_chronopost_cloud_storage_phish_is_dangerous_and_explained():
    result = analyze_email(Path("samples/synthetic-chronopost-cloud-storage-phish.eml"))

    messages = "\n".join(finding.message for finding in result.findings).lower()
    assert result.verdict == "Dangerous"
    assert "chronopost" in messages
    assert "abnormal title-tag padding" in messages
    assert "cloud-hosted landing page" in messages
    assert "storage.googleapis.com" in messages


def test_paypal_raw_ip_payment_phish_is_dangerous_and_explained():
    result = analyze_email(Path("samples/synthetic-paypal-raw-ip-payment-phish.eml"))

    messages = "\n".join(finding.message for finding in result.findings).lower()
    assert result.verdict == "Dangerous"
    assert "paypal" in messages
    assert "raw ip address" in messages
    assert "dmarc failed" in messages


def test_invoice_attachment_phish_flags_double_extension_and_script_attachment():
    result = analyze_email(Path("samples/synthetic-invoice-attachment-phish.eml"))

    messages = "\n".join(finding.message for finding in result.findings).lower()
    assert result.verdict == "Dangerous"
    assert "suspicious double extension" in messages
    assert "executable or script-like" in messages
    assert "invoice.pdf.exe" in messages


def test_authenticated_omnisend_marketing_email_stays_low_risk():
    result = analyze_email(Path("samples/synthetic-omnisend-splach-marketing.eml"))

    risk_messages = "\n".join(finding.message for finding in result.findings if finding.points > 0).lower()
    all_messages = "\n".join(finding.message for finding in result.findings).lower()
    assert result.verdict == "Low"
    assert "omnisend" in all_messages
    assert "mailgun" in all_messages
    assert "reply" not in risk_messages
    assert "soundestlink" not in risk_messages
