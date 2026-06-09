from dataclasses import replace
from pathlib import Path

from phishtriage.auth_analyzer import analyze_authentication
from phishtriage.models import AnalysisResult, Finding
from phishtriage.scoring import score_findings
from phishtriage.url_analyzer import analyze_urls

from phishtriage.app import _render_auth_quick_guide, _render_message_item, _render_score_breakdown, _render_verdict_summary, build_display_model
from phishtriage.cli import analyze_email
from phishtriage.parser import parse_email


def test_build_display_model_groups_findings_for_non_technical_ui():
    path = Path("samples/fake-microsoft-login.eml")
    parsed = parse_email(path)
    result = analyze_email(path)

    display = build_display_model(parsed, result)

    assert display["verdict"] == "Dangerous"
    assert display["score"] == 100
    assert "Do not reply" in display["primary_actions"]
    assert "reply" in display["findings_by_category"]
    assert "auth" in display["findings_by_category"]
    assert display["email_journey"][0]["from_server"] == "unknown-vps-host.test"
    assert display["attachments"][0]["filename"] == "invoice.pdf.exe"
    url_messages = "\n".join(display["findings_by_category"]["url"])
    assert "hxxps://microsoft[.]com/security" in url_messages
    assert "hxxp://198[.]51[.]100[.]77/login" in url_messages
    assert "https://microsoft.com/security" not in url_messages
    assert display["report_markdown"].startswith("# Email Threat Investigation Report")


def test_build_display_model_separates_positive_auth_evidence_from_risk_findings():
    parsed = replace(
        parse_email(Path("samples/legitimate-company-email.eml")),
        authentication_results=[
            "mx.google.com; dkim=pass header.i=@notifications.galaxus.ch; spf=pass smtp.mailfrom=em9954.notifications.galaxus.ch; dmarc=pass header.from=galaxus.ch"
        ],
    )
    result = score_findings(analyze_authentication(parsed))

    display = build_display_model(parsed, result)

    evidence = "\n".join(display["positive_evidence_by_category"]["auth"])
    assert "SPF passed" in evidence
    assert "DKIM passed" in evidence
    assert "DMARC passed" in evidence
    assert "auth" not in display["findings_by_category"]


def test_build_display_model_adds_verdict_aware_risk_score_badge():
    parsed = parse_email(Path("samples/legitimate-company-email.eml"))

    low = build_display_model(parsed, AnalysisResult("Low", 15, [], []))["score_badge"]
    suspicious = build_display_model(parsed, AnalysisResult("Suspicious", 35, [], []))["score_badge"]
    high = build_display_model(parsed, AnalysisResult("High Risk", 65, [], []))["score_badge"]
    dangerous = build_display_model(parsed, AnalysisResult("Dangerous", 90, [], []))["score_badge"]

    assert low == {"label": "Risk score 15/100", "background": "#166534", "border": "#22c55e"}
    assert suspicious == {"label": "Risk score 35/100", "background": "#92400e", "border": "#f59e0b"}
    assert high == {"label": "Risk score 65/100", "background": "#9a3412", "border": "#f97316"}
    assert dangerous == {"label": "Risk score 90/100", "background": "#991b1b", "border": "#ef4444"}


def test_render_verdict_summary_uses_colored_badge_not_green_metric_delta():
    class FakeStreamlit:
        def __init__(self):
            self.markdown_calls = []
            self.metric_calls = []

        def markdown(self, text, unsafe_allow_html=False):
            self.markdown_calls.append((text, unsafe_allow_html))

        def metric(self, *args, **kwargs):
            self.metric_calls.append((args, kwargs))

    fake_st = FakeStreamlit()

    _render_verdict_summary(
        fake_st,
        {
            "verdict": "High Risk",
            "score_badge": {"label": "Risk score 65/100", "background": "#9a3412", "border": "#f97316"},
        },
    )

    assert fake_st.metric_calls == []
    rendered, unsafe = fake_st.markdown_calls[0]
    assert unsafe is True
    assert "High Risk" in rendered
    assert "Risk score 65/100" in rendered
    assert "#9a3412" in rendered
    assert "#f97316" in rendered
    assert "↑" not in rendered


def test_build_display_model_adds_score_breakdown_by_risk_category():
    parsed = parse_email(Path("samples/legitimate-company-email.eml"))
    result = AnalysisResult(
        "High Risk",
        65,
        [
            Finding("sender", "high", "Generated sender", 20),
            Finding("sender", "high", "Generated return path", 25),
            Finding("sender", "medium", "Mismatch", 10),
            Finding("auth", "medium", "DMARC missing", 10),
            Finding("infrastructure", "info", "Known ESP context", 0),
        ],
        [],
    )

    display = build_display_model(parsed, result)

    assert display["score_breakdown"] == [
        {"category": "SENDER", "points": 55},
        {"category": "AUTH", "points": 10},
    ]


def test_render_score_breakdown_uses_collapsed_explainer_dropdown():
    class FakeExpander:
        def __init__(self, fake_st):
            self.fake_st = fake_st

        def __enter__(self):
            return self.fake_st

        def __exit__(self, exc_type, exc, traceback):
            return False

    class FakeStreamlit:
        def __init__(self):
            self.expander_calls = []
            self.dataframe_calls = []
            self.caption_calls = []

        def expander(self, label, expanded=False):
            self.expander_calls.append((label, expanded))
            return FakeExpander(self)

        def dataframe(self, data, hide_index=False, use_container_width=False):
            self.dataframe_calls.append((data, hide_index, use_container_width))

        def caption(self, text):
            self.caption_calls.append(text)

    fake_st = FakeStreamlit()

    _render_score_breakdown(fake_st, [{"category": "SENDER", "points": 55}, {"category": "AUTH", "points": 10}])

    assert fake_st.expander_calls == [("Why this score?", False)]
    assert fake_st.dataframe_calls == [([{"category": "SENDER", "points": 55}, {"category": "AUTH", "points": 10}], True, True)]
    assert "capped at 100" in fake_st.caption_calls[0]


def test_build_display_model_exposes_plain_english_auth_guidance():
    parsed = parse_email(Path("samples/legitimate-company-email.eml"))
    result = score_findings([])

    display = build_display_model(parsed, result)

    guidance = display["auth_review_guidance"]
    assert "SPF checks whether the sending server is authorized" in guidance
    assert "DKIM checks whether the message was signed" in guidance
    assert "DMARC connects SPF/DKIM to the visible From domain" in guidance
    assert "not every legitimate organization has perfect SPF/DKIM/DMARC" in guidance


def test_build_display_model_exposes_better_auth_quick_guide_items_for_dropdown():
    parsed = parse_email(Path("samples/legitimate-company-email.eml"))
    result = score_findings([])

    display = build_display_model(parsed, result)

    assert display["auth_quick_guide"] == [
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


def test_build_display_model_warns_when_input_has_too_few_email_headers():
    parsed = replace(
        parse_email(Path("samples/legitimate-company-email.eml")),
        from_address="",
        from_display_name="",
        return_path="",
        subject="",
        message_id="",
        received_headers=[],
        authentication_results=[],
    )
    result = score_findings([])

    display = build_display_model(parsed, result)

    assert display["input_quality"]["status"] == "limited"
    assert "From header is missing" in display["input_quality"]["warnings"]
    assert "No Received headers found" in display["input_quality"]["warnings"]
    assert "No Authentication-Results headers found" in display["input_quality"]["warnings"]


def test_build_display_model_exposes_url_evidence_for_cloud_storage_spam():
    parsed = parse_email(Path("samples/synthetic-iptv-cloud-storage-spam.eml"))
    result = score_findings(analyze_urls(parsed))

    display = build_display_model(parsed, result)

    assert display["url_evidence"]
    assert display["url_evidence"][0]["host"] == "storage.googleapis.com"
    assert display["url_evidence"][0]["alignment"] == "External/review manually"
    assert "Different domains are common" in display["url_review_guidance"]
    url_messages = "\n".join(display["findings_by_category"]["url"])
    assert "cloud-hosted landing page" in url_messages.lower()
    assert "storage[.]googleapis[.]com" in url_messages


def test_build_display_model_labels_url_categories_for_manual_review():
    parsed = parse_email(Path("samples/synthetic-omnisend-splach-marketing.eml"))
    result = analyze_email(Path("samples/synthetic-omnisend-splach-marketing.eml"))

    display = build_display_model(parsed, result)
    assert any(
        row["host"] == "swv.soundestlink.example" and row["category"] == "ESP tracking/redirect"
        for row in display["url_evidence"]
    )
    assert any(
        row["visible_text"] == "Shop now" and row["category"] == "Primary action"
        for row in display["url_evidence"]
    )
    assert any(
        row["visible_text"] == "Unsubscribe" and row["category"] == "Unsubscribe/preferences"
        for row in display["url_evidence"]
    )


def test_build_display_model_shortens_long_urls_for_ui_risk_messages_but_keeps_report_complete():
    parsed = parse_email(Path("samples/synthetic-iptv-cloud-storage-spam.eml"))
    result = score_findings(analyze_urls(parsed))

    display = build_display_model(parsed, result)
    url_messages = "\n".join(display["findings_by_category"]["url"])

    assert "…" in url_messages
    assert "socialimpact-investments/socialimpact" not in url_messages
    assert "socialimpact-investments/socialimpact" in display["report_markdown"]


def test_build_display_model_attaches_inline_auth_help_to_detected_auth_evidence():
    parsed = replace(
        parse_email(Path("samples/legitimate-company-email.eml")),
        authentication_results=[
            "mx.google.com; dkim=pass header.i=@notifications.galaxus.ch; spf=pass smtp.mailfrom=em9954.notifications.galaxus.ch; dmarc=pass header.from=galaxus.ch"
        ],
    )
    result = score_findings(analyze_authentication(parsed))

    display = build_display_model(parsed, result)
    auth_items = display["positive_evidence_items_by_category"]["auth"]

    assert any(item["message"].startswith("SPF passed") and "envelope sender" in item["help"] for item in auth_items)
    assert any(item["message"].startswith("DKIM passed") and "signed" in item["help"] for item in auth_items)
    assert any(item["message"].startswith("DMARC passed") and "visible From domain" in item["help"] for item in auth_items)


def test_render_message_item_keeps_evidence_bullets_plain_without_inline_auth_popovers():
    class FakeStreamlit:
        def __init__(self):
            self.write_calls = []

        def write(self, text):
            self.write_calls.append(text)

    fake_st = FakeStreamlit()

    _render_message_item(fake_st, {"message": "SPF passed", "help": "SPF help text"})

    assert fake_st.write_calls == ["- SPF passed"]


def test_render_auth_quick_guide_uses_collapsed_dropdown_with_muted_copy():
    class FakeExpander:
        def __init__(self, fake_st):
            self.fake_st = fake_st

        def __enter__(self):
            return self.fake_st

        def __exit__(self, exc_type, exc, traceback):
            return False

    class FakeStreamlit:
        def __init__(self):
            self.expander_calls = []
            self.markdown_calls = []

        def expander(self, label, expanded=False):
            self.expander_calls.append((label, expanded))
            return FakeExpander(self)

        def markdown(self, text, unsafe_allow_html=False):
            self.markdown_calls.append((text, unsafe_allow_html))

    fake_st = FakeStreamlit()

    _render_auth_quick_guide(
        fake_st,
        [
            ("SPF", "Checks whether the sending mail server is allowed to send for the envelope/Return-Path domain."),
            ("DMARC", "Checks whether SPF or DKIM aligns with the visible From domain."),
            ("DKIM", "Checks for a valid domain signature and whether key parts changed after signing."),
        ],
    )

    assert fake_st.expander_calls == [("Authentication quick guide", False)]
    rendered, unsafe = fake_st.markdown_calls[0]
    assert unsafe is False
    assert rendered.count("- **") == 3
    assert "**SPF**" in rendered
    assert "**DMARC**" in rendered
    assert "**DKIM**" in rendered
    assert "background:" not in rendered
    assert "Pass = useful positive evidence" in rendered
