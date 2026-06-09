# PhishTriage feature prioritization notes

Working note for the next prioritization pass. Do not treat this as a final roadmap yet.

## Newly discovered real-email test cases

### Legitimate transactional ecommerce email
Example pattern: Galaxus delivery notification.

Observed needs:
- Recognize related organization subdomains instead of flagging them as unrelated route infrastructure.
- Show SPF/DKIM/DMARC pass results as positive evidence.
- Explain legitimate ESP/bounce/tracking infrastructure.
- Avoid scary wording when the route anomaly is explainable.

Current status:
- SPF/DKIM/DMARC pass evidence added.
- Related Galaxus-style infrastructure false positive reduced.
- UI separates positive evidence from risk findings.
- CLI output and Markdown reports separate positive evidence from risk findings.

### Header-poor / renamed text files
Example pattern: text corpus sample renamed to `.eml`.

Observed needs:
- Warn when key headers are missing.
- Explain that the result may be incomplete.
- Distinguish limited-input confidence from actual low risk.

Current status:
- Input quality warning added for missing From, Subject, Message-ID, Received, and Authentication-Results headers.

### Legitimate marketing email in spam folder with Gmail forwarding
Example pattern: BestSecret / Salesforce Marketing Cloud message forwarded between Gmail accounts.

Observed needs:
- Detect forwarded messages using X-Forwarded-To, X-Forwarded-For, multiple Delivered-To, and ARC headers.
- Preserve original sender-auth evidence when forwarding changes final Return-Path/SPF context.
- Avoid false-positive Reply-To or Return-Path mismatch warnings when they are explainable by forwarding or ESP reply-routing.
- Identify Salesforce Marketing Cloud and similar ESPs.
- Explain tracked links and web-view links as marketing infrastructure when aligned with sender/ESP.
- Improve route labels for forwarding chains.

Current status:
- Forwarding indicators are detected from `X-Forwarded-To`, `X-Forwarded-For`, multiple `Delivered-To`, and `ARC-Authentication-Results` headers.
- ARC-authenticated upstream SPF/DKIM/DMARC pass context is preserved as positive evidence.
- Known ESP/marketing infrastructure indicators are recognized for broad platforms, starting with Salesforce Marketing Cloud plus generic support for SendGrid, Mailchimp, Amazon SES, Mailgun, and Postmark indicators.
- Route mismatch scoring is softened when known ESP context is present and authentication passes.

### Suspicious IPTV spam with cloud-hosted landing page
Example pattern: KING IPTV spam using random sender infrastructure, Gmail Reply-To, and Google Cloud Storage HTML links.

Observed needs:
- Make extracted URLs visible in the UI without visiting them.
- Flag cloud-hosted HTML landing pages when they are unrelated to the sender domain.
- Flag URL host / sender domain mismatch.
- Keep URLs defanged in UI/report-facing display.
- Later: detect DKIM permerror, missing DMARC, suspicious List-Unsubscribe, giant clickable wrappers, and IPTV spam category.

Current status:
- URL evidence section added to UI display model.
- Google Cloud Storage HTML landing pages are flagged as high-risk URL findings.
- URL hosts that do not align with the sender domain are flagged as risk findings.
- Suspicious `List-Unsubscribe` URL hosts that do not align with the sender domain are flagged as risk findings.
- Large clickable body wrappers are flagged as risk findings.
- DKIM `permerror` and `temperror` are handled explicitly.
- Missing DMARC results are flagged when Authentication-Results exists but no DMARC verdict is present.

## Candidate functionality list for prioritization

### Needed for credible MVP / GitHub showcase
- Privacy-safe report mode/redaction.
- Input-quality confidence warning in reports, not just UI.
- Forwarding/ARC awareness.
- Known ESP/marketing platform recognition.
- Better route role labels from real headers only.
- Safer handling of Reply-To mismatches for known ESP reply-routing domains.
- README/demo screenshots using only synthetic or redacted data.
- `.gitignore` protection for real emails, lab samples, and generated sensitive reports.

### Good to have
- Link tracking explanation for known aligned domains.
- Bulk/marketing-email classification.
- Body obfuscation indicators such as excessive zero-width characters, hidden preheader padding, and HTML-heavy marketing structure.
- Confidence score separate from risk score.
- Structured JSON export for analysts.
- More synthetic sample emails covering forwarding, ESP marketing, benign newsletters, BEC, credential phishing, malicious attachments.

### Special / advanced
- External URL reputation enrichment, disabled by default.
- Offline IOC extraction bundle.
- Sandbox workflow documentation.
- Optional local-only YARA/ClamAV attachment scanning.
- PCAP/case-study integration for Malware-Traffic-Analysis-style labs.
- Multi-email batch analysis.

## Ground rules
- Prioritize broad phishing-triage behaviors over one-off sample-specific detectors. If a finding only applies to a niche campaign, generalize it into a reusable pattern or leave it as a note.
- Do not fabricate missing MUA/MSA/MTA/MDA steps; show only evidence present in headers.
- Do not commit real `.eml` files or reports containing personal data.
- Redact credentials, tokens, email addresses, personal names, addresses, order numbers, and tracking numbers in public artifacts.
