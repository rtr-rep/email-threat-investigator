from __future__ import annotations

URL_REVIEW_GUIDANCE = (
    "Links are extracted for investigation only. Different domains are common in legitimate marketing emails because "
    "of CDNs, tracking, unsubscribe pages, and social media buttons. Start with the links a user would actually click; "
    "check whether the destination matches the claimed brand, uses HTTPS, avoids raw IPs/shorteners, and does not ask "
    "for credentials or payment on an unrelated domain."
)

AUTH_REVIEW_GUIDANCE = (
    "SPF checks whether the sending server is authorized for the envelope sender domain. "
    "DKIM checks whether the message was signed and not changed in transit. "
    "DMARC connects SPF/DKIM to the visible From domain and tells receivers how to handle failures. "
    "Passing results are useful positive evidence, but not every legitimate organization has perfect SPF/DKIM/DMARC, "
    "so treat missing or imperfect results as context unless other phishing indicators are present."
)
