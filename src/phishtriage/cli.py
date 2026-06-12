from __future__ import annotations

from pathlib import Path
from textwrap import wrap

from phishtriage.attachment_analyzer import analyze_attachments
from phishtriage.auth_analyzer import analyze_authentication
from phishtriage.content_analyzer import analyze_content
from phishtriage.infrastructure_analyzer import analyze_infrastructure
from phishtriage.models import AnalysisResult
from phishtriage.parser import parse_email
from phishtriage.reply_analyzer import analyze_reply_path
from phishtriage.report import render_markdown_report
from phishtriage.route_analyzer import analyze_route
from phishtriage.scoring import score_findings
from phishtriage.sender_analyzer import analyze_sender_identity
from phishtriage.url_analyzer import analyze_urls


def analyze_email(path: Path | str) -> AnalysisResult:
    parsed = parse_email(path)
    findings = []
    findings.extend(analyze_reply_path(parsed))
    findings.extend(analyze_content(parsed))
    findings.extend(analyze_sender_identity(parsed))
    findings.extend(analyze_authentication(parsed))
    findings.extend(analyze_infrastructure(parsed))
    findings.extend(analyze_route(parsed))
    findings.extend(analyze_urls(parsed))
    findings.extend(analyze_attachments(parsed))
    return score_findings(findings)


CATEGORY_HEADINGS = {
    "reply": "Sender / reply path",
    "sender": "Sender / reply path",
    "auth": "Authentication",
    "content": "Content",
    "url": "URLs",
    "attachment": "Attachments",
    "route": "Route evidence",
    "infrastructure": "Infrastructure context",
}


def _print_wrapped_bullet(text: str, *, indent: str = "  ", width: int = 100) -> None:
    lines = wrap(text, width=width, break_long_words=False, break_on_hyphens=False)
    if not lines:
        print("-")
        return
    print(f"- {lines[0]}")
    for line in lines[1:]:
        print(f"{indent}{line}")


def _print_numbered_item(index: int, text: str, *, width: int = 100) -> None:
    prefix = f"{index}. "
    lines = wrap(text, width=width - len(prefix), break_long_words=False, break_on_hyphens=False)
    if not lines:
        print(prefix.rstrip())
        return
    print(f"{prefix}{lines[0]}")
    for line in lines[1:]:
        print(f"{' ' * len(prefix)}{line}")


def _print_result(result: AnalysisResult, eml_path: Path | str | None = None) -> None:
    print("PhishTriage Analysis")
    if eml_path is not None:
        print(f"File: {Path(eml_path).name}")
    print(f"\n[!] {result.verdict.upper()} — Risk score {result.score}/100")

    positive_evidence = [finding for finding in result.findings if finding.points == 0]
    risk_findings = [finding for finding in result.findings if finding.points > 0]

    if risk_findings:
        print("\nTop risks:")
        for index, finding in enumerate(risk_findings[:4], start=1):
            _print_numbered_item(index, finding.message)

    print("\nPositive evidence:")
    if positive_evidence:
        for finding in positive_evidence:
            _print_wrapped_bullet(finding.message)
    else:
        print("- None found.")

    print("\nWhy this is suspicious:")
    if risk_findings:
        grouped_findings: dict[str, list] = {}
        for finding in risk_findings:
            heading = CATEGORY_HEADINGS.get(finding.category, finding.category.title())
            grouped_findings.setdefault(heading, []).append(finding)

        for heading, findings in grouped_findings.items():
            print(f"\n{heading}")
            for finding in findings:
                _print_wrapped_bullet(finding.message)
    else:
        print("- No suspicious findings detected by the current checks.")
    print("\nRecommended action:")
    for action in result.recommended_actions:
        _print_wrapped_bullet(action)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="phishtriage")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="Analyze a suspicious .eml file")
    analyze.add_argument("eml_path")
    analyze.add_argument("--out", help="Write a Markdown report to this path")
    args = parser.parse_args()

    if args.command == "analyze":
        parsed = parse_email(args.eml_path)
        result = analyze_email(args.eml_path)
        _print_result(result, args.eml_path)
        if args.out:
            output_path = Path(args.out)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(render_markdown_report(parsed, result), encoding="utf-8")
            print(f"\nReport written to: {output_path}")
