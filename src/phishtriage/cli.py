from __future__ import annotations

from pathlib import Path

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


def _print_result(result: AnalysisResult) -> None:
    print(f"Verdict: {result.verdict}")
    print(f"Score: {result.score}/100")

    positive_evidence = [finding for finding in result.findings if finding.points == 0]
    print("\nPositive evidence:")
    if positive_evidence:
        for finding in positive_evidence:
            print(f"- [{finding.category}] {finding.message}")
    else:
        print("- No explicit positive evidence extracted yet.")

    risk_findings = [finding for finding in result.findings if finding.points > 0]
    print("\nWhy this is suspicious:")
    if risk_findings:
        for finding in risk_findings:
            print(f"- [{finding.category}] {finding.message}")
    else:
        print("- No suspicious findings detected by the current checks.")
    print("\nRecommended action:")
    for action in result.recommended_actions:
        print(f"- {action}")


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
        _print_result(result)
        if args.out:
            output_path = Path(args.out)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(render_markdown_report(parsed, result), encoding="utf-8")
            print(f"\nReport written to: {output_path}")
