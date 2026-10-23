"""Command-line interface for AccessLens AI accessibility scanner."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .scanner import AccessibilityScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="accesslens",
        description="AccessLens AI: Automated web accessibility scanner powered by Playwright and axe-core.",
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="Target public HTTP/HTTPS URL to scan.",
    )
    parser.add_argument(
        "--url",
        dest="flag_url",
        help="Alternative flag specifying the target URL.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        help="Optional path to write the structured JSON report file.",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=float,
        default=25.0,
        help="Navigation and evaluation timeout in seconds (default: 25.0).",
    )
    parser.add_argument(
        "--allow-local",
        dest="allow_local",
        action="store_true",
        default=False,
        help="Allow scanning localhost and private IP addresses (for local testing only).",
    )
    parser.add_argument(
        "--minified",
        dest="minified",
        action="store_true",
        default=False,
        help="Output compact single-line JSON instead of indented JSON.",
    )
    parser.add_argument(
        "--summary",
        dest="summary",
        action="store_true",
        default=False,
        help="Print an executive summary to stderr before the JSON payload.",
    )
    parser.add_argument(
        "--serve",
        dest="serve",
        action="store_true",
        default=False,
        help="Launch the AccessLens AI interactive web dashboard server.",
    )
    parser.add_argument(
        "--port",
        dest="port",
        type=int,
        default=8000,
        help="Port for the web dashboard server (default: 8000).",
    )
    return parser


def main(args: list[str] | None = None) -> int:
    parser = build_parser()
    opts = parser.parse_args(args)

    if opts.serve:
        import os
        import uvicorn
        from .server import app
        if opts.allow_local:
            os.environ["ACCESSLENS_ALLOW_LOCAL"] = "1"
        print(f"Starting AccessLens AI Dashboard on http://127.0.0.1:{opts.port}")
        uvicorn.run(app, host="127.0.0.1", port=opts.port)
        return 0

    target_url = opts.flag_url or opts.url
    if not target_url:
        parser.print_usage(sys.stderr)
        sys.stderr.write("accesslens error: Target URL is required. Provide a URL as argument or via --url.\n")
        return 2

    scanner = AccessibilityScanner(
        timeout_seconds=opts.timeout,
        allow_local=opts.allow_local,
        headless=True,
    )

    report = scanner.scan_url(target_url)
    json_output = report.to_json(indent=None if opts.minified else 2)

    if opts.summary:
        sys.stderr.write(f"\n--- AccessLens AI Scan Summary ---\n")
        sys.stderr.write(f"Target URL   : {report.url}\n")
        sys.stderr.write(f"Status       : {report.status}\n")
        sys.stderr.write(f"Duration     : {report.duration_ms:.1f} ms\n")
        if report.summary:
            sys.stderr.write(f"Violations   : {report.summary.total_violations} (Critical: {report.summary.critical_count}, Serious: {report.summary.serious_count}, Moderate: {report.summary.moderate_count}, Minor: {report.summary.minor_count})\n")
            sys.stderr.write(f"Passes       : {report.summary.passes_count}\n")
        if report.error:
            sys.stderr.write(f"Error        : [{report.error_category}] {report.error}\n")
        sys.stderr.write(f"-----------------------------------\n\n")

    # Output to stdout
    print(json_output)

    # Optional file output
    if opts.output_file:
        out_path = Path(opts.output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json_output, encoding="utf-8")
        if opts.summary:
            sys.stderr.write(f"Report written to: {out_path.resolve()}\n")

    return 0 if report.status == "SUCCESS" else 1


if __name__ == "__main__":
    sys.exit(main())
