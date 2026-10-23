"""Accessibility scanning engine powered by Playwright and axe-core.

Performs deterministic, browser-grade accessibility auditing with strict SSRF
guards, redirect verification, and structured reporting.
"""

from __future__ import annotations

from datetime import datetime, timezone
import os
import time
from typing import Any
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeoutError, sync_playwright

from .models import ElementNode, ScanReport, ScanSummary, Violation
from .security import SecurityError, URLValidator
from .vendor import get_axe_script


def _categorize_playwright_error(err: Exception) -> tuple[str, str]:
    """Inspect Playwright exception to extract a precise error category and user-facing diagnostic."""
    err_msg = str(err)
    err_lower = err_msg.lower()
    if any(
        phrase in err_lower
        for phrase in (
            "executable doesn't exist",
            "please run the following command to download",
            "browsertype.launch",
            "cannot find chrome",
            "cannot find chromium",
            "error while loading shared libraries",
            "no such file or directory",
        )
    ):
        return (
            "BROWSER_UNAVAILABLE",
            "Playwright Chromium browser executable is not installed or available in this runtime environment. "
            f"Diagnostic details: {err_msg[:250]}. "
            "Playwright requires a headless browser binary to perform DOM rendering and axe-core analysis. "
            "For local or persistent container hosts (Docker, AWS App Runner, ECS, VM), run 'playwright install chromium' "
            "or set CHROMIUM_PATH/PLAYWRIGHT_CHROMIUM_PATH. "
            "Note: Serverless runtimes (such as Vercel Functions) do not include native Linux browser binaries by default.",
        )
    if "err_name_not_resolved" in err_lower:
        return (
            "DNS_FAILURE",
            f"Target hostname could not be resolved by browser: {err_msg[:200]}",
        )
    return (
        "EXECUTION_ERROR",
        f"Browser execution error: {err_msg[:250]}",
    )


class ScanError(RuntimeError):
    """Raised when an accessibility scan fails due to runtime or network errors."""


class AccessibilityScanner:
    """Executes real axe-core accessibility evaluations inside a headless Chromium instance."""

    def __init__(
        self,
        timeout_seconds: float = 25.0,
        allow_local: bool = False,
        max_nodes_per_rule: int = 25,
        headless: bool = True,
    ):
        self.timeout_seconds = timeout_seconds
        self.allow_local = allow_local
        self.max_nodes_per_rule = max_nodes_per_rule
        self.headless = headless
        self._axe_script = get_axe_script()

    def _get_browser_launch_kwargs(self) -> dict[str, Any]:
        """Assemble browser launch arguments with environment override support and headless flags."""
        chromium_path = (
            os.environ.get("CHROMIUM_PATH")
            or os.environ.get("PLAYWRIGHT_CHROMIUM_PATH")
            or os.environ.get("CHROME_PATH")
        )
        launch_args = [
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-setuid-sandbox",
        ]
        kwargs: dict[str, Any] = {
            "headless": self.headless,
            "args": launch_args,
        }
        if chromium_path:
            kwargs["executable_path"] = chromium_path
        return kwargs

    def _format_remediation(self, failure_summary: str, rule_help: str) -> str:
        """Derive actionable, clean remediation advice from failure summary and help text."""
        lines = [line.strip() for line in (failure_summary or "").splitlines() if line.strip()]
        clean_remediation = " ".join(lines)
        if clean_remediation.startswith("Fix any of the following:"):
            clean_remediation = clean_remediation.replace("Fix any of the following:", "Action needed:").strip()
        elif clean_remediation.startswith("Fix all of the following:"):
            clean_remediation = clean_remediation.replace("Fix all of the following:", "All actions required:").strip()

        if not clean_remediation:
            clean_remediation = f"Remediation guidance: {rule_help}"
        return clean_remediation

    def _parse_axe_results(self, raw_results: dict[str, Any], url: str, final_url: str, elapsed_ms: float) -> ScanReport:
        """Convert raw axe-core JSON results into structured ScanReport."""
        violations_raw = raw_results.get("violations", [])
        passes_raw = raw_results.get("passes", [])
        inapplicable_raw = raw_results.get("inapplicable", [])
        incomplete_raw = raw_results.get("incomplete", [])

        violations: list[Violation] = []
        critical_count = 0
        serious_count = 0
        moderate_count = 0
        minor_count = 0

        for item in violations_raw:
            rule_id = item.get("id", "unknown-rule")
            impact = (item.get("impact") or "unknown").lower()
            description = item.get("description", "")
            help_text = item.get("help", "")
            help_url = item.get("helpUrl", "")
            tags = item.get("tags", [])

            if impact == "critical":
                critical_count += 1
            elif impact == "serious":
                serious_count += 1
            elif impact == "moderate":
                moderate_count += 1
            elif impact == "minor":
                minor_count += 1

            raw_nodes = item.get("nodes", [])
            node_objects: list[ElementNode] = []

            for n in raw_nodes[: self.max_nodes_per_rule]:
                target = n.get("target", [])
                html = n.get("html", "")
                failure_summary = n.get("failureSummary", "")
                remediation = self._format_remediation(failure_summary, help_text)

                node_objects.append(
                    ElementNode(
                        target=target if isinstance(target, list) else [str(target)],
                        html=html[:500],  # cap snippet length
                        failure_summary=failure_summary,
                        suggested_remediation=remediation,
                    )
                )

            violations.append(
                Violation(
                    rule_id=rule_id,
                    impact=impact,
                    description=description,
                    help=help_text,
                    help_url=help_url,
                    tags=tags,
                    nodes=node_objects,
                    node_count=len(raw_nodes),
                )
            )

        incomplete: list[Violation] = []
        for item in incomplete_raw:
            rule_id = item.get("id", "unknown-rule")
            impact = (item.get("impact") or "unknown").lower()
            description = item.get("description", "")
            help_text = item.get("help", "")
            help_url = item.get("helpUrl", "")
            tags = item.get("tags", [])

            raw_nodes = item.get("nodes", [])
            node_objects = []
            for n in raw_nodes[: self.max_nodes_per_rule]:
                target = n.get("target", [])
                html = n.get("html", "")
                failure_summary = n.get("failureSummary", "")
                remediation = self._format_remediation(failure_summary, help_text)
                node_objects.append(
                    ElementNode(
                        target=target if isinstance(target, list) else [str(target)],
                        html=html[:500],
                        failure_summary=failure_summary,
                        suggested_remediation=remediation,
                    )
                )

            incomplete.append(
                Violation(
                    rule_id=rule_id,
                    impact=impact,
                    description=description,
                    help=help_text,
                    help_url=help_url,
                    tags=tags,
                    nodes=node_objects,
                    node_count=len(raw_nodes),
                )
            )

        # Sort violations by severity: critical > serious > moderate > minor
        severity_rank = {"critical": 0, "serious": 1, "moderate": 2, "minor": 3, "unknown": 4}
        violations.sort(key=lambda v: severity_rank.get(v.impact, 5))
        incomplete.sort(key=lambda v: severity_rank.get(v.impact, 5))

        summary = ScanSummary(
            total_violations=len(violations),
            critical_count=critical_count,
            serious_count=serious_count,
            moderate_count=moderate_count,
            minor_count=minor_count,
            passes_count=len(passes_raw),
            inapplicable_count=len(inapplicable_raw),
            incomplete_count=len(incomplete_raw),
        )

        return ScanReport(
            status="SUCCESS",
            url=url,
            final_url=final_url,
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration_ms=elapsed_ms,
            summary=summary,
            violations=violations,
            incomplete=incomplete,
        )

    def scan_url(self, url: str) -> ScanReport:
        """Scan a live URL for accessibility violations, enforcing SSRF and timeout guards."""
        start_time = time.perf_counter()
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Pre-navigation security validation
        try:
            validated_url = URLValidator.validate_url(url, allow_local=self.allow_local)
        except SecurityError as sec_err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScanReport(
                status="SECURITY_BLOCKED",
                url=url,
                timestamp=now_iso,
                duration_ms=elapsed_ms,
                error=str(sec_err),
                error_category="SECURITY_VIOLATION",
            )

        final_navigated_url = validated_url

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**self._get_browser_launch_kwargs())
                context = browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    user_agent="AccessLens-AI/0.1.0 (+https://github.com/accesslens-ai; accessibility auditor)",
                    ignore_https_errors=False,
                )

                # Route handler for outbound request validation (SSRF and redirect guard)
                def handle_route(route: Any) -> None:
                    req_url = route.request.url
                    try:
                        # For subresources and redirects, verify scheme and host
                        parsed = urlsplit(req_url)
                        if parsed.scheme.lower() in ("http", "https"):
                            URLValidator.validate_redirect(req_url, allow_local=self.allow_local)
                        elif parsed.scheme.lower() in ("data:", "blob:"):
                            pass  # Safe in-memory representations
                        else:
                            route.abort("blockedbyclient")
                            return
                        route.continue_()
                    except SecurityError:
                        route.abort("blockedbyclient")

                context.route("**/*", handle_route)

                page = context.new_page()
                page.set_default_timeout(int(self.timeout_seconds * 1000))

                # 2. Navigation with redirect inspection
                response = page.goto(
                    validated_url,
                    wait_until="domcontentloaded",
                    timeout=int(self.timeout_seconds * 1000),
                )

                final_navigated_url = page.url

                # 3. Post-navigation redirect re-validation
                if final_navigated_url != validated_url:
                    try:
                        URLValidator.validate_redirect(final_navigated_url, allow_local=self.allow_local)
                    except SecurityError as redirect_err:
                        browser.close()
                        elapsed_ms = (time.perf_counter() - start_time) * 1000
                        return ScanReport(
                            status="SECURITY_BLOCKED",
                            url=url,
                            final_url=final_navigated_url,
                            timestamp=now_iso,
                            duration_ms=elapsed_ms,
                            error=f"Unsafe redirect intercepted: {redirect_err}",
                            error_category="SECURITY_VIOLATION",
                        )

                # Verify HTTP response status
                if response is not None and response.status >= 400:
                    status_code = response.status
                    browser.close()
                    elapsed_ms = (time.perf_counter() - start_time) * 1000
                    return ScanReport(
                        status="SCAN_ERROR",
                        url=url,
                        final_url=final_navigated_url,
                        timestamp=now_iso,
                        duration_ms=elapsed_ms,
                        error=f"HTTP server error: target returned HTTP {status_code}",
                        error_category="HTTP_ERROR",
                    )

                # 4. Inject axe-core engine
                page.evaluate(self._axe_script)

                # 5. Execute axe.run() with standard WCAG 2.0 / 2.1 A and AA tags
                axe_run_script = """
                () => {
                    return new Promise((resolve, reject) => {
                        if (typeof axe === 'undefined') {
                            reject(new Error("axe-core library was not loaded properly into page context."));
                            return;
                        }
                        axe.run(
                            document,
                            {
                                runOnly: {
                                    type: 'tag',
                                    values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice']
                                }
                            },
                            (err, results) => {
                                if (err) reject(err);
                                else resolve(results);
                            }
                        );
                    });
                }
                """
                raw_results = page.evaluate(axe_run_script)
                browser.close()

            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return self._parse_axe_results(raw_results, url, final_navigated_url, elapsed_ms)

        except PlaywrightTimeoutError as timeout_err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return ScanReport(
                status="SCAN_ERROR",
                url=url,
                final_url=final_navigated_url,
                timestamp=now_iso,
                duration_ms=elapsed_ms,
                error=f"Scan timed out after {self.timeout_seconds:.1f}s ({timeout_err})",
                error_category="NAVIGATION_TIMEOUT",
            )
        except PlaywrightError as pw_err:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            category, diagnostic = _categorize_playwright_error(pw_err)
            return ScanReport(
                status="SCAN_ERROR",
                url=url,
                final_url=final_navigated_url,
                timestamp=now_iso,
                duration_ms=elapsed_ms,
                error=diagnostic,
                error_category=category,
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            category, diagnostic = _categorize_playwright_error(exc)
            return ScanReport(
                status="SCAN_ERROR",
                url=url,
                final_url=final_navigated_url,
                timestamp=now_iso,
                duration_ms=elapsed_ms,
                error=diagnostic if category == "BROWSER_UNAVAILABLE" else f"Unexpected scanner exception ({type(exc).__name__}): {exc}",
                error_category=category,
            )

    def scan_html(self, html_content: str, base_url: str = "http://localhost") -> ScanReport:
        """Scan raw HTML string directly in Playwright without network requests."""
        start_time = time.perf_counter()
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(**self._get_browser_launch_kwargs())
                page = browser.new_page(viewport={"width": 1280, "height": 800})
                page.set_default_timeout(int(self.timeout_seconds * 1000))

                page.set_content(html_content, wait_until="domcontentloaded")
                page.evaluate(self._axe_script)

                axe_run_script = """
                () => {
                    return new Promise((resolve, reject) => {
                        axe.run(
                            document,
                            {
                                runOnly: {
                                    type: 'tag',
                                    values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice']
                                }
                            },
                            (err, results) => {
                                if (err) reject(err);
                                else resolve(results);
                            }
                        );
                    });
                }
                """
                raw_results = page.evaluate(axe_run_script)
                browser.close()

            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return self._parse_axe_results(raw_results, base_url, base_url, elapsed_ms)

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            category, diagnostic = _categorize_playwright_error(exc)
            return ScanReport(
                status="SCAN_ERROR",
                url=base_url,
                final_url=base_url,
                timestamp=now_iso,
                duration_ms=elapsed_ms,
                error=diagnostic if category == "BROWSER_UNAVAILABLE" else f"HTML scan failed ({type(exc).__name__}): {exc}",
                error_category=category,
            )
