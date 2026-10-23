/**
 * AccessLens AI — Frontend Application Logic
 * Orchestrates accessibility audits, live progress, findings explorer,
 * JSON export, scan history drawer, and dark/light theming.
 */

(function () {
  "use strict";

  // Application State
  const state = {
    currentReport: null,
    activeSeverityFilter: "all",
    searchQuery: "",
    isScanning: false,
    timerInterval: null,
    scanStartTime: 0,
  };

  // DOM Elements Cache
  const els = {
    html: document.documentElement,
    themeToggleBtn: document.getElementById("theme-toggle-btn"),
    themeIconSun: document.getElementById("theme-icon-sun"),
    themeIconMoon: document.getElementById("theme-icon-moon"),

    // Audit Form
    scanForm: document.getElementById("scan-form"),
    urlInput: document.getElementById("url-input"),
    timeoutSelect: document.getElementById("timeout-select"),
    scanSubmitBtn: document.getElementById("scan-submit-btn"),
    scanBtnText: document.getElementById("scan-btn-text"),
    btnSpinner: document.querySelector(".btn-spinner"),
    urlErrorMsg: document.getElementById("url-error-msg"),
    presetPills: document.querySelectorAll(".preset-pill"),

    // Progress Panel
    progressCard: document.getElementById("scan-progress-card"),
    progressStatusDesc: document.getElementById("progress-status-desc"),
    progressTimerDisplay: document.getElementById("progress-timer-display"),
    progressBarFill: document.getElementById("progress-bar-fill"),
    pstep1: document.getElementById("pstep-1"),
    pstep2: document.getElementById("pstep-2"),
    pstep3: document.getElementById("pstep-3"),
    pstep4: document.getElementById("pstep-4"),

    // Error Alert
    errorCard: document.getElementById("error-card"),
    errorTitle: document.getElementById("error-title"),
    errorCategoryBadge: document.getElementById("error-category-badge"),
    errorMessage: document.getElementById("error-message"),
    errorRemediationTip: document.getElementById("error-remediation-tip"),

    // Results & Metrics
    resultsSection: document.getElementById("results-section"),
    dashboardEmptyState: document.getElementById("dashboard-empty-state"),
    resultStatusPill: document.getElementById("result-status-pill"),
    resultStatusText: document.getElementById("result-status-text"),
    resultTargetUrl: document.getElementById("result-target-url"),
    resultFinalUrlRow: document.getElementById("result-final-url-row"),
    resultFinalUrl: document.getElementById("result-final-url"),
    resultDuration: document.getElementById("result-duration"),
    resultTimestamp: document.getElementById("result-timestamp"),
    downloadJsonBtn: document.getElementById("download-json-btn"),
    viewRawJsonBtn: document.getElementById("view-raw-json-btn"),

    // Metric numbers
    metricTotalViolations: document.getElementById("metric-total-violations"),
    metricCriticalCount: document.getElementById("metric-critical-count"),
    metricSeriousCount: document.getElementById("metric-serious-count"),
    metricModerateCount: document.getElementById("metric-moderate-count"),
    metricMinorCount: document.getElementById("metric-minor-count"),
    metricPassesCount: document.getElementById("metric-passes-count"),
    metricIncompleteCount: document.getElementById("metric-incomplete-count"),

    // Findings & Filters
    findingsSubtitle: document.getElementById("findings-subtitle"),
    searchInput: document.getElementById("search-input"),
    searchClearBtn: document.getElementById("search-clear-btn"),
    filterChips: document.querySelectorAll(".filter-chip"),
    filterAllCount: document.getElementById("filter-all-count"),
    filterCriticalCount: document.getElementById("filter-critical-count"),
    filterSeriousCount: document.getElementById("filter-serious-count"),
    filterModerateCount: document.getElementById("filter-moderate-count"),
    filterMinorCount: document.getElementById("filter-minor-count"),
    violationsContainer: document.getElementById("violations-accordion-container"),
    violationsEmptyState: document.getElementById("violations-empty-state"),

    // History Drawer
    historyToggleBtn: document.getElementById("history-toggle-btn"),
    historyCountBadge: document.getElementById("history-count-badge"),
    historyDrawer: document.getElementById("history-drawer"),
    historyBackdrop: document.getElementById("history-backdrop"),
    historyCloseBtn: document.getElementById("history-close-btn"),
    historyClearBtn: document.getElementById("history-clear-btn"),
    historyList: document.getElementById("history-list"),
    historyEmpty: document.getElementById("history-empty"),

    // Raw JSON Modal
    jsonModal: document.getElementById("json-modal"),
    modalJsonCode: document.getElementById("modal-json-code"),
    modalCopyJsonBtn: document.getElementById("modal-copy-json-btn"),
    modalCloseBtn: document.getElementById("modal-close-btn"),

    // Toasts
    toastContainer: document.getElementById("toast-container"),
  };

  /* ==========================================================================
     Theme Management (Dark / Light)
     ========================================================================== */
  function initTheme() {
    const savedTheme = localStorage.getItem("accesslens_theme");
    const systemPrefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    const initialTheme = savedTheme || (systemPrefersDark ? "dark" : "light");
    setTheme(initialTheme);
  }

  function setTheme(theme) {
    els.html.setAttribute("data-theme", theme);
    localStorage.setItem("accesslens_theme", theme);
    if (theme === "dark") {
      els.themeIconSun.style.display = "block";
      els.themeIconMoon.style.display = "none";
    } else {
      els.themeIconSun.style.display = "none";
      els.themeIconMoon.style.display = "block";
    }
  }

  function toggleTheme() {
    const current = els.html.getAttribute("data-theme") || "dark";
    setTheme(current === "dark" ? "light" : "dark");
  }

  /* ==========================================================================
     Toast Notifications
     ========================================================================== */
  function showToast(message, duration = 3000) {
    const toast = document.createElement("div");
    toast.className = "toast";
    toast.textContent = message;
    els.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transition = "opacity 0.3s ease";
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  /* ==========================================================================
     URL Input Validation & Presets
     ========================================================================== */
  function validateInputUrl(url) {
    if (!url || typeof url !== "string") {
      return "Please enter a target URL.";
    }
    const trimmed = url.trim();
    if (trimmed.startsWith("fixture:")) {
      return null;
    }
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
      return "URL must begin with http:// or https:// (or choose a civic fixture preset)";
    }
    try {
      new URL(trimmed);
      return null;
    } catch {
      return "Please enter a valid, well-formed URL.";
    }
  }

  function handlePresetClick(e) {
    const targetUrl = e.currentTarget.getAttribute("data-url");
    if (targetUrl) {
      els.urlInput.value = targetUrl;
      els.urlInput.focus();
      els.urlErrorMsg.style.display = "none";
    }
  }

  /* ==========================================================================
     Scan Execution & Live Progress
     ========================================================================== */
  async function handleScanSubmit(e) {
    e.preventDefault();
    if (state.isScanning) return;

    const rawUrl = els.urlInput.value.trim();
    const validationError = validateInputUrl(rawUrl);

    if (validationError) {
      els.urlErrorMsg.textContent = validationError;
      els.urlErrorMsg.style.display = "block";
      els.urlInput.focus();
      return;
    }

    els.urlErrorMsg.style.display = "none";
    const timeoutVal = parseFloat(els.timeoutSelect.value) || 25.0;

    startScanProgress(rawUrl);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: rawUrl, timeout: timeoutVal }),
      });

      const data = await response.json();

      if (!response.ok && !data.status) {
        throw new Error(data.detail || `Server returned error status ${response.status}`);
      }

      finishScanProgress();

      if (data.status === "SUCCESS") {
        renderScanSuccess(data);
        showToast("Audit completed successfully!");
      } else {
        renderScanFailure(data);
      }

      // Refresh scan history drawer count
      loadHistory();

    } catch (err) {
      finishScanProgress();
      renderScanFailure({
        status: "SCAN_ERROR",
        url: rawUrl,
        error_category: "NETWORK_ERROR",
        error: err.message || "Failed to reach AccessLens AI scanning server.",
      });
      showToast("Scan failed: " + err.message, 4500);
    }
  }

  function startScanProgress(url) {
    state.isScanning = true;
    state.scanStartTime = performance.now();

    // UI state updates
    els.scanSubmitBtn.disabled = true;
    els.btnSpinner.style.display = "inline-block";
    els.scanBtnText.textContent = "Auditing...";
    els.urlInput.disabled = true;
    els.timeoutSelect.disabled = true;

    // Show progress panel, hide old results & errors
    els.dashboardEmptyState.style.display = "none";
    els.resultsSection.style.display = "none";
    els.errorCard.style.display = "none";
    els.progressCard.style.display = "flex";

    // Reset steps
    resetProgressSteps();

    // Start timer & animated progress updates
    let step = 1;
    els.timerInterval = setInterval(() => {
      const elapsedSec = ((performance.now() - state.scanStartTime) / 1000).toFixed(1);
      els.progressTimerDisplay.textContent = `${elapsedSec}s`;

      // Simulate step progression
      const elapsed = parseFloat(elapsedSec);
      if (elapsed > 0.5 && step === 1) {
        step = 2;
        activateProgressStep(2, "Launching Playwright Chromium & rendering client DOM...", 45);
      } else if (elapsed > 2.0 && step === 2) {
        step = 3;
        activateProgressStep(3, "Evaluating axe-core 4.13.0 WCAG 2.0/2.1 A & AA rules...", 75);
      } else if (elapsed > 4.5 && step === 3) {
        step = 4;
        activateProgressStep(4, "Collating violation nodes & structuring remediation...", 90);
      }
    }, 100);
  }

  function resetProgressSteps() {
    [els.pstep1, els.pstep2, els.pstep3, els.pstep4].forEach((s, idx) => {
      s.className = "progress-step-item" + (idx === 0 ? " active" : "");
    });
    els.progressBarFill.style.width = "20%";
    els.progressStatusDesc.textContent = "Verifying URL safety and resolving DNS records (SSRF guard)...";
  }

  function activateProgressStep(stepNum, statusDesc, progressPercent) {
    for (let i = 1; i <= 4; i++) {
      const el = document.getElementById(`pstep-${i}`);
      if (i < stepNum) {
        el.className = "progress-step-item completed";
      } else if (i === stepNum) {
        el.className = "progress-step-item active";
      } else {
        el.className = "progress-step-item";
      }
    }
    els.progressStatusDesc.textContent = statusDesc;
    els.progressBarFill.style.width = `${progressPercent}%`;
  }

  function finishScanProgress() {
    state.isScanning = false;
    clearInterval(els.timerInterval);

    els.scanSubmitBtn.disabled = false;
    els.btnSpinner.style.display = "none";
    els.scanBtnText.textContent = "Run Audit";
    els.urlInput.disabled = false;
    els.timeoutSelect.disabled = false;
    els.progressCard.style.display = "none";
  }

  /* ==========================================================================
     Render Scan Results (Success)
     ========================================================================== */
  function renderScanSuccess(report) {
    state.currentReport = report;
    els.errorCard.style.display = "none";
    els.dashboardEmptyState.style.display = "none";
    els.resultsSection.style.display = "flex";

    const isFixture = Boolean(report.is_fixture || (report.url && report.url.startsWith("fixture:")));
    const fixtureBanner = document.getElementById("fixture-mode-banner");
    const fixtureDesc = document.getElementById("fixture-mode-desc");

    // Status Banner
    if (isFixture) {
      els.resultStatusPill.className = "result-status-pill fixture";
      els.resultStatusText.textContent = "LOCAL CIVIC FIXTURE";
      if (fixtureBanner) {
        fixtureBanner.style.display = "flex";
        if (fixtureDesc) {
          fixtureDesc.textContent = `This audit evaluated a local pre-packaged test scenario in memory (${report.url}). Controlled civic fixture conditions demonstrate real axe-core heuristics without live website network requests.`;
        }
      }
    } else {
      els.resultStatusPill.className = "result-status-pill success";
      els.resultStatusText.textContent = "AUDIT COMPLETE";
      if (fixtureBanner) {
        fixtureBanner.style.display = "none";
      }
    }

    els.resultTargetUrl.textContent = report.url;
    els.resultTargetUrl.href = isFixture ? "#" : report.url;

    if (report.final_url && report.final_url !== report.url && !isFixture) {
      els.resultFinalUrlRow.style.display = "flex";
      els.resultFinalUrl.textContent = report.final_url;
    } else {
      els.resultFinalUrlRow.style.display = "none";
    }

    els.resultDuration.textContent = `${Math.round(report.duration_ms || 0).toLocaleString()} ms`;
    els.resultTimestamp.textContent = formatTimestamp(report.timestamp);

    // Summary Metrics
    const s = report.summary || {
      total_violations: 0,
      critical_count: 0,
      serious_count: 0,
      moderate_count: 0,
      minor_count: 0,
      passes_count: 0,
      incomplete_count: 0,
    };

    els.metricTotalViolations.textContent = s.total_violations;
    els.metricCriticalCount.textContent = s.critical_count;
    els.metricSeriousCount.textContent = s.serious_count;
    els.metricModerateCount.textContent = s.moderate_count;
    els.metricMinorCount.textContent = s.minor_count;
    els.metricPassesCount.textContent = s.passes_count;
    els.metricIncompleteCount.textContent = s.incomplete_count;

    // Filter Chip Counts
    els.filterAllCount.textContent = s.total_violations;
    els.filterCriticalCount.textContent = s.critical_count;
    els.filterSeriousCount.textContent = s.serious_count;
    els.filterModerateCount.textContent = s.moderate_count;
    els.filterMinorCount.textContent = s.minor_count;

    // Reset Search & Severity Filter
    state.activeSeverityFilter = "all";
    state.searchQuery = "";
    els.searchInput.value = "";
    els.searchClearBtn.style.display = "none";
    updateFilterChipUI();

    // Render Violations
    renderViolationsList();
  }

  /* ==========================================================================
     Render Scan Failure (SSRF Block, DNS Error, Timeout, HTTP Error)
     ========================================================================== */
  function renderScanFailure(report) {
    state.currentReport = report;
    els.resultsSection.style.display = "none";
    els.dashboardEmptyState.style.display = "none";
    els.errorCard.style.display = "block";

    const isSecurity = report.status === "SECURITY_BLOCKED" || report.error_category === "SECURITY_VIOLATION";

    els.errorCategoryBadge.textContent = report.error_category || report.status || "SCAN_ERROR";
    els.errorCategoryBadge.className = isSecurity ? "badge badge-error" : "badge badge-error";

    els.errorTitle.textContent = isSecurity
      ? "Scan Target Prohibited by Security Policy (SSRF Guard)"
      : "Audit Execution Failed";

    els.errorMessage.textContent = report.error || "The scan could not be completed.";

    let remediationText = "";
    if (isSecurity) {
      remediationText = "AccessLens AI blocks connections to loopback (127.0.0.1, localhost), RFC 1918 private subnets (10.x, 172.16.x, 192.168.x), and cloud metadata endpoints (169.254.169.254) to defend internal networks. Please target a public website.";
    } else if (report.error_category === "BROWSER_UNAVAILABLE") {
      remediationText = "Playwright Chromium browser binary is not installed in this execution environment. Serverless runtimes (such as Vercel Functions) do not include native Linux browser binaries. Run AccessLens AI locally or on a containerized host (Docker, AWS App Runner, ECS, VM) where Playwright Chromium can be launched.";
    } else if (report.error_category === "DNS_FAILURE") {
      remediationText = "The target domain name could not be resolved by DNS. Please check that the URL hostname is spelled correctly and is active.";
    } else if (report.error_category === "NAVIGATION_TIMEOUT") {
      remediationText = "Navigation timed out before the page reached DOMContentLoaded. Try increasing the scan timeout to 45 or 60 seconds.";
    } else {
      remediationText = "Ensure the target web server is reachable and permits automated user agents.";
    }
    els.errorRemediationTip.textContent = remediationText;
  }

  /* ==========================================================================
     Violations Filtering & Accordion Rendering
     ========================================================================== */
  function getFilteredViolations() {
    if (!state.currentReport || !state.currentReport.violations) {
      return [];
    }

    const q = state.searchQuery.toLowerCase().trim();
    const severity = state.activeSeverityFilter;

    return state.currentReport.violations.filter((v) => {
      // 1. Severity filter
      if (severity !== "all" && v.impact !== severity) {
        return false;
      }

      // 2. Search query filter
      if (q) {
        const matchesRule = v.rule_id.toLowerCase().includes(q);
        const matchesDesc = (v.description || "").toLowerCase().includes(q);
        const matchesHelp = (v.help || "").toLowerCase().includes(q);
        const matchesTag = (v.tags || []).some((t) => t.toLowerCase().includes(q));
        const matchesNodes = (v.nodes || []).some((n) => {
          return (
            (n.target || []).some((t) => t.toLowerCase().includes(q)) ||
            (n.failure_summary || "").toLowerCase().includes(q) ||
            (n.suggested_remediation || "").toLowerCase().includes(q)
          );
        });
        if (!matchesRule && !matchesDesc && !matchesHelp && !matchesTag && !matchesNodes) {
          return false;
        }
      }

      return true;
    });
  }

  function renderViolationsList() {
    const filtered = getFilteredViolations();
    const totalCount = (state.currentReport && state.currentReport.violations) ? state.currentReport.violations.length : 0;

    els.findingsSubtitle.textContent = `Showing ${filtered.length} of ${totalCount} violations`;

    els.violationsContainer.innerHTML = "";

    const emptyDesc = document.getElementById("empty-state-desc");

    if (filtered.length === 0) {
      els.violationsEmptyState.style.display = "block";
      if (totalCount === 0) {
        if (emptyDesc) {
          emptyDesc.innerHTML = `
            <strong style="color:var(--text-primary); font-size:1rem;">Zero automated violations detected by axe-core.</strong>
            <p style="margin:0.5rem 0 0; color:var(--text-secondary); line-height:1.5;">
              Automated testing evaluates a subset of machine-detectable criteria (syntax, attributes, deterministic contrast). 
              <strong>Zero reported violations does not certify full WCAG compliance.</strong>
            </p>
            <div style="margin-top:1rem; padding:1rem; background:rgba(30, 64, 175, 0.05); border:1px solid rgba(30, 64, 175, 0.2); border-radius:8px; text-align:left;">
              <strong style="color:var(--text-primary); font-size:0.875rem;">Mandatory Civic Manual Compliance Testing Protocol:</strong>
              <ul style="margin:0.5rem 0 0 1.25rem; font-size:0.8125rem; color:var(--text-secondary); line-height:1.5;">
                <li><strong>Screen Reader Traversal:</strong> Verify end-to-end form completion using NVDA, JAWS, or VoiceOver.</li>
                <li><strong>Keyboard-Only Navigation:</strong> Ensure visible focus indicators and unhindered tabbing order across all controls.</li>
                <li><strong>Semantic Usability:</strong> Confirm field descriptions, statutory instructions, and error alerts are announced unambiguously.</li>
                <li><strong>Responsive Reflow:</strong> Check page readability and element accessibility at 200% and 400% zoom levels.</li>
              </ul>
            </div>
          `;
        }
      } else {
        if (emptyDesc) emptyDesc.textContent = "No violations match the current filter or search criteria.";
      }
    } else {
      els.violationsEmptyState.style.display = "none";

      // Generate accordion items
      filtered.forEach((v, index) => {
        const card = createViolationCard(v, index);
        els.violationsContainer.appendChild(card);
      });
    }

    renderIncompleteSection();
  }

  function renderIncompleteSection() {
    const incSection = document.getElementById("incomplete-checks-section");
    const incBadge = document.getElementById("incomplete-section-badge");
    const incAccordion = document.getElementById("incomplete-accordion-container");
    if (!incSection || !incAccordion) return;

    const incompleteList = (state.currentReport && state.currentReport.incomplete) ? state.currentReport.incomplete : [];
    if (incompleteList.length === 0) {
      incSection.style.display = "none";
      return;
    }

    incSection.style.display = "flex";
    if (incBadge) incBadge.textContent = `${incompleteList.length} ${incompleteList.length === 1 ? "item" : "items"}`;
    incAccordion.innerHTML = "";

    incompleteList.forEach((inc) => {
      const card = document.createElement("div");
      card.className = "incomplete-card";

      const header = document.createElement("div");
      header.className = "incomplete-header-row";

      const badge = document.createElement("span");
      badge.className = "incomplete-badge";
      badge.textContent = "Needs Manual Review";

      const code = document.createElement("code");
      code.className = "rule-id-code";
      code.textContent = inc.rule_id;

      const desc = document.createElement("span");
      desc.className = "rule-desc";
      desc.textContent = inc.description;

      header.appendChild(badge);
      header.appendChild(code);
      header.appendChild(desc);
      card.appendChild(header);

      if (inc.help) {
        const helpP = document.createElement("p");
        helpP.style.fontSize = "0.8125rem";
        helpP.style.color = "var(--text-secondary)";
        helpP.style.margin = "0.25rem 0 0";
        helpP.textContent = `Review Requirement: ${inc.help}`;
        card.appendChild(helpP);
      }

      incAccordion.appendChild(card);
    });
  }

  function createViolationCard(v, index) {
    const card = document.createElement("div");
    card.className = "violation-card";
    card.id = `violation-${v.rule_id}`;

    // Header Button
    const headerBtn = document.createElement("button");
    headerBtn.type = "button";
    headerBtn.className = "violation-header-btn";
    headerBtn.setAttribute("aria-expanded", index === 0 ? "true" : "false");
    headerBtn.setAttribute("aria-controls", `body-${v.rule_id}`);

    const headerLeft = document.createElement("div");
    headerLeft.className = "violation-header-left";

    const impactBadge = document.createElement("span");
    impactBadge.className = `impact-badge impact-${v.impact}`;
    impactBadge.textContent = v.impact;

    const ruleCode = document.createElement("span");
    ruleCode.className = "rule-id-code";
    ruleCode.textContent = v.rule_id;

    const ruleDesc = document.createElement("span");
    ruleDesc.className = "rule-desc";
    ruleDesc.textContent = v.description;

    headerLeft.appendChild(impactBadge);
    headerLeft.appendChild(ruleCode);
    headerLeft.appendChild(ruleDesc);

    const headerRight = document.createElement("div");
    headerRight.className = "violation-header-right";

    const nodesCount = document.createElement("span");
    nodesCount.className = "nodes-count-badge";
    const count = v.node_count || (v.nodes ? v.nodes.length : 0);
    nodesCount.textContent = `${count} ${count === 1 ? "element" : "elements"}`;

    const chevron = document.createElement("span");
    chevron.className = "chevron-icon";
    chevron.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>`;

    headerRight.appendChild(nodesCount);
    headerRight.appendChild(chevron);

    headerBtn.appendChild(headerLeft);
    headerBtn.appendChild(headerRight);

    // Body Panel
    const bodyPanel = document.createElement("div");
    bodyPanel.className = "violation-body";
    bodyPanel.id = `body-${v.rule_id}`;
    if (index !== 0) {
      bodyPanel.style.display = "none";
    } else {
      card.classList.add("open");
    }

    // Toggle Click Event
    headerBtn.addEventListener("click", () => {
      const isOpen = card.classList.contains("open");
      if (isOpen) {
        card.classList.remove("open");
        bodyPanel.style.display = "none";
        headerBtn.setAttribute("aria-expanded", "false");
      } else {
        card.classList.add("open");
        bodyPanel.style.display = "flex";
        headerBtn.setAttribute("aria-expanded", "true");
      }
    });

    // 1. Meta Bar (Tags + Deque University Doc Link)
    const metaBar = document.createElement("div");
    metaBar.className = "violation-meta-bar";

    const tagsList = document.createElement("div");
    tagsList.className = "tags-list";
    (v.tags || []).forEach((t) => {
      const tagSpan = document.createElement("span");
      tagSpan.className = "wcag-tag";
      tagSpan.textContent = t;
      tagsList.appendChild(tagSpan);
    });

    metaBar.appendChild(tagsList);

    if (v.help_url) {
      const helpLink = document.createElement("a");
      helpLink.className = "rule-help-link";
      helpLink.href = v.help_url;
      helpLink.target = "_blank";
      helpLink.rel = "noopener noreferrer";
      helpLink.innerHTML = `Learn more on Deque University <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>`;
      metaBar.appendChild(helpLink);
    }

    bodyPanel.appendChild(metaBar);

    // 2. Primary Remediation Advice Box
    const sampleNode = (v.nodes && v.nodes.length > 0) ? v.nodes[0] : null;
    const remediationAdvice = (sampleNode && sampleNode.suggested_remediation)
      ? sampleNode.suggested_remediation
      : `Remediation guidance: ${v.help || v.description}`;

    const remediationBox = document.createElement("div");
    remediationBox.className = "remediation-box";
    remediationBox.innerHTML = `
      <div class="remediation-box-title">Remediation Guidance</div>
      <div class="remediation-text">${escapeHtml(remediationAdvice)}</div>
    `;
    bodyPanel.appendChild(remediationBox);

    // 3. Affected Elements List
    if (v.nodes && v.nodes.length > 0) {
      const nodesSection = document.createElement("div");
      nodesSection.className = "affected-nodes-section";
      nodesSection.innerHTML = `<div class="nodes-section-title">Affected Elements &amp; Failure Evidence (${v.nodes.length})</div>`;

      v.nodes.forEach((node, nIdx) => {
        const nodeCard = document.createElement("div");
        nodeCard.className = "node-item-card";

        const targetSelector = Array.isArray(node.target) ? node.target.join(" > ") : String(node.target);

        // Target Selector Row with Copy Button
        const targetRow = document.createElement("div");
        targetRow.className = "node-target-row";

        const targetCode = document.createElement("code");
        targetCode.className = "node-target-code";
        targetCode.textContent = targetSelector;

        const copyTargetBtn = document.createElement("button");
        copyTargetBtn.type = "button";
        copyTargetBtn.className = "copy-btn";
        copyTargetBtn.textContent = "Copy Selector";
        copyTargetBtn.addEventListener("click", (e) => {
          e.stopPropagation();
          copyToClipboard(targetSelector);
          copyTargetBtn.textContent = "Copied!";
          setTimeout(() => (copyTargetBtn.textContent = "Copy Selector"), 1800);
        });

        targetRow.appendChild(targetCode);
        targetRow.appendChild(copyTargetBtn);
        nodeCard.appendChild(targetRow);

        // Failure Summary
        if (node.failure_summary) {
          const failSummary = document.createElement("div");
          failSummary.className = "node-failure-summary";
          failSummary.textContent = node.failure_summary;
          nodeCard.appendChild(failSummary);
        }

        // HTML Snippet
        if (node.html) {
          const htmlContainer = document.createElement("div");
          htmlContainer.style.position = "relative";

          const htmlPre = document.createElement("pre");
          htmlPre.className = "node-html-code";
          htmlPre.textContent = node.html;

          const copyHtmlBtn = document.createElement("button");
          copyHtmlBtn.type = "button";
          copyHtmlBtn.className = "copy-btn";
          copyHtmlBtn.style.position = "absolute";
          copyHtmlBtn.style.top = "6px";
          copyHtmlBtn.style.right = "6px";
          copyHtmlBtn.textContent = "Copy HTML";
          copyHtmlBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            copyToClipboard(node.html);
            copyHtmlBtn.textContent = "Copied!";
            setTimeout(() => (copyHtmlBtn.textContent = "Copy HTML"), 1800);
          });

          htmlContainer.appendChild(htmlPre);
          htmlContainer.appendChild(copyHtmlBtn);
          nodeCard.appendChild(htmlContainer);
        }

        nodesSection.appendChild(nodeCard);
      });

      bodyPanel.appendChild(nodesSection);
    }

    // 4. Strands Decider 2B Remediation Analysis & Static WCAG Guidance
    const aiContainer = document.createElement("div");
    aiContainer.className = "ai-analysis-container";
    aiContainer.id = `ai-section-${v.rule_id}`;

    const aiHeaderRow = document.createElement("div");
    aiHeaderRow.className = "ai-header-row";

    const aiTitleGroup = document.createElement("div");
    aiTitleGroup.className = "ai-title-group";
    aiTitleGroup.innerHTML = `
      <div class="ai-spark-icon" aria-hidden="true">✦</div>
      <div>
        <div class="ai-section-title">Strands Decider 2B Remediation Analysis</div>
        <div class="ai-section-desc">Action classification via hosted Decider 2B &amp; deterministic WCAG guidance</div>
      </div>
    `;

    const aiBtn = document.createElement("button");
    aiBtn.type = "button";
    aiBtn.className = "btn-ai-analyze";
    aiBtn.innerHTML = `<span>Analyze with Decider 2B</span>`;

    aiHeaderRow.appendChild(aiTitleGroup);
    aiHeaderRow.appendChild(aiBtn);
    aiContainer.appendChild(aiHeaderRow);

    const aiResultsPanel = document.createElement("div");
    aiResultsPanel.className = "ai-results-panel";
    aiResultsPanel.style.display = "none";
    aiContainer.appendChild(aiResultsPanel);

    aiBtn.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (aiBtn.disabled) return;
      aiBtn.disabled = true;
      aiBtn.innerHTML = `<span class="btn-spinner" aria-hidden="true" style="display:inline-block; width:12px; height:12px;"></span> Classifying...`;

      try {
        const payload = {
          rule_id: v.rule_id,
          impact: v.impact,
          description: v.description,
          target: sampleNode ? sampleNode.target : [],
          html: sampleNode ? sampleNode.html : "",
          failure_summary: sampleNode ? sampleNode.failure_summary : "",
        };

        const res = await fetch("/api/findings/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }

        const data = await res.json();
        renderAIAnalysisResults(aiResultsPanel, data);
        aiResultsPanel.style.display = "flex";
        aiBtn.innerHTML = `<span>Classification Ready</span>`;
      } catch (err) {
        aiResultsPanel.innerHTML = `
          <div class="ai-unavailable-card">
            <strong>Service Communication Notice:</strong>
            <span>Failed to request Decider analysis: ${escapeHtml(err.message)}. Ensure server is reachable.</span>
          </div>
        `;
        aiResultsPanel.style.display = "flex";
        aiBtn.disabled = false;
        aiBtn.innerHTML = `<span>Retry Analysis</span>`;
      }
    });

    bodyPanel.appendChild(aiContainer);

    card.appendChild(headerBtn);
    card.appendChild(bodyPanel);
    return card;
  }

  function renderAIAnalysisResults(container, data) {
    container.innerHTML = "";
    const dec = data.decision || {};
    const staticGuidance = data.static_guidance || {};
    const explanation = data.explanation || {};

    // 1. Strands Decider 2B Action Card (Always First: Policy Decision)
    const decCard = document.createElement("div");
    decCard.className = "ai-decision-card";

    if (dec.status === "unavailable") {
      decCard.innerHTML = `
        <div class="ai-unavailable-card">
          <strong>Strands Decider 2B Unavailable:</strong>
          <span>${escapeHtml(dec.error || "DECIDER_API_KEY is not configured.")} Set DECIDER_API_KEY in .env to enable hosted Decider 2B classification. Safely defaulted to HUMAN_REVIEW.</span>
        </div>
      `;
    } else {
      const actionClass = dec.action === "AUTO_FIX_CANDIDATE"
        ? "action-auto-fix"
        : (dec.action === "EXPLAIN_ONLY" ? "action-explain-only" : "action-human-review");

      const confPct = Math.round((dec.confidence || 0) * 100);
      const riskLevel = escapeHtml(dec.risk_level || "high").toUpperCase();
      const latencyMs = dec.latency_ms ? `${Math.round(dec.latency_ms)} ms` : "";

      decCard.innerHTML = `
        <div class="ai-card-title-row">
          <div class="ai-card-category-badge">Strands Decider 2B Classification</div>
          <div style="display:flex; align-items:center; gap:0.4rem;">
            ${latencyMs ? `<span class="latency-pill">${latencyMs}</span>` : ""}
            <span class="risk-pill risk-${escapeHtml(dec.risk_level || 'high')}">Risk: ${riskLevel}</span>
          </div>
        </div>
        <div class="ai-decision-header">
          <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap;">
            <span style="font-size:0.75rem; font-weight:700; color:var(--text-muted); text-transform:uppercase;">Recommended Action:</span>
            <span class="action-pill ${actionClass}">${escapeHtml(dec.action || "HUMAN_REVIEW")}</span>
          </div>
          <span class="confidence-pill">${confPct}% confidence</span>
        </div>
        <div class="ai-rationale-text">${escapeHtml(dec.rationale || "Action recommended based on rule heuristics.")}</div>
      `;
    }
    container.appendChild(decCard);

    // 2. Concrete Downstream Workflow Execution Card (Genuinely Driven by Decider)
    const workflow = data.workflow;
    if (workflow) {
      const wfCard = document.createElement("div");
      const wfAction = workflow.workflow_action || "ESCALATE_HUMAN_REVIEW";
      let cardModClass = "workflow-escalate";
      let badgeModClass = "workflow-badge-escalate";
      let badgeText = "Escalated for Human Review";

      if (wfAction === "GENERATE_REMEDIATION") {
        cardModClass = "workflow-remediation";
        badgeModClass = "workflow-badge-remediation";
        badgeText = "Advisory Patch Generated";
      } else if (wfAction === "ENRICH_CONTEXT") {
        cardModClass = "workflow-enrichment";
        badgeModClass = "workflow-badge-enrichment";
        badgeText = "Context Enriched via DOM Analysis";
      }

      wfCard.className = `workflow-result-card ${cardModClass}`;

      let innerContent = `
        <div class="ai-card-title-row">
          <div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap;">
            <span class="workflow-badge ${badgeModClass}">${escapeHtml(badgeText)}</span>
            <strong style="font-size:0.875rem; color:var(--text-primary);">${escapeHtml(workflow.action_title || "")}</strong>
          </div>
          <span class="static-source-tag">Downstream Workflow</span>
        </div>
        <div class="static-summary-text">${escapeHtml(workflow.summary || "")}</div>
      `;

      if (workflow.escalation_ticket) {
        const ticket = workflow.escalation_ticket;
        const steps = Array.isArray(ticket.manual_testing_checklist) ? ticket.manual_testing_checklist : [];
        innerContent += `
          <div class="workflow-ticket-box">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
              <span style="font-weight:700; color:var(--text-primary);">Ticket Ref: <code>${escapeHtml(ticket.ticket_id)}</code></span>
              <span class="wcag-criterion-tag" style="color:#f59e0b; border-color:rgba(245, 158, 11, 0.3);">Civic Area: ${escapeHtml(ticket.civic_impact_area)}</span>
            </div>
            <div style="color:var(--text-secondary); margin-top:0.25rem;">
              <strong>Escalation Protocol:</strong> ${escapeHtml(ticket.escalation_reason)}
            </div>
            ${steps.length > 0 ? `
              <div style="margin-top:0.4rem;">
                <strong style="color:var(--text-primary); display:block; margin-bottom:0.25rem;">Required Manual Verification Protocols:</strong>
                <ul class="workflow-checklist">
                  ${steps.map(s => `<li>${escapeHtml(s)}</li>`).join("")}
                </ul>
              </div>
            ` : ""}
            <div style="margin-top:0.35rem; font-size:0.75rem; color:var(--text-muted); line-height:1.4;">
              <em>${escapeHtml(ticket.statutory_compliance_note)}</em>
            </div>
          </div>
        `;
      } else if (workflow.remediation_patch) {
        const patch = workflow.remediation_patch;
        const checklist = Array.isArray(patch.verification_checklist) ? patch.verification_checklist : [];
        const patchCode = patch.proposed_remediation || "";
        innerContent += `
          <div class="workflow-ticket-box">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
              <span style="font-weight:700; color:var(--text-primary);">Patch Ref: <code>${escapeHtml(patch.patch_id)}</code></span>
              <span class="wcag-criterion-tag" style="color:#10b981; border-color:rgba(16, 185, 129, 0.3);">Rule: ${escapeHtml(patch.rule_id)}</span>
            </div>
            <div style="color:var(--text-secondary);">
              <strong>Developer Review Note:</strong> ${escapeHtml(patch.patch_explanation)}
            </div>
            ${patchCode ? `
              <div class="ai-code-remediation" style="margin-top:0.4rem;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                  <span class="ai-remediation-title">Suggested HTML Fix (Advisory Developer Review):</span>
                  <button type="button" class="copy-btn copy-patch-fix-btn">Copy Patch</button>
                </div>
                <pre class="ai-code-block" style="color:#86efac;"><code>${escapeHtml(patchCode)}</code></pre>
              </div>
            ` : ""}
            ${checklist.length > 0 ? `
              <div style="margin-top:0.4rem;">
                <strong style="color:var(--text-primary); display:block; margin-bottom:0.25rem;">Developer Verification Checklist:</strong>
                <ul class="workflow-checklist">
                  ${checklist.map(c => `<li>${escapeHtml(c)}</li>`).join("")}
                </ul>
              </div>
            ` : ""}
            <div style="margin-top:0.35rem; font-size:0.75rem; color:var(--text-muted); line-height:1.4;">
              <em>${escapeHtml(patch.advisory_disclaimer)}</em>
            </div>
          </div>
        `;
      } else if (workflow.context_enrichment) {
        const enr = workflow.context_enrichment;
        const notes = Array.isArray(enr.contextual_notes) ? enr.contextual_notes : [];
        innerContent += `
          <div class="workflow-ticket-box">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
              <span style="font-weight:700; color:var(--text-primary);">Enrichment Ref: <code>${escapeHtml(enr.enrichment_id)}</code></span>
              <span class="wcag-criterion-tag" style="color:#3b82f6; border-color:rgba(59, 130, 246, 0.3);">Landmark: ${escapeHtml(enr.surrounding_landmark)}</span>
            </div>
            <div style="color:var(--text-secondary);">
              <strong>Detected Container:</strong> <code>${escapeHtml(enr.detected_container)}</code> &bull; <strong>Depth:</strong> ${escapeHtml(enr.context_depth)}
            </div>
            ${notes.length > 0 ? `
              <div style="margin-top:0.4rem;">
                <strong style="color:var(--text-primary); display:block; margin-bottom:0.25rem;">DOM Structural Observations:</strong>
                <ul class="workflow-checklist">
                  ${notes.map(n => `<li>${escapeHtml(n)}</li>`).join("")}
                </ul>
              </div>
            ` : ""}
            <div style="margin-top:0.35rem; font-size:0.775rem; color:var(--text-secondary); line-height:1.4;">
              <strong>Investigation Advice:</strong> ${escapeHtml(enr.investigation_guidance)}
            </div>
          </div>
        `;
      }

      wfCard.innerHTML = innerContent;

      const copyPatchBtn = wfCard.querySelector(".copy-patch-fix-btn");
      if (copyPatchBtn && workflow.remediation_patch && workflow.remediation_patch.proposed_remediation) {
        copyPatchBtn.addEventListener("click", () => {
          copyToClipboard(workflow.remediation_patch.proposed_remediation);
          copyPatchBtn.textContent = "Copied!";
          setTimeout(() => (copyPatchBtn.textContent = "Copy Patch"), 1800);
        });
      }

      container.appendChild(wfCard);
    }

    // 3. Amazon Bedrock Contextual Explanation Card (Rendered ONLY on Genuine Successful Response)
    if (explanation.status === "success" && explanation.is_llm_generated === true) {
      const bedrockCard = document.createElement("div");
      bedrockCard.className = "bedrock-explanation-card";

      const bModel = escapeHtml(explanation.model_id || "Amazon Bedrock");
      const bLatency = explanation.latency_ms ? `${Math.round(explanation.latency_ms)} ms` : "";
      const bFix = explanation.proposed_remediation || "";
      const valSteps = Array.isArray(explanation.validation_steps) ? explanation.validation_steps : [];

      bedrockCard.innerHTML = `
        <div class="ai-card-title-row">
          <div class="static-guidance-title">
            <span class="bedrock-pill">Amazon Bedrock Explanation</span>
            <span class="bedrock-model-tag">${bModel}</span>
          </div>
          <div style="display:flex; align-items:center; gap:0.4rem;">
            ${bLatency ? `<span class="latency-pill">${bLatency}</span>` : ""}
            <span class="static-source-tag">Live GenAI (Conditioned on Decider)</span>
          </div>
        </div>
        <div class="static-summary-text">${escapeHtml(explanation.plain_language_explanation || "")}</div>
        ${
          explanation.why_it_matters
            ? `
          <div class="verification-step-box" style="border-left-color: #f97316;">
            <strong>User Impact:</strong> ${escapeHtml(explanation.why_it_matters)}
          </div>
        `
            : ""
        }
        ${
          bFix
            ? `
          <div class="ai-code-remediation">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <span class="ai-remediation-title">Proposed Remediation (Bedrock):</span>
              <button type="button" class="copy-btn copy-bedrock-fix-btn">Copy Fix Code</button>
            </div>
            <pre class="ai-code-block" style="color:#fdba74;"><code>${escapeHtml(bFix)}</code></pre>
          </div>
        `
            : ""
        }
        ${
          valSteps.length > 0
            ? `
          <div style="font-size:0.8125rem; color:var(--text-secondary);">
            <strong style="color:var(--text-primary); display:block; margin-bottom:0.25rem;">Verification Steps:</strong>
            <ul style="margin:0; padding-left:1.25rem;">
              ${valSteps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}
            </ul>
          </div>
        `
            : ""
        }
      `;

      const copyBedrockBtn = bedrockCard.querySelector(".copy-bedrock-fix-btn");
      if (copyBedrockBtn && bFix) {
        copyBedrockBtn.addEventListener("click", () => {
          copyToClipboard(bFix);
          copyBedrockBtn.textContent = "Copied!";
          setTimeout(() => (copyBedrockBtn.textContent = "Copy Fix Code"), 1800);
        });
      }
      container.appendChild(bedrockCard);
    }

    // 3. Deterministic Static WCAG Guidance Card (Always Rendered as Ground Truth)
    const guidanceCard = document.createElement("div");
    guidanceCard.className = "static-guidance-card";

    const standardFix = staticGuidance.standard_fix || "";
    guidanceCard.innerHTML = `
      <div class="ai-card-title-row">
        <div class="static-guidance-title">
          <span class="static-pill">Static WCAG Guidance</span>
          <span class="wcag-criterion-tag">${escapeHtml(staticGuidance.wcag_criterion || "WCAG 2.1 Standard")}</span>
        </div>
        <span class="static-source-tag">Deterministic (No LLM)</span>
      </div>
      <div class="static-summary-text">${escapeHtml(staticGuidance.summary || "")}</div>
      ${
        standardFix
          ? `
        <div class="ai-code-remediation">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="ai-remediation-title">Standard Fix Pattern:</span>
            <button type="button" class="copy-btn copy-static-fix-btn">Copy Fix Pattern</button>
          </div>
          <pre class="ai-code-block"><code>${escapeHtml(standardFix)}</code></pre>
        </div>
      `
          : ""
      }
      ${
        staticGuidance.verification_step
          ? `
        <div class="verification-step-box">
          <strong>Verification Step:</strong> ${escapeHtml(staticGuidance.verification_step)}
        </div>
      `
          : ""
      }
    `;

    const copyStaticBtn = guidanceCard.querySelector(".copy-static-fix-btn");
    if (copyStaticBtn && standardFix) {
      copyStaticBtn.addEventListener("click", () => {
        copyToClipboard(standardFix);
        copyStaticBtn.textContent = "Copied!";
        setTimeout(() => (copyStaticBtn.textContent = "Copy Fix Pattern"), 1800);
      });
    }
    container.appendChild(guidanceCard);

    // 4. Honest Engine Status Notice Card
    const noticeCard = document.createElement("div");
    noticeCard.className = "decider-only-notice-card";

    let noticeIcon = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
    let noticeTitle = "Decider-Only Configuration:";
    let noticeBody = "Amazon Bedrock is disabled. Live AI requests use only the hosted Strands Decider 2B API quota.";

    if (explanation.status === "success") {
      noticeTitle = "Dual-Engine Pipeline Active:";
      noticeBody = "Strands Decider 2B executed the policy action decision; Amazon Bedrock generated contextual remediation guidance.";
    } else if (explanation.status === "fallback") {
      noticeIcon = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
      noticeTitle = "Amazon Bedrock Fallback Active:";
      const reasonMsg = explanation.fallback_reason === "access_denied_or_verification_pending"
        ? "AWS account verification is pending or model access is unverified."
        : (explanation.fallback_reason === "timeout" ? "Request timed out." : "Bedrock service was unreachable.");
      noticeBody = `${reasonMsg} Safely defaulted to deterministic static WCAG guidance without disrupting Decider policy.`;
    } else if (explanation.status === "unconfigured") {
      noticeTitle = "Amazon Bedrock Unconfigured:";
      noticeBody = "AWS credentials are not set in environment. Safely defaulted to deterministic static WCAG guidance.";
    }

    noticeCard.innerHTML = `
      <div class="notice-header">
        ${noticeIcon}
        <strong>${escapeHtml(noticeTitle)}</strong>
        <span>${escapeHtml(noticeBody)}</span>
      </div>
      <div class="ai-advisory-note">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        <span>Advisory suggestion only. No website code has been modified. Automated audits do not certify full WCAG compliance.</span>
      </div>
    `;
    container.appendChild(noticeCard);
  }

  /* ==========================================================================
     History Drawer & Persistence
     ========================================================================== */
  async function loadHistory() {
    try {
      const response = await fetch("/api/history?limit=30");
      if (!response.ok) return;
      const data = await response.json();

      const items = data.items || [];
      els.historyCountBadge.textContent = data.total || items.length;

      renderHistoryList(items);
    } catch {
      // Graceful fallback if server unavailable
    }
  }

  function renderHistoryList(items) {
    els.historyList.innerHTML = "";

    if (!items || items.length === 0) {
      els.historyEmpty.style.display = "flex";
      return;
    }

    els.historyEmpty.style.display = "none";

    items.forEach((item) => {
      const card = document.createElement("div");
      card.className = "history-item-card";

      const isSuccess = item.status === "SUCCESS";
      const statusPillClass = isSuccess ? "impact-minor" : "impact-critical";

      card.innerHTML = `
        <div class="history-item-top">
          <span class="history-url">${escapeHtml(item.url)}</span>
          <span class="impact-badge ${statusPillClass}">${item.status}</span>
        </div>
        <div class="history-item-meta">
          <span>${formatTimestamp(item.timestamp)}</span>
          <span>•</span>
          <span>${Math.round(item.duration_ms)} ms</span>
        </div>
        <div class="history-item-counts">
          ${
            isSuccess
              ? `
            <span class="pill-count" style="background:#ef4444">${item.critical_count} crit</span>
            <span class="pill-count" style="background:#f97316">${item.serious_count} ser</span>
            <span class="pill-count" style="background:#f59e0b">${item.moderate_count} mod</span>
            <span class="pill-count" style="background:#10b981">${item.passes_count} pass</span>
          `
              : `<span style="color:var(--critical); font-size:0.75rem;">${escapeHtml(item.error_category || "Error")}</span>`
          }
        </div>
      `;

      card.addEventListener("click", () => {
        loadScanById(item.id);
        closeHistoryDrawer();
      });

      els.historyList.appendChild(card);
    });
  }

  async function loadScanById(scanId) {
    try {
      const response = await fetch(`/api/scans/${scanId}`);
      if (!response.ok) {
        showToast("Failed to load historical scan.");
        return;
      }
      const data = await response.json();
      if (data.status === "SUCCESS") {
        renderScanSuccess(data);
        showToast(`Loaded scan #${scanId} from local history.`);
      } else {
        renderScanFailure(data);
      }
    } catch (err) {
      showToast("Error loading scan: " + err.message);
    }
  }

  function openHistoryDrawer() {
    loadHistory();
    els.historyDrawer.style.display = "flex";
    els.historyToggleBtn.setAttribute("aria-expanded", "true");
  }

  function closeHistoryDrawer() {
    els.historyDrawer.style.display = "none";
    els.historyToggleBtn.setAttribute("aria-expanded", "false");
  }

  async function handleClearHistory() {
    if (!confirm("Are you sure you want to clear all local scan history? This action cannot be undone.")) {
      return;
    }
    try {
      const res = await fetch("/api/history", { method: "DELETE" });
      if (res.ok) {
        showToast("Scan history cleared.");
        loadHistory();
      }
    } catch (err) {
      showToast("Failed to clear history: " + err.message);
    }
  }

  /* ==========================================================================
     JSON Download & Modal
     ========================================================================== */
  function downloadCurrentJson() {
    if (!state.currentReport) {
      showToast("No active scan report to download.");
      return;
    }
    const id = state.currentReport.id || "report";
    const filename = `accesslens-report-${id}.json`;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.currentReport, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", filename);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    showToast("Downloaded " + filename);
  }

  function openRawJsonModal() {
    if (!state.currentReport) return;
    els.modalJsonCode.textContent = JSON.stringify(state.currentReport, null, 2);
    els.jsonModal.showModal();
  }

  function closeRawJsonModal() {
    els.jsonModal.close();
  }

  /* ==========================================================================
     Event Listeners & Setup
     ========================================================================== */
  function updateFilterChipUI() {
    els.filterChips.forEach((chip) => {
      const sev = chip.getAttribute("data-severity");
      chip.classList.toggle("active", sev === state.activeSeverityFilter);
    });
  }

  function setupEventListeners() {
    // Theme toggle
    els.themeToggleBtn.addEventListener("click", toggleTheme);

    // Scan form
    els.scanForm.addEventListener("submit", handleScanSubmit);

    // Preset pills
    els.presetPills.forEach((p) => p.addEventListener("click", handlePresetClick));

    // Severity filter buttons
    els.filterChips.forEach((chip) => {
      chip.addEventListener("click", () => {
        state.activeSeverityFilter = chip.getAttribute("data-severity");
        updateFilterChipUI();
        renderViolationsList();
      });
    });

    // Search input
    els.searchInput.addEventListener("input", (e) => {
      state.searchQuery = e.target.value;
      els.searchClearBtn.style.display = state.searchQuery ? "block" : "none";
      renderViolationsList();
    });

    els.searchClearBtn.addEventListener("click", () => {
      state.searchQuery = "";
      els.searchInput.value = "";
      els.searchClearBtn.style.display = "none";
      renderViolationsList();
      els.searchInput.focus();
    });

    // Download & JSON buttons
    els.downloadJsonBtn.addEventListener("click", downloadCurrentJson);
    els.viewRawJsonBtn.addEventListener("click", openRawJsonModal);
    els.modalCloseBtn.addEventListener("click", closeRawJsonModal);
    els.modalCopyJsonBtn.addEventListener("click", () => {
      if (state.currentReport) {
        copyToClipboard(JSON.stringify(state.currentReport, null, 2));
        els.modalCopyJsonBtn.textContent = "Copied!";
        setTimeout(() => (els.modalCopyJsonBtn.textContent = "Copy JSON"), 1800);
      }
    });

    // History drawer controls
    els.historyToggleBtn.addEventListener("click", openHistoryDrawer);
    els.historyCloseBtn.addEventListener("click", closeHistoryDrawer);
    els.historyBackdrop.addEventListener("click", closeHistoryDrawer);
    els.historyClearBtn.addEventListener("click", handleClearHistory);

    // Keyboard navigation (Escape closes modal and drawer)
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        if (els.jsonModal.open) {
          closeRawJsonModal();
        } else if (els.historyDrawer.style.display === "flex") {
          closeHistoryDrawer();
        }
      }
    });
  }

  /* ==========================================================================
     Utility Helpers
     ========================================================================== */
  function copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function formatTimestamp(isoStr) {
    if (!isoStr) return "";
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return isoStr;
    }
  }

  // Initialization
  document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    setupEventListeners();
    loadHistory();
  });
})();
