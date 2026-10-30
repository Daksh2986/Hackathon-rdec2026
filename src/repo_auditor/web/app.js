"use strict";

const form = document.querySelector("#audit-form");
const submitButton = document.querySelector("#submit-button");
const errorMessage = document.querySelector("#form-error");
const auditSection = document.querySelector("#audit-section");
const statusBadge = document.querySelector("#status-badge");
const auditMessage = document.querySelector("#audit-message");
const summaryGrid = document.querySelector("#summary-grid");
const findingList = document.querySelector("#finding-list");
const findingSearch = document.querySelector("#finding-search");
const findingFilterCount = document.querySelector("#finding-filter-count");
const emptyFindings = document.querySelector("#empty-findings");
const progressState = document.querySelector("#progress-state");
const progressLabel = document.querySelector("#progress-label");
const MAX_RENDERED_FINDINGS = 200;
let pollTimer;
let renderedFindingCards = [];

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setFormBusy(busy) {
  submitButton.disabled = busy;
  submitButton.firstElementChild.textContent = busy ? "Audit in progress…" : "Start security audit";
  errorMessage.hidden = true;
}

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.hidden = false;
  setFormBusy(false);
}

function metric(value, label) {
  const card = element("div", "metric");
  card.append(element("strong", "", String(value)), element("span", "", label));
  return card;
}

function renderReport(job) {
  const report = job.report;
  if (!report) return;

  summaryGrid.replaceChildren(
    metric(report.status, "Run status"),
    metric(report.summary.findings, "Findings"),
    metric(report.summary.files_discovered, "Files inventoried"),
    metric(report.summary.dependencies_resolved, "Dependencies")
  );
  auditMessage.textContent = `${job.target} · ${report.created_at}`;

  const reportLinks = document.querySelector("#report-links");
  reportLinks.replaceChildren();
  for (const [filename, label] of [["report.md", "Open Markdown report"], ["report.json", "View JSON report"]]) {
    const link = element("a", "", label);
    link.href = `/api/audits/${encodeURIComponent(job.id)}/files/${filename}`;
    link.target = "_blank";
    link.rel = "noopener";
    reportLinks.append(link);
  }
  reportLinks.hidden = false;

  const analyzerSection = document.querySelector("#analyzer-section");
  const analyzerList = document.querySelector("#analyzer-list");
  analyzerList.replaceChildren();
  for (const analyzer of report.analyzers) {
    const row = element("div", "coverage-item");
    const description = element("div");
    description.append(element("strong", "", analyzer.name), element("p", "", analyzer.message));
    row.append(description, element("span", `coverage-status ${analyzer.status}`, analyzer.status));
    analyzerList.append(row);
  }
  analyzerSection.hidden = report.analyzers.length === 0;

  const warningSection = document.querySelector("#warning-section");
  const warningList = document.querySelector("#warning-list");
  warningList.replaceChildren();
  for (const warning of report.warnings) warningList.append(element("li", "", warning));
  warningSection.hidden = report.warnings.length === 0;

  const findingSection = document.querySelector("#finding-section");
  const totalFindings = report.findings_total ?? report.findings.length;
  document.querySelector("#finding-count").textContent = `${totalFindings} total`;
  findingList.replaceChildren();
  const fragment = document.createDocumentFragment();
  renderedFindingCards = [];
  for (const finding of report.findings.slice(0, MAX_RENDERED_FINDINGS)) {
    const card = element("article", `finding-card severity-${finding.severity}`);
    const titleRow = element("div", "finding-title-row");
    titleRow.append(element("span", `severity ${finding.severity}`, finding.severity), element("h4", "", finding.title));
    card.append(titleRow);
    card.append(element("div", "finding-meta", `${finding.rule_id} · ${finding.status} · confidence ${finding.confidence}`));
    card.append(element("p", "", finding.description));
    const details = element("details");
    details.append(element("summary", "", "Evidence, locations & remediation"));
    const list = element("ul");
    for (const location of finding.locations) {
      const line = location.line ? `:${location.line}` : "";
      list.append(element("li", "", `${location.path}${line} — ${location.role}`));
    }
    for (const evidence of finding.evidence) list.append(element("li", "", evidence));
    list.append(element("li", "", `Remediation: ${finding.remediation}`));
    details.append(list);
    card.append(details);
    card.dataset.search = [
      finding.title,
      finding.rule_id,
      finding.severity,
      finding.status,
      finding.description,
      ...finding.locations.map((location) => `${location.path} ${location.role}`),
    ].join(" ").toLowerCase();
    renderedFindingCards.push(card);
    fragment.append(card);
  }
  findingList.append(fragment);
  const truncationNote = document.querySelector("#truncation-note");
  truncationNote.hidden = !report.findings_truncated;
  truncationNote.textContent = report.findings_truncated
    ? `Showing the first ${MAX_RENDERED_FINDINGS} findings for faster display. Open the full JSON report to review all ${totalFindings}.`
    : "";
  findingSearch.value = "";
  filterFindings();
  findingSection.hidden = totalFindings === 0;
  statusBadge.textContent = report.status;
  statusBadge.className = `status-badge ${report.status === "complete" ? "complete" : ""}`;
  auditMessage.textContent = report.status === "complete"
    ? `Audit finished. Review the findings and analyzer coverage below. Target: ${job.target}`
    : `Audit finished with incomplete coverage. Review warnings before interpreting the results. Target: ${job.target}`;
  progressState.classList.add("finished");
  progressLabel.textContent = "Audit complete";
  setFormBusy(false);
}

function filterFindings() {
  const query = findingSearch.value.trim().toLowerCase();
  let visible = 0;
  for (const card of renderedFindingCards) {
    const matches = !query || card.dataset.search.includes(query);
    card.hidden = !matches;
    if (matches) visible += 1;
  }
  findingFilterCount.textContent = query ? `${visible} of ${renderedFindingCards.length} shown` : `${renderedFindingCards.length} shown`;
  emptyFindings.hidden = visible > 0 || renderedFindingCards.length === 0;
}

async function pollJob(jobId, delay = 450) {
  try {
    const response = await fetch(`/api/audits/${encodeURIComponent(jobId)}`, { cache: "no-store" });
    const job = await response.json();
    if (!response.ok) throw new Error(job.error || "Could not retrieve audit status.");
    statusBadge.textContent = job.status;
    statusBadge.className = `status-badge ${job.status === "completed" ? "complete" : job.status === "failed" ? "failed" : ""}`;
    if (job.status === "queued" || job.status === "running") {
      progressLabel.textContent = job.status === "queued"
        ? "Your audit is queued…"
        : "Scanning files and checking supported dependencies…";
      auditMessage.textContent = "The audit runs in the background. You can keep this page open while it works.";
      pollTimer = window.setTimeout(() => pollJob(jobId, Math.min(Math.round(delay * 1.35), 1400)), delay);
      return;
    }
    if (job.status === "failed") {
      auditMessage.textContent = "The audit could not be completed.";
      progressState.classList.add("finished");
      showError(job.error || "The audit failed. Check the target path and output folder, then try again.");
      return;
    }
    renderReport(job);
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not retrieve audit status.");
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  window.clearTimeout(pollTimer);
  setFormBusy(true);
  auditSection.hidden = false;
  statusBadge.textContent = "starting";
  statusBadge.className = "status-badge";
  auditMessage.textContent = "Starting your audit…";
  progressState.classList.remove("finished");
  progressLabel.textContent = "Preparing the audit…";
  summaryGrid.replaceChildren();
  document.querySelector("#report-links").hidden = true;
  document.querySelector("#analyzer-section").hidden = true;
  document.querySelector("#warning-section").hidden = true;
  document.querySelector("#finding-section").hidden = true;
  auditSection.scrollIntoView({ behavior: "smooth", block: "start" });

  try {
    const response = await fetch("/api/audits", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: form.elements.target.value,
        output: form.elements.output.value,
        offline: form.elements.offline.checked,
      }),
    });
    const job = await response.json();
    if (!response.ok) throw new Error(job.error || "Could not start the audit.");
    progressLabel.textContent = "Audit started";
    await pollJob(job.id);
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not start the audit.");
  }
});

findingSearch.addEventListener("input", filterFindings);

async function loadDefaults() {
  try {
    const response = await fetch("/api/config", { cache: "no-store" });
    const config = await response.json();
    if (!response.ok) throw new Error(config.error || "Could not load local workspace defaults.");
    if (!form.elements.target.value) form.elements.target.value = config.default_target;
    if (!form.elements.output.value) form.elements.output.value = config.default_output;
  } catch (error) {
    showError(error instanceof Error ? error.message : "Could not load local workspace defaults.");
  }
}

loadDefaults();
