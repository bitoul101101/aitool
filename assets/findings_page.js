(function () {
  const body = document.querySelector("#findings-table tbody");
  if (!body) {
    return;
  }

  const search = document.getElementById("findings-search");
  const project = document.getElementById("findings-filter-project");
  const repo = document.getElementById("findings-filter-repo");
  const status = document.getElementById("findings-filter-status");
  const severity = document.getElementById("findings-filter-severity");
  const rule = document.getElementById("findings-filter-rule");
  const applyBtn = document.getElementById("apply-findings-action-btn");
  const htmlBtn = document.getElementById("generate-findings-html-btn");
  const csvBtn = document.getElementById("generate-findings-csv-btn");
  const jsonBtn = document.getElementById("generate-findings-json-btn");
  const prevBtn = document.getElementById("findings-prev-btn");
  const nextBtn = document.getElementById("findings-next-btn");
  const pageInfo = document.getElementById("findings-page-info");
  const selectAll = document.getElementById("findings-select-all");
  const PAGE_SIZE = 25;
  let currentPage = 1;
  let sortState = { index: null, dir: 1, kind: "text" };

  function rows() {
    return Array.from(body.querySelectorAll("tr.finding-row")).filter((row) => row.querySelectorAll("td").length > 1);
  }

  function closeDetailRow(row) {
    const next = row?.nextElementSibling;
    if (next && next.classList.contains("finding-detail-row")) {
      next.remove();
      row.classList.remove("row-expanded");
    }
  }

  function closeAllDetailRows() {
    rows().forEach((row) => closeDetailRow(row));
  }

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function highlightSnippet(content, match) {
    const escapedContent = escapeHtml(content);
    const escapedMatch = escapeHtml(match);
    if (!escapedMatch) {
      return escapedContent;
    }
    const idx = escapedContent.indexOf(escapedMatch);
    if (idx === -1) {
      return escapedContent;
    }
    return `${escapedContent.slice(0, idx)}<mark class="snippet-hit">${escapedMatch}</mark>${escapedContent.slice(idx + escapedMatch.length)}`;
  }

  function renderRichContent(content, { codeOnly = false, highlight = "" } = {}) {
    const text = String(content || "");
    if (!text) {
      return "";
    }
    if (codeOnly) {
      return `<pre class="finding-detail-code"><code>${highlightSnippet(text, highlight)}</code></pre>`;
    }
    const fenceRe = /```([a-zA-Z0-9_+-]*)\n?([\s\S]*?)```/g;
    let lastIndex = 0;
    let html = "";
    let match;
    while ((match = fenceRe.exec(text)) !== null) {
      const before = text.slice(lastIndex, match.index).trim();
      if (before) {
        html += `<p>${escapeHtml(before).replace(/\n/g, "<br>")}</p>`;
      }
      const language = (match[1] || "").trim();
      const code = match[2] || "";
      html += `<pre class="finding-detail-code"><code${language ? ` data-lang="${escapeHtml(language)}"` : ""}>${highlightSnippet(code.trim(), highlight)}</code></pre>`;
      lastIndex = fenceRe.lastIndex;
    }
    const tail = text.slice(lastIndex).trim();
    if (tail) {
      html += `<p>${escapeHtml(tail).replace(/\n/g, "<br>")}</p>`;
    }
    return html || `<p>${escapeHtml(text).replace(/\n/g, "<br>")}</p>`;
  }

  function detailBlock(title, content, options = {}) {
    if (!content) {
      return "";
    }
    return `<h4>${title}</h4>${renderRichContent(content, options)}`;
  }

  function toggleDetailRow(row) {
    const existing = row.nextElementSibling;
    if (existing && existing.classList.contains("finding-detail-row")) {
      closeDetailRow(row);
      return;
    }
    closeAllDetailRows();
    const detailRow = document.createElement("tr");
    detailRow.className = "finding-detail-row";
    const detailCell = document.createElement("td");
    detailCell.colSpan = row.children.length;
    const verdict = row.dataset.llmVerdict ? `<div class="scorecard"><span class="scorechip">LLM Verdict: ${escapeHtml(row.dataset.llmVerdict)}</span></div>` : "";
    const reviewed = row.dataset.llmReviewed === "1";
    const reason = row.dataset.llmReason || "";
    const remediation = row.dataset.remediation || "";
    const secureExample = row.dataset.llmSecureExample || "";
    const match = row.dataset.match || "";
    const fallback = reviewed
      ? '<p class="finding-detail-note">LLM reviewed this finding, but no explanation was stored in history.</p>'
      : '<p class="finding-detail-note">No LLM explanation is stored for this finding yet.</p>';
    const secureExampleBlock = secureExample
      ? detailBlock("Secure Code Example", secureExample, { codeOnly: true, highlight: match })
      : '<p class="finding-detail-note">No secure code example is stored for this finding yet.</p>';
    detailCell.innerHTML = `<div class="finding-detail-panel">${verdict}${detailBlock("Why It's Problematic", reason)}${detailBlock("How to Fix It", remediation)}${secureExampleBlock}${(!reason && !remediation && !secureExample) ? fallback : ""}</div>`;
    detailRow.appendChild(detailCell);
    row.after(detailRow);
    row.classList.add("row-expanded");
  }

  function updateBulkAction() {
    const hasSelection = rows().some((row) => row.querySelector(".finding-check")?.checked);
    applyBtn?.classList.toggle("hidden", !hasSelection);
    htmlBtn?.classList.toggle("hidden", !hasSelection);
    csvBtn?.classList.toggle("hidden", !hasSelection);
    jsonBtn?.classList.toggle("hidden", !hasSelection);
  }

  function displayedRows() {
    return rows().filter((row) => row.style.display !== "none");
  }

  function updateSelectAllState() {
    if (!selectAll) {
      return;
    }
    const visibleChecks = displayedRows().map((row) => row.querySelector(".finding-check")).filter(Boolean);
    const checked = visibleChecks.filter((box) => box.checked).length;
    selectAll.checked = visibleChecks.length > 0 && checked === visibleChecks.length;
    selectAll.indeterminate = checked > 0 && checked < visibleChecks.length;
  }

  function filteredRows() {
    const q = (search?.value || "").toLowerCase().trim();
    return rows().filter((row) => {
      const text = row.textContent.toLowerCase();
      return (!q || text.includes(q))
        && (!project?.value || row.dataset.project === project.value)
        && (!repo?.value || row.dataset.repo === repo.value)
        && (!status?.value || row.dataset.status === status.value)
        && (!severity?.value || row.dataset.severity === severity.value)
        && (!rule?.value || row.dataset.rule === rule.value);
    });
  }

  function renderPage() {
    const visible = filteredRows();
    const totalPages = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
    currentPage = Math.min(currentPage, totalPages);
    const start = (currentPage - 1) * PAGE_SIZE;
    const end = start + PAGE_SIZE;
    rows().forEach((row) => { row.style.display = "none"; });
    visible.slice(start, end).forEach((row) => { row.style.display = ""; });
    rows().forEach((row) => {
      if (row.style.display === "none") {
        closeDetailRow(row);
      }
    });
    if (pageInfo) {
      pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
    }
    if (prevBtn) {
      prevBtn.disabled = currentPage <= 1;
    }
    if (nextBtn) {
      nextBtn.disabled = currentPage >= totalPages;
    }
    updateBulkAction();
    updateSelectAllState();
  }

  function applyFilters() {
    currentPage = 1;
    renderPage();
  }

  function cellValue(row, index, kind) {
    if (kind === "datetime") {
      return Number(row.dataset.ts) || 0;
    }
    const text = (row.children[index]?.innerText || "").trim();
    if (kind === "number") {
      return Number(text) || 0;
    }
    return text.toLowerCase();
  }

  function sortRows(index, kind) {
    const currentRows = rows();
    if (sortState.index === index) {
      sortState.dir *= -1;
    } else {
      sortState = { index, dir: kind === "datetime" ? -1 : 1, kind };
    }
    currentRows.sort((a, b) => {
      const av = cellValue(a, sortState.index, sortState.kind);
      const bv = cellValue(b, sortState.index, sortState.kind);
      if (av < bv) {
        return -1 * sortState.dir;
      }
      if (av > bv) {
        return 1 * sortState.dir;
      }
      return 0;
    });
    currentRows.forEach((row) => body.appendChild(row));
    currentPage = 1;
    renderPage();
  }

  document.querySelectorAll("#findings-table thead th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => sortRows(Number(th.dataset.colIndex || 0), th.dataset.sort));
  });
  [search, project, repo, status, severity, rule].forEach((el) => el?.addEventListener("input", applyFilters));
  [project, repo, status, severity, rule].forEach((el) => el?.addEventListener("change", applyFilters));
  document.getElementById("reset-findings-filters")?.addEventListener("click", () => {
    if (search) search.value = "";
    if (project) project.value = "";
    if (repo) repo.value = "";
    if (status) status.value = "";
    if (severity) severity.value = "";
    if (rule) rule.value = "";
    applyFilters();
  });
  rows().forEach((row) => row.querySelector(".finding-check")?.addEventListener("change", () => {
    updateBulkAction();
    updateSelectAllState();
  }));
  rows().forEach((row) => row.addEventListener("click", (event) => {
    if (event.target.closest("a,button,input,label,select")) {
      return;
    }
    toggleDetailRow(row);
  }));
  selectAll?.addEventListener("change", () => {
    displayedRows().forEach((row) => {
      const box = row.querySelector(".finding-check");
      if (box) {
        box.checked = selectAll.checked;
      }
    });
    updateBulkAction();
    updateSelectAllState();
  });
  prevBtn?.addEventListener("click", () => {
    if (currentPage > 1) {
      currentPage -= 1;
      renderPage();
    }
  });
  nextBtn?.addEventListener("click", () => {
    const totalPages = Math.max(1, Math.ceil(filteredRows().length / PAGE_SIZE));
    if (currentPage < totalPages) {
      currentPage += 1;
      renderPage();
    }
  });
  sortRows(10, "datetime");
})();
