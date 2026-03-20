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
  const prevBtn = document.getElementById("findings-prev-btn");
  const nextBtn = document.getElementById("findings-next-btn");
  const pageInfo = document.getElementById("findings-page-info");
  const selectAll = document.getElementById("findings-select-all");
  const PAGE_SIZE = 25;
  let currentPage = 1;
  let sortState = { index: null, dir: 1, kind: "text" };

  function rows() {
    return Array.from(body.querySelectorAll("tr")).filter((row) => row.querySelectorAll("td").length > 1);
  }

  function updateBulkAction() {
    applyBtn?.classList.toggle("hidden", !rows().some((row) => row.querySelector(".finding-check")?.checked));
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

  document.querySelectorAll("#findings-table thead th[data-sort]").forEach((th, index) => {
    th.addEventListener("click", () => sortRows(index + 1, th.dataset.sort));
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
  sortRows(8, "datetime");
})();
