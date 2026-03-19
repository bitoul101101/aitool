(function () {
  const hBody = document.querySelector("#history-table tbody");
  if (!hBody) {
    return;
  }

  const search = document.getElementById("history-search");
  const fp = document.getElementById("filter-project");
  const fr = document.getElementById("filter-repo");
  const fs = document.getElementById("filter-status");
  const fm = document.getElementById("filter-model");
  const delBtn = document.getElementById("delete-selected-btn");
  const form = document.getElementById("history-form");
  const prevBtn = document.getElementById("history-prev-btn");
  const nextBtn = document.getElementById("history-next-btn");
  const pageInfo = document.getElementById("history-page-info");
  const selectPage = document.getElementById("history-select-page");
  const PAGE_SIZE = 20;
  let currentPage = 1;
  let sortState = { index: null, dir: -1, kind: "datetime" };

  function rows() {
    return Array.from(hBody.querySelectorAll("tr")).filter((r) => r.querySelectorAll("td").length > 1);
  }

  function visiblePageRows() {
    return rows().filter((row) => row.style.display !== "none");
  }

  function updateDelete() {
    delBtn?.classList.toggle("hidden", !rows().some((r) => r.querySelector(".history-check")?.checked));
    if (!selectPage) {
      return;
    }
    const visible = visiblePageRows();
    const selectedVisible = visible.filter((r) => r.querySelector(".history-check")?.checked);
    selectPage.checked = visible.length > 0 && selectedVisible.length === visible.length;
    selectPage.indeterminate = selectedVisible.length > 0 && selectedVisible.length < visible.length;
  }

  function filteredRows() {
    const q = (search?.value || "").toLowerCase().trim();
    return rows().filter((row) => {
      const text = row.textContent.toLowerCase();
      const ok = !q || text.includes(q);
      const okP = !fp?.value || row.dataset.project === fp.value;
      const okR = !fr?.value || row.dataset.repo === fr.value;
      const okS = !fs?.value || row.dataset.status === fs.value;
      const okM = !fm?.value || row.dataset.model === fm.value;
      return ok && okP && okR && okS && okM;
    });
  }

  function renderPage() {
    const visible = filteredRows();
    const totalPages = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
    currentPage = Math.min(currentPage, totalPages);
    const start = (currentPage - 1) * PAGE_SIZE;
    const end = start + PAGE_SIZE;
    rows().forEach((row) => {
      row.style.display = "none";
    });
    visible.slice(start, end).forEach((row) => {
      row.style.display = "";
    });
    if (pageInfo) {
      pageInfo.textContent = `Page ${totalPages ? currentPage : 1} of ${totalPages}`;
    }
    if (prevBtn) {
      prevBtn.disabled = currentPage <= 1;
    }
    if (nextBtn) {
      nextBtn.disabled = currentPage >= totalPages;
    }
    updateDelete();
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
      return Number(text.replace(":", ".")) || 0;
    }
    return text.toLowerCase();
  }

  function sortHistory(index, kind) {
    const rs = rows();
    if (sortState.index === index) {
      sortState.dir *= -1;
    } else {
      sortState = { index, dir: kind === "datetime" ? -1 : 1, kind };
    }
    rs.sort((a, b) => {
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
    rs.forEach((row) => hBody.appendChild(row));
    currentPage = 1;
    renderPage();
  }

  document.querySelectorAll("#history-table thead th[data-sort]").forEach((th, index) => {
    th.addEventListener("click", () => sortHistory(index + 1, th.dataset.sort));
  });
  [search, fp, fr, fs, fm].forEach((el) => el?.addEventListener("input", applyFilters));
  [fp, fr, fs, fm].forEach((el) => el?.addEventListener("change", applyFilters));
  document.getElementById("reset-history-filters")?.addEventListener("click", () => {
    if (search) search.value = "";
    if (fp) fp.value = "";
    if (fr) fr.value = "";
    if (fs) fs.value = "";
    if (fm) fm.value = "";
    applyFilters();
  });
  rows().forEach((r) => r.querySelector(".history-check")?.addEventListener("change", updateDelete));
  selectPage?.addEventListener("change", () => {
    visiblePageRows().forEach((row) => {
      const check = row.querySelector(".history-check");
      if (check) {
        check.checked = selectPage.checked;
      }
    });
    updateDelete();
  });
  form?.addEventListener("submit", (event) => {
    const selected = rows().filter((r) => r.querySelector(".history-check")?.checked).length;
    if (!selected) {
      event.preventDefault();
      return;
    }
    const noun = selected === 1 ? "scan" : "scans";
    if (!window.confirm(`Delete ${selected} selected ${noun}? This removes the scan history, activity log, and generated reports.`)) {
      event.preventDefault();
    }
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
  sortHistory(1, "datetime");
})();
