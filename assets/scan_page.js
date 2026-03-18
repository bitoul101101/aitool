(function () {
  const repoSearch = document.getElementById("repo-search");
  const repoCount = document.getElementById("repo-selection-count");
  const startScanBtn = document.getElementById("start-scan-btn");
  const newScanForm = document.getElementById("new-scan-form");
  const runningNotice = document.getElementById("running-scan-notice");
  const modelSelect = document.getElementById("llm-model-select");
  const modelWarning = document.getElementById("model-size-warning");
  const logEl = document.getElementById("scan-log");
  const textEl = document.getElementById("scan-state-text");
  const timelineEl = document.getElementById("phase-timeline");
  const baselineSummary = document.getElementById("baseline-summary");
  const hardwareSummary = document.getElementById("hardware-summary");
  const stopBtn = document.getElementById("stop-scan-btn");

  if (
    !repoSearch &&
    !startScanBtn &&
    !runningNotice &&
    !modelSelect &&
    !logEl &&
    !timelineEl &&
    !baselineSummary &&
    !hardwareSummary
  ) {
    return;
  }

  let submitInFlight = false;
  let redirectedToResults = false;
  let previousScanState = null;
  let replaceInitialLog = Boolean(logEl && logEl.textContent.trim());
  let stream = null;

  function escHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, function (ch) {
      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[ch];
    });
  }

  function repoCheckboxes() {
    return Array.from(document.querySelectorAll(".repo-checkbox"));
  }

  function updateRepoCount() {
    const selectedCount = repoCheckboxes().filter(function (cb) { return cb.checked; }).length;
    if (repoCount) {
      repoCount.textContent = selectedCount + " selected";
    }
    if (startScanBtn && !startScanBtn.dataset.blockedByRun) {
      startScanBtn.disabled = selectedCount === 0;
    }
  }

  function filterRepos() {
    if (!repoSearch) {
      updateRepoCount();
      return;
    }
    const query = (repoSearch.value || "").toLowerCase().trim();
    document.querySelectorAll(".repo-row").forEach(function (row) {
      const name = row.dataset.repoName || "";
      row.style.display = !query || name.includes(query) ? "flex" : "none";
    });
    updateRepoCount();
  }

  function parseModelSize(model) {
    const match = (model || "").toLowerCase().match(/(^|[^0-9])(\d+(?:\.\d+)?)\s*([bm])(?!\w)/);
    if (!match) {
      return 0;
    }
    const value = parseFloat(match[2] || "0");
    return match[3] === "b" ? value : value / 1000;
  }

  function updateModelWarning() {
    if (!modelWarning || !modelSelect) {
      return;
    }
    const size = parseModelSize(modelSelect.value);
    const under4b = size > 0 && size < 4;
    modelWarning.textContent = "Selected model is below 4B and may be unreliable for LLM review.";
    modelWarning.classList.toggle("hidden", !under4b);
  }

  function setModelOptions(models) {
    if (!modelSelect || !Array.isArray(models) || !models.length) {
      return;
    }
    const currentValue = modelSelect.value || "";
    const uniqueModels = Array.from(new Set(models.filter(Boolean)));
    if (currentValue && !uniqueModels.includes(currentValue)) {
      uniqueModels.unshift(currentValue);
    }
    modelSelect.innerHTML = uniqueModels.map(function (name) {
      const safe = escHtml(name);
      return '<option value="' + safe + '">' + safe + "</option>";
    }).join("");
    if (uniqueModels.includes(currentValue)) {
      modelSelect.value = currentValue;
    }
    updateModelWarning();
  }

  async function refreshModels() {
    if (!modelSelect) {
      return;
    }
    try {
      const url = new URL("/api/ollama/models", window.location.origin);
      url.searchParams.set("refresh", "1");
      const res = await fetch(url.toString(), { headers: { Accept: "application/json" } });
      if (!res.ok) {
        return;
      }
      const data = await res.json();
      setModelOptions(data.models || []);
    } catch (_err) {
    }
  }

  function titleCaseState(state) {
    const text = String(state || "").trim();
    return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Ready";
  }

  function timelineRows(items, scanState) {
    if (!items || !items.length) {
      return '<div class="muted">Timeline will appear after the scan starts.</div>';
    }
    const state = String(scanState || "").toLowerCase();
    const finished = ["done", "stopped", "error"].includes(state);
    return items
      .filter(function (item) {
        return finished || String(item.name || "").toLowerCase() !== "total";
      })
      .map(function (item) {
        const name = String(item.name || "");
        const rowClass = name.toLowerCase() === "total" ? "timeline-row total-row" : "timeline-row";
        return (
          '<div class="' + rowClass + '">' +
          '<span class="state-icon ' + escHtml(item.state || "pending") + '"></span>' +
          '<span class="timeline-name">' + escHtml(name) + "</span>" +
          "<strong>" + escHtml(item.duration || "—") + "</strong>" +
          "</div>"
        );
      })
      .join("");
  }

  function baselineList(items) {
    if (!items || !items.length) {
      return "<li>No fixed findings.</li>";
    }
    return items.slice(0, 8).map(function (item) {
      const line = item.line ? ":" + escHtml(item.line) : "";
      return (
        "<li><strong>" + escHtml(item.repo || item.provider_or_lib || "Finding") + "</strong> " +
        '<span class="muted">' + escHtml(item.file || "") + line + "</span></li>"
      );
    }).join("");
  }

  function renderBaseline(data) {
    if (!baselineSummary) {
      return;
    }
    const delta = data.delta || {};
    const card = baselineSummary.closest(".card");
    if (!delta.has_baseline) {
      if (card) {
        card.remove();
      }
      return;
    }
    const newEl = document.getElementById("baseline-new-count");
    const existingEl = document.getElementById("baseline-existing-count");
    const fixedEl = document.getElementById("baseline-fixed-count");
    const sourceEl = document.getElementById("baseline-source");
    const listEl = document.getElementById("baseline-fixed-list");
    if (newEl) {
      newEl.textContent = String(delta.new_count || 0);
    }
    if (existingEl) {
      existingEl.textContent = String(delta.existing_count ?? delta.unchanged_count ?? 0);
    }
    if (fixedEl) {
      fixedEl.textContent = String(delta.fixed_count || 0);
    }
    if (sourceEl) {
      sourceEl.textContent = "Compared to " + (delta.baseline_file || "previous scan");
    }
    if (listEl) {
      listEl.innerHTML = baselineList(delta.fixed_findings || []);
    }
  }

  function renderHardware(data) {
    if (!hardwareSummary) {
      return;
    }
    const hardware = data.hardware || {};
    const cpuEl = document.getElementById("hardware-cpu");
    const ramEl = document.getElementById("hardware-ram");
    const gpuEl = document.getElementById("hardware-gpu");
    const diskIoEl = document.getElementById("hardware-disk-io");
    if (cpuEl) {
      cpuEl.textContent = String(hardware.cpu_percent || "Sampling...");
    }
    if (ramEl) {
      ramEl.textContent = String(hardware.ram_text || "Unavailable");
    }
    if (gpuEl) {
      gpuEl.textContent = String(hardware.gpu_text || "Unavailable");
    }
    if (diskIoEl) {
      diskIoEl.textContent = String(hardware.disk_io_text || "Sampling...");
    }
  }

  function updateSelectionStatus(data) {
    if (!startScanBtn && !runningNotice) {
      return;
    }
    if (submitInFlight && String(data.state || "").toLowerCase() === "running") {
      submitInFlight = false;
    }
    if (submitInFlight) {
      return;
    }
    const blocked = String(data.state || "").toLowerCase() === "running";
    if (startScanBtn) {
      startScanBtn.dataset.blockedByRun = blocked ? "1" : "";
      startScanBtn.disabled = blocked || repoCheckboxes().filter(function (cb) { return cb.checked; }).length === 0;
    }
    if (runningNotice) {
      runningNotice.textContent = "A scan is in progress. Wait until it finishes before starting a new scan.";
      runningNotice.classList.toggle("hidden", !blocked);
    }
  }

  function updateRunningStatus(data) {
    const state = String(data.state || "").toLowerCase();
    const justFinished = previousScanState === "running" && state === "done";
    if (textEl) {
      textEl.textContent = titleCaseState(data.state);
    }
    if (timelineEl) {
      timelineEl.innerHTML = timelineRows(data.phase_timeline || [], data.state || "");
    }
    renderBaseline(data);
    renderHardware(data);
    if (stopBtn) {
      stopBtn.disabled = state !== "running";
    }
    if (state !== "running" && stream) {
      stream.close();
      stream = null;
    }
    if (!redirectedToResults && justFinished && data.scan_id && data.report && data.report.html_name) {
      redirectedToResults = true;
      window.setTimeout(function () {
        window.location.assign("/scan/" + encodeURIComponent(data.scan_id) + "?tab=results");
      }, 900);
    }
    previousScanState = state;
  }

  function startLogStream() {
    if (!logEl || stream) {
      return;
    }
    stream = new EventSource("/api/scan/stream");
    stream.onmessage = function (event) {
      if (!event.data) {
        return;
      }
      let line = event.data;
      try {
        line = JSON.parse(event.data);
      } catch (_err) {
      }
      if (replaceInitialLog) {
        logEl.textContent = line;
        replaceInitialLog = false;
      } else {
        logEl.textContent += (logEl.textContent.trim() ? "\n" : "") + line;
      }
      logEl.scrollTop = logEl.scrollHeight;
    };
    stream.onerror = function () {
      if (stream) {
        stream.close();
        stream = null;
      }
    };
  }

  async function pollStatus() {
    try {
      const res = await fetch("/api/scan/status", { headers: { Accept: "application/json" } });
      if (!res.ok) {
        return;
      }
      const data = await res.json();
      updateSelectionStatus(data);
      updateRunningStatus(data);
    } catch (_err) {
    }
  }

  document.getElementById("select-all-repos-btn")?.addEventListener("click", function () {
    repoCheckboxes().forEach(function (cb) {
      const row = cb.closest(".repo-row");
      if (!row || row.style.display !== "none") {
        cb.checked = true;
      }
    });
    updateRepoCount();
  });
  document.getElementById("select-none-repos-btn")?.addEventListener("click", function () {
    repoCheckboxes().forEach(function (cb) { cb.checked = false; });
    updateRepoCount();
  });
  repoCheckboxes().forEach(function (cb) {
    cb.addEventListener("change", updateRepoCount);
  });
  repoSearch?.addEventListener("input", filterRepos);
  modelSelect?.addEventListener("change", updateModelWarning);
  newScanForm?.addEventListener("submit", function () {
    submitInFlight = true;
    if (startScanBtn) {
      startScanBtn.dataset.blockedByRun = "";
      startScanBtn.disabled = true;
    }
    runningNotice?.classList.add("hidden");
  });

  filterRepos();
  updateModelWarning();
  refreshModels();
  startLogStream();
  pollStatus();
  window.setInterval(pollStatus, 3000);
})();
