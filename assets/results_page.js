(function () {
  const card = document.getElementById("report-progress-card");
  if (!card) return;

  const scanId = card.dataset.scanId || "";
  const active = card.dataset.reportGenerationActive === "1";
  if (!scanId || !active) return;

  const messageEl = document.getElementById("report-progress-message");
  const fillEl = document.getElementById("report-progress-fill");
  const metaEl = document.getElementById("report-progress-meta");

  function setProgress(payload) {
    const state = String(payload.state || "").toLowerCase();
    const current = Number(payload.current || 0);
    const total = Number(payload.total || 0);
    const pct = total > 0 ? Math.max(0, Math.min(100, Math.round((current / total) * 100))) : (state === "done" ? 100 : 0);
    if (messageEl) messageEl.textContent = payload.message || "";
    if (fillEl) fillEl.style.width = pct + "%";
    if (metaEl) metaEl.textContent = total > 0 ? `${current}/${total}` : (state === "done" ? "Complete" : "");
    if (state === "done") {
      try {
        localStorage.setItem(`phantomlm.report.updated.${scanId}`, String(Date.now()));
      } catch (_err) {
      }
      window.setTimeout(() => window.location.reload(), 600);
    }
    if (state === "error") {
      card.dataset.reportGenerationActive = "0";
    }
  }

  async function poll() {
    try {
      const res = await fetch(`/api/report-generation/status/${encodeURIComponent(scanId)}`, {
        headers: { Accept: "application/json" },
      });
      if (!res.ok) return;
      const payload = await res.json();
      setProgress(payload);
      if ((payload.state || "").toLowerCase() === "running" || (payload.state || "").toLowerCase() === "queued") {
        window.setTimeout(poll, 1500);
      }
    } catch (_err) {
      window.setTimeout(poll, 2500);
    }
  }

  poll();
})();
