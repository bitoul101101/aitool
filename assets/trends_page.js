(function () {
  const dashboard = document.getElementById("trend-dashboard");
  const selector = document.getElementById("trends-layout-select");
  if (!dashboard || !selector) return;

  const STORAGE_KEY = "phantomlm.trends.layout.mode.v1";
  const LAYOUTS = {
    balanced: {
      findings_over_time: [6, 8],
      critical_over_time: [6, 8],
      new_fixed_over_time: [5, 8],
      top_repos_by_risk: [7, 14],
      top_noisy_rules: [5, 6],
      suppression_rate_by_rule: [5, 6],
      llm_review_failure_rate_by_model: [12, 8],
    },
    compact: {
      findings_over_time: [6, 7],
      critical_over_time: [6, 7],
      new_fixed_over_time: [4, 7],
      top_repos_by_risk: [8, 10],
      top_noisy_rules: [4, 5],
      suppression_rate_by_rule: [4, 5],
      llm_review_failure_rate_by_model: [12, 7],
    },
  };

  function cards() {
    return Array.from(dashboard.querySelectorAll(".trend-panel"));
  }

  function applyLayout(mode) {
    const layout = LAYOUTS[mode] || LAYOUTS.balanced;
    dashboard.setAttribute("data-layout", mode);
    cards().forEach((card) => {
      const id = card.dataset.cardId;
      const dims = layout[id];
      if (!dims) return;
      card.style.setProperty("--col-span", dims[0]);
      card.style.setProperty("--row-span", dims[1]);
    });
  }

  const initialMode = (() => {
    try {
      return localStorage.getItem(STORAGE_KEY) || "balanced";
    } catch (_err) {
      return "balanced";
    }
  })();

  selector.value = initialMode in LAYOUTS ? initialMode : "balanced";
  applyLayout(selector.value);

  selector.addEventListener("change", () => {
    applyLayout(selector.value);
    try {
      localStorage.setItem(STORAGE_KEY, selector.value);
    } catch (_err) {
      // Ignore storage failures.
    }
  });
})();
