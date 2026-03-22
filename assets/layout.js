setTimeout(() => {
  document.querySelectorAll(".toast").forEach((el) => el.remove());
}, 5000);

(() => {
  const exitButton = document.getElementById("exit-app-btn");
  if (!exitButton) {
    return;
  }

  async function exitApp() {
    const ok = window.confirm("Are you sure you want to exit?");
    if (!ok) {
      return;
    }

    const csrfToken = exitButton.dataset.csrf || "";
    const payload = JSON.stringify({ csrf_token: csrfToken });
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 1500);

    try {
      await fetch("/api/app/exit", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: payload,
        cache: "no-store",
        signal: controller.signal,
      });
    } catch (_err) {
      try {
        navigator.sendBeacon(
          "/api/app/exit",
          new Blob([payload], { type: "application/json" }),
        );
      } catch (_ignored) {
      }
    } finally {
      window.clearTimeout(timeout);
    }

    try {
      window.close();
    } catch (_err) {
    }

    document.body.innerHTML = [
      "<main class=\"app-closed-screen\">",
      "<section class=\"card\">",
      "<h1>PhantomLM stopped</h1>",
      "<p>The local server has been shut down.</p>",
      "<p>You can close this window.</p>",
      "</section>",
      "</main>",
    ].join("");
  }

  exitButton.addEventListener("click", exitApp);
})();

(() => {
  const url = new URL(window.location.href);
  const notice = String(url.searchParams.get("notice") || "");
  const path = window.location.pathname;

  try {
    if (path === "/history" && /^Deleted \d+ scan record\(s\)/.test(notice)) {
      localStorage.setItem("phantomlm.history.updated", String(Date.now()));
    }
    if (path === "/findings" && (notice.startsWith("Updated ") || notice.startsWith("Finding triage "))) {
      localStorage.setItem("phantomlm.triage.updated", String(Date.now()));
    }
    if (path === "/settings" && notice === "Settings saved") {
      localStorage.setItem("phantomlm.settings.updated", String(Date.now()));
    }
  } catch (_err) {
  }

  if (url.searchParams.has("notice") || url.searchParams.has("error")) {
    url.searchParams.delete("notice");
    url.searchParams.delete("error");
    history.replaceState(null, "", url.pathname + (url.search ? url.search : ""));
  }
})();

(() => {
  if (document.body.classList.contains("login-page")) {
    return;
  }

  const syncablePaths = new Set(["/history", "/findings", "/trends", "/inventory"]);
  const syncableStorageKeys = new Set(["phantomlm.history.updated", "phantomlm.triage.updated", "phantomlm.settings.updated"]);

  const banner = document.getElementById("connection-banner");
  let failures = 0;
  let reconnecting = false;

  function setDisconnected(flag) {
    if (!banner) {
      return;
    }
    banner.classList.toggle("hidden", !flag);
  }

  async function checkConnection() {
    try {
      const res = await fetch("/api/status", {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      if (res.status === 401) {
        window.location.assign("/login");
        return;
      }
      if (!res.ok) {
        throw new Error("status " + res.status);
      }
      failures = 0;
      reconnecting = false;
      setDisconnected(false);
    } catch (_err) {
      failures += 1;
      if (failures >= 2) {
        reconnecting = true;
        setDisconnected(true);
      }
    }
  }

  window.setInterval(checkConnection, 15000);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) {
      checkConnection();
      if (reconnecting) {
        window.setTimeout(() => window.location.reload(), 1200);
      }
    }
  });
  window.addEventListener("online", () => {
    checkConnection();
    if (reconnecting) {
      window.setTimeout(() => window.location.reload(), 1200);
    }
  });
  window.addEventListener("storage", (event) => {
    if (String(event.key || "").startsWith("phantomlm.report.updated.")) {
      const updatedScanId = String(event.key || "").slice("phantomlm.report.updated.".length);
      if (updatedScanId && updatedScanId === currentScanId()) {
        window.location.reload();
      }
      return;
    }
    if (!syncableStorageKeys.has(event.key)) {
      return;
    }
    if (!syncablePaths.has(window.location.pathname)) {
      return;
    }
    window.location.reload();
  });
})();
  function currentScanId() {
    if (window.location.pathname.startsWith("/scan/")) {
      return decodeURIComponent(window.location.pathname.slice("/scan/".length).split("/")[0] || "");
    }
    if (window.location.pathname === "/findings") {
      return String(new URL(window.location.href).searchParams.get("scan_id") || "");
    }
    return "";
  }
