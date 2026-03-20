setTimeout(() => {
  document.querySelectorAll(".toast").forEach((el) => el.remove());
}, 5000);

(() => {
  const url = new URL(window.location.href);
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
    if (event.key !== "phantomlm.history.updated") {
      return;
    }
    if (!syncablePaths.has(window.location.pathname)) {
      return;
    }
    window.location.reload();
  });
})();
