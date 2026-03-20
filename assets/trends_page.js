(function () {
  const dashboard = document.getElementById("trend-dashboard");
  if (!dashboard) return;

  const resetButton = document.getElementById("trends-reset-layout");
  const STORAGE_KEY = "phantomlm.trends.layout.v1";
  const DEFAULTS = {};

  function cards() {
    return Array.from(dashboard.querySelectorAll(".trend-panel"));
  }

  function captureDefaults() {
    cards().forEach((card, index) => {
      DEFAULTS[card.dataset.cardId] = {
        order: index,
        col: parseInt(card.dataset.colSpan || "4", 10),
        row: parseInt(card.dataset.rowSpan || "8", 10),
      };
    });
  }

  function loadLayout() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
    } catch (_err) {
      return {};
    }
  }

  function saveLayout() {
    const layout = {};
    cards().forEach((card, index) => {
      layout[card.dataset.cardId] = {
        order: index,
        col: parseInt(card.style.getPropertyValue("--col-span") || card.dataset.colSpan || "4", 10),
        row: parseInt(card.style.getPropertyValue("--row-span") || card.dataset.rowSpan || "8", 10),
      };
    });
    localStorage.setItem(STORAGE_KEY, JSON.stringify(layout));
  }

  function applyLayout() {
    const layout = loadLayout();
    const ordered = cards().sort((a, b) => {
      const left = layout[a.dataset.cardId]?.order ?? DEFAULTS[a.dataset.cardId]?.order ?? 0;
      const right = layout[b.dataset.cardId]?.order ?? DEFAULTS[b.dataset.cardId]?.order ?? 0;
      return left - right;
    });
    ordered.forEach((card) => dashboard.appendChild(card));
    ordered.forEach((card) => {
      const item = layout[card.dataset.cardId] || DEFAULTS[card.dataset.cardId];
      card.style.setProperty("--col-span", clamp(item.col, 3, 12));
      card.style.setProperty("--row-span", clamp(item.row, 6, 18));
    });
  }

  function clamp(value, min, max) {
    return Math.max(min, Math.min(max, Number(value) || min));
  }

  let dragCard = null;

  function closestCard(target) {
    return target && target.closest ? target.closest(".trend-panel") : null;
  }

  cards().forEach((card) => {
    const head = card.querySelector(".trend-card-head");
    if (head) {
      head.setAttribute("draggable", "true");
      head.addEventListener("dragstart", () => {
        dragCard = card;
        card.classList.add("dragging");
      });
      head.addEventListener("dragend", () => {
        if (dragCard) dragCard.classList.remove("dragging");
        cards().forEach((item) => item.classList.remove("drop-target"));
        dragCard = null;
        saveLayout();
      });
    }

    card.addEventListener("dragover", (event) => {
      if (!dragCard || dragCard === card) return;
      event.preventDefault();
      cards().forEach((item) => item.classList.remove("drop-target"));
      card.classList.add("drop-target");
    });

    card.addEventListener("drop", (event) => {
      if (!dragCard || dragCard === card) return;
      event.preventDefault();
      card.classList.remove("drop-target");
      const rect = card.getBoundingClientRect();
      const before = event.clientY < rect.top + rect.height / 2;
      if (before) {
        dashboard.insertBefore(dragCard, card);
      } else {
        dashboard.insertBefore(dragCard, card.nextSibling);
      }
      saveLayout();
    });

    const resizeHandle = card.querySelector(".trend-resize");
    if (resizeHandle) {
      resizeHandle.addEventListener("pointerdown", (event) => {
        event.preventDefault();
        event.stopPropagation();
        const startX = event.clientX;
        const startY = event.clientY;
        const startCol = parseInt(card.style.getPropertyValue("--col-span") || card.dataset.colSpan || "4", 10);
        const startRow = parseInt(card.style.getPropertyValue("--row-span") || card.dataset.rowSpan || "8", 10);
        const move = (moveEvent) => {
          const col = clamp(startCol + Math.round((moveEvent.clientX - startX) / 90), 3, 12);
          const row = clamp(startRow + Math.round((moveEvent.clientY - startY) / 36), 6, 18);
          card.style.setProperty("--col-span", col);
          card.style.setProperty("--row-span", row);
        };
        const up = () => {
          window.removeEventListener("pointermove", move);
          window.removeEventListener("pointerup", up);
          saveLayout();
        };
        window.addEventListener("pointermove", move);
        window.addEventListener("pointerup", up);
      });
    }
  });

  if (resetButton) {
    resetButton.addEventListener("click", () => {
      localStorage.removeItem(STORAGE_KEY);
      cards()
        .sort((a, b) => DEFAULTS[a.dataset.cardId].order - DEFAULTS[b.dataset.cardId].order)
        .forEach((card) => {
          card.style.setProperty("--col-span", DEFAULTS[card.dataset.cardId].col);
          card.style.setProperty("--row-span", DEFAULTS[card.dataset.cardId].row);
          dashboard.appendChild(card);
        });
    });
  }

  captureDefaults();
  applyLayout();
})();
