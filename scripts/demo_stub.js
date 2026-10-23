"use strict";
(() => {
  const DEMO = __DEMO_DATA__;
  const VIEWS = ["overview", "inventory", "findings", "shield", "ledger", "reports", "settings"];
  const target = decodeURIComponent(location.hash.slice(1));
  const [view, detail] = target.split(":");

  function pickEntry() {
    for (const row of document.querySelectorAll("#content tbody tr")) {
      const name = row.querySelector(".name");
      if (name && name.textContent === detail) {
        row.click();
        return;
      }
    }
  }

  function showControls() {
    const colors = { minimize: "#e0a43a", maximize: "#3fbf7f", close: "#e5484d" };
    for (const button of document.querySelectorAll("#winctl .wc")) {
      const glyph = button.querySelector("svg");
      button.style.transition = "none";
      glyph.style.transition = "none";
      button.style.background = colors[button.dataset.win];
      glyph.style.opacity = "1";
    }
  }

  function navigate() {
    const index = VIEWS.indexOf(view);
    if (index > 0) document.querySelectorAll("#nav button")[index].click();
    if (detail === "hover") showControls();
    else if (detail === "editor") setTimeout(() => document.querySelector(".status-card .btn.primary").click(), 200);
    else if (detail) setTimeout(pickEntry, 50);
    document.getElementById("toast").hidden = view !== "overview";
  }

  window.pywebview = {
    api: {
      state: async () => DEMO.state,
      scan: () => {
        if (view === "busy") return new Promise(() => {});
        setTimeout(navigate, 60);
        return Promise.resolve(DEMO.report);
      },
      accept_changes: async () => DEMO.report,
      ledger: async () => DEMO.ledger,
      verify_anchor: async () => DEMO.ledger,
      export: async () => ({ saved: false }),
      set_language: async () => DEMO.state,
      set_option: async () => DEMO.state,
      add_project: async () => DEMO.state,
      remove_project: async () => DEMO.state,
      shield: async () => DEMO.shield,
      shield_rules_text: async () => ({ exists: true, text: DEMO.rules_text }),
      window_minimize: async () => null,
      window_close: async () => null,
      window_state: async () => ({ maximized: false }),
      window_maximize: async () => null,
      window_restore: async () => null,
      settings_history: async () => ({ items: DEMO.history || [] }),
      window_resize: async () => null,
    },
  };
})();
