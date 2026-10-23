"use strict";
(() => {
  const DEMO = __DEMO_DATA__;
  const VIEWS = ["overview", "inventory", "findings", "ledger", "reports", "settings"];
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

  function navigate() {
    const index = VIEWS.indexOf(view);
    if (index > 0) document.querySelectorAll("#nav button")[index].click();
    if (detail) setTimeout(pickEntry, 50);
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
    },
  };
})();
