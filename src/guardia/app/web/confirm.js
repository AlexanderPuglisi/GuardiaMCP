"use strict";
(() => {
  let remaining = 0;
  let timer = null;
  let sent = false;

  function byId(id) {
    return document.getElementById(id);
  }

  function answer(choice) {
    if (sent) return;
    sent = true;
    clearInterval(timer);
    const remember = byId("remember").checked;
    window.pywebview.api.answer(choice === "allow" && remember ? "allow_remember" : choice);
  }

  function tick(ui) {
    remaining -= 1;
    byId("countdown").textContent = ui.countdown.split("{seconds}").join(String(Math.max(remaining, 0)));
    if (remaining <= 0) answer("timeout");
  }

  function lead(ui, data) {
    const box = byId("lead");
    const parts = (data.tool ? ui.lead_tool : ui.lead_method).split(/(\{server\}|\{tool\}|\{method\})/);
    const values = { "{server}": data.server, "{tool}": data.tool, "{method}": data.method };
    box.replaceChildren();
    for (const part of parts) {
      if (part in values) {
        const strong = document.createElement("b");
        strong.textContent = values[part];
        box.append(strong);
      } else if (part) {
        box.append(document.createTextNode(part));
      }
    }
  }

  async function start() {
    const data = await window.pywebview.api.details();
    const ui = data.ui;
    document.documentElement.lang = data.language;
    byId("title").textContent = ui.title;
    lead(ui, data);
    byId("reasons-title").textContent = ui.reasons;
    const list = byId("reasons");
    list.replaceChildren();
    for (const reason of data.reasons) {
      const item = document.createElement("li");
      item.textContent = reason;
      list.append(item);
    }
    byId("details-title").textContent = ui.details;
    byId("details").textContent = data.details;
    byId("details-box").hidden = !data.details;
    byId("remember-label").textContent = ui.remember;
    byId("allow").textContent = ui.allow;
    byId("block").textContent = ui.block;
    byId("close").setAttribute("aria-label", ui.block);
    byId("close").setAttribute("title", ui.block);
    byId("allow").addEventListener("click", () => answer("allow"));
    byId("block").addEventListener("click", () => answer("block"));
    byId("close").addEventListener("click", () => answer("block"));
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") answer("block");
    });
    remaining = data.seconds + 1;
    tick(ui);
    timer = setInterval(() => tick(ui), 1000);
    byId("block").focus();
  }

  if (window.pywebview && window.pywebview.api) start();
  else window.addEventListener("pywebviewready", start, { once: true });
})();
