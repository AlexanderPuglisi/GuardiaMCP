"use strict";
(() => {
  const SVG = "http://www.w3.org/2000/svg";
  const ICONS = {
    overview: ["M3 3h7v9H3z", "M14 3h7v5h-7z", "M14 12h7v9h-7z", "M3 16h7v5H3z"],
    inventory: ["M3 4h18v6H3z", "M3 14h18v6H3z", "M7 7h.01", "M7 17h.01"],
    findings: ["M12 3 2.5 20h19z", "M12 10v4", "M12 17h.01"],
    ledger: ["M4 3h16v18H4z", "M9 7h6", "M9 12h6", "M9 17h4"],
    reports: ["M12 3v12", "M7 10l5 5 5-5", "M4 19h16"],
    settings: ["M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z", "M12 2v3", "M12 19v3", "M2 12h3", "M19 12h3", "M4.9 4.9l2.1 2.1", "M17 17l2.1 2.1", "M4.9 19.1 7 17", "M17 7l2.1-2.1"],
  };
  const VIEWS = ["overview", "inventory", "findings", "ledger", "reports", "settings"];
  const state = {
    ui: {}, settings: {}, report: null, view: "overview", version: "", dataDir: "",
    entryId: null, entryType: "all", problemsOnly: false, entrySearch: "",
    findingLevel: "all", findingSearch: "", ledger: null,
  };
  const MIN_SIZE = [900, 600];
  const windowState = { maximized: false, saved: null, resizing: null, target: null, pending: false };

  function t(key, values) {
    let text = state.ui[key] || key;
    for (const [name, value] of Object.entries(values || {})) {
      text = text.split("{" + name + "}").join(String(value));
    }
    return text;
  }

  function el(tag, options, ...children) {
    const node = document.createElement(tag);
    const opts = options || {};
    if (opts.cls) node.className = opts.cls;
    if (opts.text !== undefined) node.textContent = String(opts.text);
    if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) node.setAttribute(k, String(v));
    if (opts.on) for (const [k, v] of Object.entries(opts.on)) node.addEventListener(k, v);
    for (const child of children) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function icon(name) {
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.8");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    for (const d of ICONS[name] || []) {
      const path = document.createElementNS(SVG, "path");
      path.setAttribute("d", d);
      svg.append(path);
    }
    return svg;
  }

  function localTime(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return String(iso).slice(0, 19);
    return date.toLocaleString(state.settings.language === "en" ? "en-GB" : "it-IT",
      { dateStyle: "short", timeStyle: "medium" });
  }

  function badge(level, label) {
    return el("span", { cls: "badge b-" + (level || "none"), text: label || "—" });
  }

  function toast(message) {
    const box = document.getElementById("toast");
    box.textContent = message;
    box.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { box.hidden = true; }, 6000);
  }

  function busy(on, text) {
    document.getElementById("busy").hidden = !on;
    document.getElementById("busy-text").textContent = text || "";
    document.getElementById("scan-button").disabled = on;
  }

  async function call(method, ...args) {
    try {
      return await window.pywebview.api[method](...args);
    } catch (error) {
      toast(t("error", { message: (error && error.message) || String(error) }));
      throw error;
    }
  }

  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const area = el("textarea", { text });
      document.body.append(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    toast(t("copied"));
  }

  function apply(next) {
    state.ui = next.ui;
    state.settings = next.settings;
    state.version = next.version;
    state.dataDir = next.data_dir;
    if (next.report) state.report = next.report;
    document.documentElement.lang = next.language;
  }

  function show(view) {
    state.view = view;
    if (view === "ledger") loadLedger();
    render();
  }

  function renderNav() {
    const nav = document.getElementById("nav");
    nav.replaceChildren();
    const report = state.report;
    const counts = {
      inventory: report ? report.entries.length : "",
      findings: report ? report.total : "",
    };
    const severe = report ? report.summary.some((s) => s.count && (s.severity === "critical" || s.severity === "high")) : false;
    for (const view of VIEWS) {
      const label = t("nav_" + view);
      const count = counts[view] !== undefined && counts[view] !== ""
        ? el("em", { cls: "count" + (view === "findings" && severe ? " alert" : ""), text: counts[view] }) : null;
      const button = el("button", { attrs: { type: "button", title: label, "aria-label": label }, on: { click: () => show(view) } },
        icon(view), el("span", { text: label }), count);
      if (view === state.view) button.setAttribute("aria-current", "page");
      nav.append(button);
    }
  }

  function renderHeader() {
    const report = state.report;
    document.getElementById("title").textContent = t("nav_" + state.view);
    document.getElementById("help").textContent = t("help_" + state.view);
    document.documentElement.dataset.glow = state.settings.glow === false ? "off" : "on";
    for (const button of document.querySelectorAll("#winctl .wc")) {
      const key = button.dataset.win === "maximize" && windowState.maximized ? "restore" : button.dataset.win;
      button.setAttribute("aria-label", t("win_" + key));
      button.setAttribute("title", t("win_" + key));
    }
    document.getElementById("subtitle").textContent = report
      ? t("last_scan", { time: localTime(report.generated_at), seconds: report.seconds })
      : t("never");
    document.getElementById("baseline-pill").textContent = report && report.baseline.active ? t("baseline_active") : t("baseline_off");
    document.getElementById("offline").textContent = t("offline");
    document.getElementById("version").textContent = "v" + state.version;
    const scan = document.getElementById("scan-button");
    scan.replaceChildren(el("span", { text: t("scan_now") }));
    for (const button of document.querySelectorAll(".lang button")) {
      button.setAttribute("aria-pressed", String(button.dataset.lang === state.settings.language));
    }
  }

  function needScan() {
    return el("div", { cls: "card empty", text: t("need_scan") });
  }

  function overview(report) {
    const root = el("section");
    const max = Math.max(1, ...report.summary.map((s) => s.count));
    const cards = el("div", { cls: "grid sev-cards" });
    for (const item of report.summary) {
      const fill = el("i");
      fill.style.width = Math.round((item.count / max) * 100) + "%";
      cards.append(el("div", { cls: "card sev-card" }, el("small", { text: item.label }), el("b", { text: item.count }),
        el("div", { cls: "bar " + item.severity }, fill)));
    }
    root.append(cards, el("h2", { text: t("priority_title") }));
    const list = el("div", { cls: "list" });
    if (!report.priority.length) list.append(el("div", { cls: "empty", text: t("priority_empty") }));
    for (const finding of report.priority) {
      list.append(el("button", {
        cls: "prio-item", attrs: { type: "button" },
        on: { click: () => openEntry(finding.entry_id) },
      }, badge(finding.severity, finding.severity_label),
      el("div", {}, el("b", { text: finding.title }), el("p", { text: finding.why })),
      el("span", { cls: "who", text: finding.entry_name })));
    }
    root.append(list, el("h2", { text: t("protection_title") }));
    const status = el("div", { cls: "grid status-cards" });
    const baseline = report.baseline;
    status.append(el("div", { cls: "card status-card" },
      el("h3", {}, el("span", { cls: "led " + (baseline.active ? (report.has_rug_pull ? "warn" : "") : "off") }), t("baseline_title")),
      el("p", { text: baseline.line || t("baseline_off") })));
    const ledger = report.ledger;
    const ledgerRow = el("div", { cls: "row" },
      el("button", { cls: "btn", text: t("verify_now"), attrs: { type: "button" }, on: { click: () => show("ledger") } }),
      ledger.anchor ? el("button", { cls: "btn", text: t("copy_anchor"), attrs: { type: "button" }, on: { click: () => copy(ledger.anchor) } }) : null);
    status.append(el("div", { cls: "card status-card" },
      el("h3", {}, el("span", { cls: "led " + (ledger.tampered ? "bad" : ledger.intact ? "" : "warn") }), t("ledger_title")),
      el("p", { text: ledger.line }), ledgerRow));
    status.append(el("div", { cls: "card status-card" },
      el("h3", {}, el("span", { cls: "led warn" }), t("coverage_title")),
      el("p", { text: report.coverage.join(" ") })));
    root.append(status);
    if (!report.complete) root.append(el("div", { cls: "note-box", text: t("incomplete", { count: report.errors }) }));
    root.append(el("div", { cls: "note-box", text: state.ui["scan.not_safe"] }));
    return root;
  }

  function segmented(options, current, onPick) {
    const group = el("div", { cls: "seg", attrs: { role: "group" } });
    for (const [value, label] of options) {
      group.append(el("button", {
        text: label, attrs: { type: "button", "aria-pressed": String(value === current) },
        on: { click: () => onPick(value) },
      }));
    }
    return group;
  }

  function search(value, placeholder, onInput) {
    const input = el("input", { cls: "search", attrs: { type: "search", placeholder, "aria-label": placeholder } });
    input.value = value;
    input.addEventListener("input", () => onInput(input.value));
    return input;
  }

  function findingBlock(finding) {
    const rows = el("dl", {},
      el("dt", { text: state.ui["scan.where"] }), el("dd", { cls: "mono", text: finding.where }));
    if (finding.evidence) rows.append(el("dt", { text: state.ui["scan.found"] }), el("dd", { cls: "mono", text: finding.evidence }));
    rows.append(el("dt", { text: state.ui["scan.why"] }), el("dd", { text: finding.why }),
      el("dt", { text: state.ui["scan.fix"] }), el("dd", { text: finding.fix }));
    return el("div", { cls: "finding" },
      el("h4", {}, badge(finding.severity, finding.severity_label), el("span", { text: finding.title }), el("code", { text: finding.rule_id })),
      rows);
  }

  function entryMatches(entry) {
    if (state.entryType !== "all" && entry.type !== state.entryType) return false;
    if (state.problemsOnly && !entry.findings.length) return false;
    const query = state.entrySearch.trim().toLowerCase();
    if (!query) return true;
    return [entry.name, entry.client, entry.path, entry.target].some((v) => v.toLowerCase().includes(query));
  }

  function openEntry(id) {
    if (!id) return;
    state.entryId = id;
    state.view = "inventory";
    render();
  }

  function detail(entry) {
    const box = el("aside", { cls: "detail" });
    if (!entry) {
      box.append(el("div", { cls: "empty", text: t("select_entry") }));
      return box;
    }
    const chips = el("div", { cls: "chips" });
    if (entry.coverage) chips.append(el("span", { cls: "chip", text: entry.coverage }));
    box.append(el("div", { cls: "detail-head" },
      badge(entry.risk, entry.risk_label),
      el("h3", { text: entry.name }),
      el("div", { cls: "muted" }, entry.client + " · " + entry.scope + (entry.target ? " · " : ""), entry.target ? el("span", { cls: "mono", text: entry.target }) : null),
      chips));
    if (!entry.findings.length) box.append(el("div", { cls: "empty", text: t("no_findings") }));
    for (const finding of entry.findings) box.append(findingBlock(finding));
    const actions = el("div", { cls: "actions" },
      el("button", { cls: "btn", text: t("copy_path"), attrs: { type: "button" }, on: { click: () => copy(entry.path) } }));
    if (entry.findings.some((f) => f.rug_pull)) {
      actions.append(el("button", { cls: "btn danger", text: t("accept_changes"), attrs: { type: "button" }, on: { click: acceptChanges } }));
    }
    box.append(actions);
    return box;
  }

  function inventory(report) {
    const root = el("section");
    root.append(el("div", { cls: "toolbar" },
      search(state.entrySearch, t("search_entries"), (v) => { state.entrySearch = v; renderTable(); }),
      segmented([["all", t("filter_all")], ["server", t("filter_servers")], ["skill", t("filter_skills")]], state.entryType,
        (v) => { state.entryType = v; render(); }),
      segmented([[true, t("filter_problems")]], state.problemsOnly, () => { state.problemsOnly = !state.problemsOnly; render(); })));
    const body = el("tbody");
    const table = el("table", {},
      el("thead", {}, el("tr", {}, el("th", { text: t("col_risk") }), el("th", { text: t("col_name") }),
        el("th", { text: t("col_client") }), el("th", { text: t("col_type") }))), body);
    const split = el("div", { cls: "split" }, table, detail(report.entries.find((e) => e.id === state.entryId)));
    root.append(split);
    function renderTable() {
      body.replaceChildren();
      const entries = report.entries.filter(entryMatches);
      if (!entries.length) body.append(el("tr", {}, el("td", { cls: "empty", text: t("no_results"), attrs: { colspan: 4 } })));
      for (const entry of entries) {
        const row = el("tr", { attrs: { "aria-selected": String(entry.id === state.entryId), tabindex: 0 } },
          el("td", {}, badge(entry.risk, entry.risk_label)),
          el("td", {}, el("div", { cls: "name", text: entry.name }), el("div", { cls: "where", text: entry.path })),
          el("td", { text: entry.client }),
          el("td", { text: entry.type_label + (entry.transport ? " · " + entry.transport : "") }));
        const pick = () => { state.entryId = entry.id; render(); };
        row.addEventListener("click", pick);
        row.addEventListener("keydown", (event) => { if (event.key === "Enter") pick(); });
        body.append(row);
      }
    }
    renderTable();
    return root;
  }

  function findingMatches(finding) {
    const rank = finding.severity_rank;
    if (state.findingLevel === "severe" && rank < 3) return false;
    if (state.findingLevel === "medium" && rank !== 2) return false;
    if (state.findingLevel === "minor" && rank > 1) return false;
    const query = state.findingSearch.trim().toLowerCase();
    if (!query) return true;
    return [finding.title, finding.where, finding.rule_id, finding.entry_name].some((v) => v.toLowerCase().includes(query));
  }

  function findingsView(report) {
    const root = el("section");
    root.append(el("div", { cls: "toolbar" },
      search(state.findingSearch, t("search_findings"), (v) => { state.findingSearch = v; renderRows(); }),
      segmented([["all", t("filter_all")], ["severe", t("filter_severe")], ["medium", t("filter_medium")], ["minor", t("filter_minor")]],
        state.findingLevel, (v) => { state.findingLevel = v; render(); })));
    const body = el("tbody");
    root.append(el("table", {},
      el("thead", {}, el("tr", {}, el("th", { text: t("col_level") }), el("th", { text: t("col_problem") }),
        el("th", { text: t("col_where") }), el("th", { text: t("col_rule") }))), body));
    const all = [...report.findings, ...report.file_findings].sort((a, b) => b.severity_rank - a.severity_rank);
    function renderRows() {
      body.replaceChildren();
      const rows = all.filter(findingMatches);
      if (!rows.length) body.append(el("tr", {}, el("td", { cls: "empty", text: t("no_results"), attrs: { colspan: 4 } })));
      for (const finding of rows) {
        const row = el("tr", { attrs: { tabindex: 0 } },
          el("td", {}, badge(finding.severity, finding.severity_label)),
          el("td", { text: finding.title }),
          el("td", { text: (finding.entry_name ? finding.entry_name + " · " : "") + (finding.line ? t("line", { line: finding.line }) : finding.path) }),
          el("td", { cls: "mono", text: finding.rule_id }));
        row.addEventListener("click", () => openEntry(finding.entry_id));
        row.addEventListener("keydown", (event) => { if (event.key === "Enter") openEntry(finding.entry_id); });
        body.append(row);
      }
    }
    renderRows();
    if (report.has_rug_pull) {
      root.append(el("div", { cls: "note-box" }, t("rug_pull_note") + " ",
        el("button", { cls: "btn danger", text: t("accept_changes"), attrs: { type: "button" }, on: { click: acceptChanges } })));
    }
    return root;
  }

  async function loadLedger(anchor) {
    try {
      state.ledger = anchor ? await call("verify_anchor", anchor) : await call("ledger", 50);
      if (state.view === "ledger") render();
    } catch { }
  }

  function ledgerView() {
    const root = el("section");
    const ledger = state.ledger;
    if (!ledger) {
      root.append(el("div", { cls: "card empty", text: t("loading") }));
      return root;
    }
    const level = ledger.tampered ? "bad" : ledger.intact ? "" : "warn";
    const summary = !ledger.records ? t("ledger_empty")
      : ledger.tampered ? t("ledger_tampered") : ledger.intact ? t("ledger_ok", { records: ledger.records }) : t("ledger_unverified");
    const card = el("div", { cls: "card status-card" }, el("h3", {}, el("span", { cls: "led " + level }), summary));
    if (ledger.anchor_checked && ledger.intact) card.append(el("p", { text: t("anchor_ok") }));
    for (const issue of ledger.issues) {
      card.append(el("p", { cls: "issue", text: (issue.line ? t("line", { line: issue.line }) + ": " : "") + issue.problem }));
    }
    root.append(card);
    if (ledger.anchor) {
      root.append(el("h2", { text: t("anchor_title") }),
        el("div", { cls: "anchor" }, el("span", { cls: "mono", text: ledger.anchor }),
          el("button", { cls: "btn", text: t("copy"), attrs: { type: "button" }, on: { click: () => copy(ledger.anchor) } })),
        el("p", { cls: "muted", text: t("anchor_hint") }));
    }
    const input = el("input", { cls: "search", attrs: { placeholder: t("anchor_placeholder"), "aria-label": t("anchor_placeholder") } });
    root.append(el("div", { cls: "toolbar" }, input,
      el("button", { cls: "btn", text: t("verify_anchor"), attrs: { type: "button" }, on: { click: () => loadLedger(input.value) } }),
      el("button", { cls: "btn", text: t("verify_now"), attrs: { type: "button" }, on: { click: () => loadLedger() } })));
    root.append(el("h2", { text: t("events_title") }));
    const list = el("div", { cls: "list" });
    if (!ledger.events.length) list.append(el("div", { cls: "empty", text: t("ledger_empty") }));
    for (const event of ledger.events) {
      list.append(el("div", { cls: "event" },
        el("span", { cls: "seq", text: event.seq }),
        el("div", {}, el("b", { text: event.label }), " · ", event.details, el("div", { cls: "hash", text: event.hash })),
        el("span", { cls: "muted", text: localTime(event.time) })));
    }
    root.append(list);
    return root;
  }

  async function exportReport(format) {
    try {
      const result = await call("export", format);
      if (result.saved) toast(t("exported", { path: result.path, hash: result.sha256.slice(0, 16) + "…" }));
    } catch { }
  }

  function reportsView() {
    const root = el("section");
    const cards = el("div", { cls: "grid export-cards" });
    for (const format of ["html", "json", "sarif"]) {
      cards.append(el("div", { cls: "card export-card" },
        el("h3", { text: t("export_" + format + "_title") }),
        el("p", { text: t("export_" + format + "_text") }),
        el("button", { cls: "btn" + (format === "html" ? " primary" : ""), text: t("export_button"), attrs: { type: "button" },
          on: { click: () => exportReport(format) } })));
    }
    root.append(cards, el("div", { cls: "note-box", text: t("export_note") }));
    return root;
  }

  function settingRow(title, text, control) {
    return el("div", { cls: "setting" }, el("div", {}, el("b", { text: title }), el("span", { text })), control);
  }

  function toggle(name) {
    const value = Boolean(state.settings[name]);
    return el("button", {
      cls: "switch", attrs: { type: "button", role: "switch", "aria-checked": String(value), "aria-label": t("settings_" + name) },
      on: { click: async () => { try { apply(await call("set_option", name, !value)); render(); } catch { } } },
    });
  }

  function settingsView() {
    const root = el("section");
    const language = el("select", { attrs: { "aria-label": t("settings_language") } },
      el("option", { text: "Italiano", attrs: { value: "it" } }), el("option", { text: "English", attrs: { value: "en" } }));
    language.value = state.settings.language;
    language.addEventListener("change", () => setLanguage(language.value));
    const card = el("div", { cls: "card card-plain" },
      settingRow(t("settings_language"), t("settings_language_text"), language),
      settingRow(t("settings_skills"), t("settings_skills_text"), toggle("skills")),
      settingRow(t("settings_tools"), t("settings_tools_text"), toggle("tools")),
      settingRow(t("settings_baseline"), t("settings_baseline_text"), toggle("baseline")),
      settingRow(t("settings_glow"), t("settings_glow_text"), toggle("glow")),
      settingRow(t("settings_projects"), t("settings_projects_text"),
        el("button", { cls: "btn", text: t("add_folder"), attrs: { type: "button" },
          on: { click: async () => { try { apply(await call("add_project")); render(); } catch { } } } })));
    for (const project of state.settings.projects) {
      card.append(el("div", { cls: "project" }, el("span", { cls: "mono", text: project }),
        el("button", { cls: "btn", text: t("remove"), attrs: { type: "button" },
          on: { click: async () => { try { apply(await call("remove_project", project)); render(); } catch { } } } })));
    }
    card.append(settingRow(t("settings_data"), state.dataDir,
      el("button", { cls: "btn", text: t("copy_path"), attrs: { type: "button" }, on: { click: () => copy(state.dataDir) } })));
    root.append(card, el("div", { cls: "note-box", text: t("settings_note") }), el("div", { cls: "note-box", text: t("settings_rescan") }));
    return root;
  }

  function render() {
    renderNav();
    renderHeader();
    const content = document.getElementById("content");
    const report = state.report;
    let view;
    if (state.view === "ledger") view = ledgerView();
    else if (state.view === "settings") view = settingsView();
    else if (!report) view = needScan();
    else if (state.view === "inventory") view = inventory(report);
    else if (state.view === "findings") view = findingsView(report);
    else if (state.view === "reports") view = reportsView();
    else view = overview(report);
    content.replaceChildren(view);
  }

  async function runScan() {
    busy(true, t("scanning"));
    try {
      state.report = await call("scan");
      toast(t("scan_done", { total: state.report.total }));
    } catch { } finally {
      busy(false);
      render();
    }
  }

  async function acceptChanges() {
    if (!window.confirm(t("accept_confirm"))) return;
    busy(true, t("scanning"));
    try {
      state.report = await call("accept_changes", true);
      toast(t("accepted"));
    } catch { } finally {
      busy(false);
      render();
    }
  }

  async function setLanguage(language) {
    try {
      apply(await call("set_language", language));
      render();
    } catch { }
  }

  function setMaximized(on) {
    windowState.maximized = on;
    document.documentElement.classList.toggle("maximized", on);
    document.getElementById("titlebar").classList.toggle("pywebview-drag-region", !on);
    renderHeader();
  }

  async function toggleMaximize() {
    try {
      if (windowState.maximized) {
        await call("window_place", ...windowState.saved);
        setMaximized(false);
        return;
      }
      windowState.saved = [window.screenX, window.screenY, window.outerWidth, window.outerHeight];
      await call("window_place", screen.availLeft || 0, screen.availTop || 0, screen.availWidth, screen.availHeight);
      setMaximized(true);
    } catch {
      return;
    }
  }

  function windowAction(action) {
    if (action === "maximize") {
      toggleMaximize();
      return;
    }
    call(action === "close" ? "window_close" : "window_minimize").catch(() => undefined);
  }

  function startResize(grip, event) {
    if (windowState.maximized) return;
    event.preventDefault();
    grip.setPointerCapture(event.pointerId);
    windowState.resizing = {
      edge: grip.dataset.edge, x: event.screenX, y: event.screenY, w: window.outerWidth, h: window.outerHeight,
    };
  }

  async function flushResize() {
    const resizing = windowState.resizing;
    const target = windowState.target;
    try {
      if (resizing && target) await window.pywebview.api.window_resize(target[0], target[1], resizing.edge);
    } catch {
      windowState.resizing = null;
    }
    windowState.pending = false;
  }

  function moveResize(event) {
    const resizing = windowState.resizing;
    if (!resizing) return;
    const dx = event.screenX - resizing.x;
    const dy = event.screenY - resizing.y;
    let width = resizing.w;
    let height = resizing.h;
    if (resizing.edge.includes("e")) width += dx;
    if (resizing.edge.includes("w")) width -= dx;
    if (resizing.edge.includes("s")) height += dy;
    if (resizing.edge.includes("n")) height -= dy;
    windowState.target = [Math.max(MIN_SIZE[0], Math.round(width)), Math.max(MIN_SIZE[1], Math.round(height))];
    if (windowState.pending) return;
    windowState.pending = true;
    requestAnimationFrame(flushResize);
  }

  async function endResize() {
    if (windowState.resizing && windowState.target) await flushResize();
    windowState.resizing = null;
    windowState.target = null;
  }

  function wireWindow() {
    for (const button of document.querySelectorAll("#winctl .wc")) {
      button.addEventListener("click", () => windowAction(button.dataset.win));
    }
    document.getElementById("titlebar").addEventListener("dblclick", (event) => {
      if (event.target.id === "titlebar") toggleMaximize();
    });
    for (const grip of document.querySelectorAll(".grip")) {
      grip.addEventListener("pointerdown", (event) => startResize(grip, event));
      grip.addEventListener("pointermove", moveResize);
      grip.addEventListener("pointerup", endResize);
      grip.addEventListener("pointercancel", endResize);
    }
  }

  async function start() {
    apply(await call("state"));
    wireWindow();
    document.getElementById("scan-button").addEventListener("click", runScan);
    for (const button of document.querySelectorAll(".lang button")) {
      button.addEventListener("click", () => setLanguage(button.dataset.lang));
    }
    render();
    await runScan();
  }

  if (window.pywebview && window.pywebview.api) start();
  else window.addEventListener("pywebviewready", start, { once: true });
})();
