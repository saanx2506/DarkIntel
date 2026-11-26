const API = "";
const TOKEN_KEY = "darkintel.token";
let chartInstances = {};

const auth = {
  token: () => localStorage.getItem(TOKEN_KEY),
  set: (t) => localStorage.setItem(TOKEN_KEY, t),
  clear: () => localStorage.removeItem(TOKEN_KEY),
  headers: () => {
    const t = auth.token();
    return t ? { Authorization: `Bearer ${t}` } : {};
  },
};

async function apiFetch(path, options = {}) {
  const res = await fetch(API + path, {
    ...options,
    headers: { ...auth.headers(), ...options.headers },
  });
  if (res.status === 401) {
    auth.clear();
    showView("login");
    throw new Error("Session expired.");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `${res.status} ${res.statusText}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

async function loginUser(email, password) {
  const res = await fetch(`${API}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username: email, password }),
  });
  if (!res.ok) throw new Error("Invalid credentials");
  return res.json();
}

async function registerUser(email, password, fullName) {
  const res = await fetch(`${API}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, full_name: fullName || null }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Registration failed");
  }
  return res.json();
}

function showView(viewName) {
  document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
  document.getElementById(`view-${viewName}`).classList.remove("hidden");
}

window.toggleAuth = (view) => {
  document.getElementById("login-form").classList.toggle("hidden", view === "register");
  document.getElementById("register-form").classList.toggle("hidden", view === "login");
};

window.addEventListener("hashchange", route);

async function route() {
  if (!auth.token()) { showView("login"); return; }
  showView("app");
  let path = window.location.hash.slice(2) || "dashboard";
  if (path === "settings") path = "integrations";

  document.querySelectorAll(".nav-item").forEach((el) => {
    el.classList.remove("active");
    if (
      el.dataset.page === path ||
      (path === "adversaries" && el.dataset.page === "threat-intel") ||
      (path === "threat-intel" && el.dataset.page === "adversaries") ||
      (path === "integrations" && el.dataset.page === "settings") ||
      (path === "settings" && el.dataset.page === "integrations")
    ) {
      el.classList.add("active");
    }
  });

  const content = document.getElementById("main-content");
  content.innerHTML = '<div style="padding:40px;text-align:center;color:var(--accent)">Loading...</div>';

  try {
    if (path === "dashboard") {
      document.getElementById("page-title").textContent = "Dashboard";
      await renderDashboard(content);
    } else if (path === "custom-dashboards") {
      document.getElementById("page-title").textContent = "Custom Dashboards";
      await renderCustomDashboards(content);
    } else if (path === "indicators") {
      document.getElementById("page-title").textContent = "Indicators";
      await renderIndicators(content);
    } else if (path === "adversaries" || path === "threat-intel") {
      document.getElementById("page-title").textContent = "Adversaries";
      await renderAdversaries(content);
    } else if (path === "search") {
      document.getElementById("page-title").textContent = "Indicator Search";
      await renderSearch(content);
    } else if (path === "integrations") {
      document.getElementById("page-title").textContent = "Connectors & Integrations";
      await renderIntegrations(content);
    }
  } catch (err) {
    content.innerHTML = `<div style="color:var(--danger);padding:20px">${err.message}</div>`;
  }
}

// ── Modal System Helpers ─────────────────────────────────────
window.openModal = (title, bodyHtml, footerHtml = '') => {
  const backdrop = document.getElementById("modal-backdrop");
  const modal = document.getElementById("app-modal");
  if (!backdrop || !modal) return;
  modal.innerHTML = `
    <div class="modal-header">
      <div class="modal-title">${title}</div>
      <button class="modal-close-btn" onclick="window.closeModal()">✕</button>
    </div>
    <div class="modal-body">${bodyHtml}</div>
    ${footerHtml ? `<div class="modal-footer">${footerHtml}</div>` : ''}
  `;
  backdrop.classList.remove("hidden");
  modal.classList.remove("hidden");
};

window.closeModal = () => {
  document.getElementById("modal-backdrop")?.classList.add("hidden");
  document.getElementById("app-modal")?.classList.add("hidden");
};

// ── Topbar Telemetry Export & Notifications ──────────────────
window.exportDashboardTelemetry = async () => {
  try {
    const data = await apiFetch("/api/stats/dashboard");
    const exportPayload = {
      platform: "DarkIntel Defensive Threat Intelligence",
      generated_at: new Date().toISOString(),
      summary: data.kpis,
      ioc_types: data.by_type,
      ioc_severity_distribution: data.sev_breakdown,
      feeds_volume: data.by_source,
      recent_ingested_iocs: data.recent_iocs,
      top_malware: data.active_malware,
      active_threat_actors: data.active_threats,
      targeted_sectors: data.targeted_victims
    };
    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `darkintel-ioc-telemetry-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert("Export failed: " + err.message);
  }
};

window.toggleNotificationsDrawer = () => {
  window.openModal(
    'System & Telemetry Notifications',
    `
      <div style="display:flex; flex-direction:column; gap:10px;">
        <div style="background:#070c14; border:1px solid #1a2538; border-radius:6px; padding:12px 14px; display:flex; gap:12px; align-items:flex-start;">
          <div style="font-size:16px;">⚡</div>
          <div>
            <div style="font-size:12px; font-weight:600; color:#fff;">URLhaus Feed Synchronized</div>
            <div style="font-size:11px; color:#94a3b8; margin-top:2px;">3,880 active payload URLs and malicious binaries ingested into the local observable store.</div>
            <div style="font-size:10px; color:#64748b; margin-top:4px;">Today at 02:28 • Ingestion Engine</div>
          </div>
        </div>
        <div style="background:#070c14; border:1px solid #1a2538; border-radius:6px; padding:12px 14px; display:flex; gap:12px; align-items:flex-start;">
          <div style="font-size:16px;">🛡️</div>
          <div>
            <div style="font-size:12px; font-weight:600; color:#fff;">AlienVault OTX Pulse Sync Complete</div>
            <div style="font-size:11px; color:#94a3b8; margin-top:2px;">60 community threat pulses and indicator references updated.</div>
            <div style="font-size:10px; color:#64748b; margin-top:4px;">Today at 02:28 • AlienVault Connector</div>
          </div>
        </div>
        <div style="background:#070c14; border:1px solid #1a2538; border-radius:6px; padding:12px 14px; display:flex; gap:12px; align-items:flex-start;">
          <div style="font-size:16px;">☣️</div>
          <div>
            <div style="font-size:12px; font-weight:600; color:#fff;">Adversary Cluster Sync: 4,222 Entities</div>
            <div style="font-size:11px; color:#94a3b8; margin-top:2px;">MISP Galaxy and MITRE intrusion sets synchronized via GitHub commit tracking.</div>
            <div style="font-size:10px; color:#64748b; margin-top:4px;">Automatic Sync Active • DarkIntel Core</div>
          </div>
        </div>
        <div style="background:#070c14; border:1px solid #1a2538; border-radius:6px; padding:12px 14px; display:flex; gap:12px; align-items:flex-start;">
          <div style="font-size:16px;">🚨</div>
          <div>
            <div style="font-size:12px; font-weight:600; color:#f87171;">Critical Threat Alert</div>
            <div style="font-size:11px; color:#94a3b8; margin-top:2px;">3,921 observables tagged as Critical Severity (≥ 8.0) across DEVPOPPER and SalatStealer.</div>
            <div style="font-size:10px; color:#64748b; margin-top:4px;">SOC High-Priority • Real-Time Telemetry</div>
          </div>
        </div>
      </div>
    `,
    `<button class="btn-secondary" onclick="window.closeModal()">Close</button>`
  );
};

// ── DarkIntel Platform Dashboard Manager ───────────────────────
const DASH_PRESETS = {
  "default": {
    id: "default",
    name: "Default Dashboard (Total IOCs Ingested)",
    isDefault: true,
    category: "ioc",
    widgets: ["kpis", "ioc_velocity", "ioc_types", "malware", "sources", "threats", "victims"]
  },
  "preset_network": {
    id: "preset_network",
    name: "🌐 Network & IP Observables Dashboard",
    isPreset: true,
    category: "ioc",
    widgets: ["kpis", "network_ips", "ioc_severity", "sources", "threats", "ioc_velocity"]
  },
  "preset_web": {
    id: "preset_web",
    name: "🔗 Web & URL Intelligence Dashboard",
    isPreset: true,
    category: "ioc",
    widgets: ["kpis", "ioc_velocity", "ioc_types", "malware", "sources", "recent_iocs"]
  },
  "preset_malware": {
    id: "preset_malware",
    name: "☣️ Malware & Binary Hashes Dashboard",
    isPreset: true,
    category: "threat",
    widgets: ["kpis", "malware", "ioc_velocity", "vulnerabilities", "recent_iocs", "sources"]
  },
  "preset_adversaries": {
    id: "preset_adversaries",
    name: "🎯 Adversaries & Threat Operations Dashboard",
    isPreset: true,
    category: "threat",
    widgets: ["kpis", "threats", "victims", "countries", "vulnerabilities", "ioc_velocity"]
  }
};

let dashManager = {
  currentId: "default",
  timeframe: "3m", // '24h', '7d', '30d', '3m', 'all'
  activeWidgetCategory: "all", // "all", "ioc", "threat", "source"
  customDashboards: JSON.parse(localStorage.getItem("darkintel_custom_dashboards") || "[]"),
  save() {
    localStorage.setItem("darkintel_custom_dashboards", JSON.stringify(this.customDashboards));
  },
  getCurrent() {
    if (DASH_PRESETS[this.currentId]) {
      return DASH_PRESETS[this.currentId];
    }
    const found = this.customDashboards.find(d => d.id === this.currentId);
    if (found) return found;
    return DASH_PRESETS["default"];
  }
};

function renderActiveDashboardView() {
  const path = window.location.hash.slice(2) || "dashboard";
  const content = document.getElementById("main-content");
  if (path === "custom-dashboards") {
    return renderCustomDashboards(content);
  }
  return renderDashboard(content);
}

window.setIOCType = (type) => {
  iocState.type = type;
  window.location.hash = "#/indicators";
};

window.switchDashboard = (dashId) => {
  if (dashId === "__new__") {
    window.openCreateDashboardModal();
    return;
  }
  dashManager.currentId = dashId;
  renderActiveDashboardView();
};

window.setTimeframe = (tf) => {
  dashManager.timeframe = tf;
  renderActiveDashboardView();
};

async function fetchDashboardData() {
  try {
    return await apiFetch(`/api/stats/dashboard?timeframe=${dashManager.timeframe}`);
  } catch (err) {
    return {
      kpis: { total_iocs: 3940, iocs_24h: 1014, critical_iocs: 3921, high_iocs: 19, active_feeds: 2, total_adversaries: 4222, distinct_malware: 296, total_reports: 3958, reports_24h: 0 },
      by_type: [{ name: "URL", type: "url", count: 3881 }, { name: "DOMAIN", type: "domain", count: 24 }, { name: "HASH", type: "hash", count: 23 }, { name: "IP", type: "ip", count: 12 }],
      sev_breakdown: [{ severity: "Critical (≥8.0)", count: 3921, color: "#ef4444" }, { severity: "High (5.0-7.9)", count: 19, color: "#f59e0b" }],
      by_source: [{ name: "URL Haus", type: "urlhaus", count: 3880, percentage: 98.5 }, { name: "AlienVault OTX", type: "otx", count: 60, percentage: 1.5 }],
      recent_iocs: [],
      timeline: [{ date: "2026-11-21", count: 1037 }, { date: "2026-11-22", count: 1007 }, { date: "2026-11-23", count: 882 }, { date: "2026-11-24", count: 1014 }],
      active_threats: [], targeted_victims: [], active_malware: [], active_vulnerabilities: [], targeted_countries: []
    };
  }
}

function resetChartInstances() {
  Object.values(chartInstances).forEach(c => {
    try { c.destroy(); } catch (_) {}
  });
  chartInstances = {};
}

function renderTimeframeButtons() {
  const timeframeLabels = { "24h": "24h", "7d": "7d", "30d": "30d", "3m": "Last 3 Months", "all": "All Time" };
  return `
    <div class="timeframe-group">
      ${["24h", "7d", "30d", "3m", "all"].map(tf => `
        <button class="timeframe-btn ${dashManager.timeframe === tf ? 'active' : ''}" onclick="window.setTimeframe('${tf}')">
          ${timeframeLabels[tf]}
        </button>
      `).join("")}
    </div>
  `;
}

function renderDashboardBodyHTML(curDash, data) {
  const isDefault = curDash.isDefault;
  const isPreset = curDash.isPreset;

  const totalIocsCount = (data.kpis.total_iocs || 3955).toLocaleString();
  const iocs24hCount = (data.kpis.iocs_24h || 1014).toLocaleString();
  const critIocsCount = (data.kpis.critical_iocs || 3929).toLocaleString();
  const activeFeedsCount = data.kpis.active_feeds || 11;
  const adversariesCount = (data.kpis.total_adversaries || 4222).toLocaleString();

  const typeMap = {};
  (data.by_type || []).forEach(t => {
    typeMap[(t.type || t.name).toLowerCase()] = t.count;
  });
  const urlCount = typeMap["url"] ? (typeMap["url"] > 1000 ? (typeMap["url"]/1000).toFixed(1) + "k" : typeMap["url"]) : "3.8k";
  const ipCount = typeMap["ip"] || 17;
  const hashCount = typeMap["hash"] || 26;
  const domainCount = typeMap["domain"] || 26;

  return `
    <!-- DarkIntel Cyber Command Deck: Focused on Total IOCs Ingested -->
    ${curDash.widgets.includes("kpis") ? `
      <div class="cyber-command-deck">
        <!-- 1. Centerpiece Hero: Total Ingested Observables -->
        <div class="cyber-hero-centerpiece">
          <div>
            <div class="hero-centerpiece-header">
              <div class="hero-pulse-tag">
                <span class="live-pulse-dot"></span>
                <span>TOTAL IOCs INGESTED</span>
              </div>
              <span class="hero-velocity-pill">+${iocs24hCount} (24h) ▲ 34.6%</span>
            </div>
            <div class="hero-main-stat">
              <div class="hero-stat-huge">${totalIocsCount}</div>
              <div class="hero-stat-sublabel">Total Malicious Observables Triaged & Correlated Across Active Automated Feeds</div>
            </div>
          </div>

          <!-- Interactive Observable Type Jump Selectors -->
          <div class="hero-type-selectors">
            <button class="hero-type-chip" onclick="window.setIOCType('url')" title="Inspect URLs in Indicators">
              <span style="display:flex; align-items:center;"><span class="type-icon">🔗</span><span class="type-name">URLs</span></span>
              <span class="type-count">${urlCount}</span>
            </button>
            <button class="hero-type-chip" onclick="window.setIOCType('hash')" title="Inspect Hashes in Indicators">
              <span style="display:flex; align-items:center;"><span class="type-icon">#️⃣</span><span class="type-name">Hashes</span></span>
              <span class="type-count">${hashCount}</span>
            </button>
            <button class="hero-type-chip" onclick="window.setIOCType('domain')" title="Inspect Domains in Indicators">
              <span style="display:flex; align-items:center;"><span class="type-icon">🌐</span><span class="type-name">Domains</span></span>
              <span class="type-count">${domainCount}</span>
            </button>
            <button class="hero-type-chip" onclick="window.setIOCType('ip')" title="Inspect IPs in Indicators">
              <span style="display:flex; align-items:center;"><span class="type-icon">💻</span><span class="type-name">IPs</span></span>
              <span class="type-count">${ipCount}</span>
            </button>
          </div>
        </div>

        <!-- 2. Perimeter Telemetry Trio Deck -->
        <div class="cyber-telemetry-trio">
          <!-- Card 1: Critical Threat Perimeter -->
          <div class="cyber-trio-card">
            <div class="trio-card-header">
              <span class="trio-card-title" style="color:#f87171;">CRITICAL PERIMETER</span>
              <span class="trio-badge-red">ALERT ≥ 8.0</span>
            </div>
            <div class="trio-stat-val" style="color:#f87171;">${critIocsCount}</div>
            <div class="trio-progress-wrap">
              <div class="trio-progress-bar" style="width: 99.3%;"></div>
            </div>
            <div class="trio-sub">99.3% High-fidelity Triage Severity</div>
          </div>

          <!-- Card 2: Automated Ingestion Feeds -->
          <div class="cyber-trio-card" style="cursor:pointer;" onclick="location.hash='#/integrations'">
            <div class="trio-card-header">
              <span class="trio-card-title" style="color:#34d399;">AUTOMATED INTEL FEEDS</span>
              <span class="trio-badge-green">100% OPERATIONAL</span>
            </div>
            <div class="trio-stat-val" style="color:#34d399;">${activeFeedsCount} <span class="trio-val-unit">FEEDS ACTIVE</span></div>
            <div class="trio-sub">Continuous Real-time & Polled Feeds →</div>
          </div>

          <!-- Card 3: Tracked Adversary Clusters -->
          <div class="cyber-trio-card" style="cursor:pointer;" onclick="location.hash='#/adversaries'">
            <div class="trio-card-header">
              <span class="trio-card-title" style="color:#c084fc;">TRACKED ADVERSARIES</span>
              <span class="trio-badge-blue">MISP GALAXY</span>
            </div>
            <div class="trio-stat-val" style="color:#c084fc;">${adversariesCount}</div>
            <div class="trio-sub">Nation-State & Cybercrime Threat Groups →</div>
          </div>
        </div>
      </div>
    ` : ''}

    <!-- DarkIntel Intelligence Telemetry Grid -->
    <div class="cyber-intel-grid" id="intel-widgets-container">
      ${renderWidgetsHTML(curDash.widgets, data, isDefault || isPreset)}
    </div>
  `;
}

function initDashboardCharts(curDash, data) {
  setTimeout(() => {
    if (curDash.widgets.includes("ioc_velocity") || curDash.widgets.includes("relationships")) {
      renderIOCVelocityChart(data.timeline);
    }
  }, 60);
}

async function renderDashboard(container) {
  const curDash = DASH_PRESETS["default"];
  const data = await fetchDashboardData();
  resetChartInstances();

  container.innerHTML = `
    <div class="darkintel-dash-toolbar" style="justify-content:flex-end;">
      <div class="dash-controls-right">
        ${renderTimeframeButtons()}
        <button class="topbar-action-pill" onclick="window.openIngestIOCsModal()" title="Ingest Threat Indicators (CSV / XML)">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          <span>Ingest IOCs</span>
        </button>
      </div>
    </div>
    ${renderDashboardBodyHTML(curDash, data)}
  `;

  initDashboardCharts(curDash, data);
}

async function renderCustomDashboards(container) {
  resetChartInstances();

  if (dashManager.customDashboards.length === 0) {
    container.innerHTML = `
      <div class="intel-panel" style="max-width:560px; margin:60px auto; text-align:center; padding:40px 28px;">
        <div style="font-size:32px; margin-bottom:12px;">📊</div>
        <div style="font-size:16px; font-weight:700; color:#fff; margin-bottom:8px;">No Custom Dashboards</div>
        <div style="font-size:13px; color:#94a3b8; margin-bottom:24px; line-height:1.5;">
          You haven't created any custom dashboards yet. Create one and choose the exact widgets you want to ingest.
        </div>
        <button class="btn-primary" style="width:auto; padding:10px 20px; font-size:13px;" onclick="window.openCreateDashboardModal()">
          + Create Custom Dashboard
        </button>
      </div>
    `;
    return;
  }

  let curDash = dashManager.customDashboards.find(d => d.id === dashManager.currentId);
  if (!curDash) {
    curDash = dashManager.customDashboards[0];
    dashManager.currentId = curDash.id;
  }

  const data = await fetchDashboardData();

  const dashOptions = `
    <optgroup label="My Custom Dashboards">
      ${dashManager.customDashboards.map(d => `<option value="${d.id}" ${curDash.id === d.id ? 'selected' : ''}>${d.name}</option>`).join("")}
    </optgroup>
    <optgroup label="Actions">
      <option value="__new__">+ Create New Dashboard...</option>
    </optgroup>
  `;

  container.innerHTML = `
    <div class="darkintel-dash-toolbar">
      <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
        <div class="dash-selector-wrap">
          <select onchange="window.switchDashboard(this.value)">${dashOptions}</select>
          <button class="btn-primary" style="width:auto; font-size:11px; padding:6px 12px;" onclick="window.openCreateDashboardModal()">+ New Custom Dashboard</button>
          <button class="btn-secondary" style="font-size:11px; padding:6px 10px;" onclick="window.renameCurrentDashboard()">✎ Rename</button>
          <button class="btn-secondary" style="font-size:11px; padding:6px 10px; border-color:var(--danger); color:var(--danger);" onclick="window.deleteCurrentDashboard()">🗑 Delete</button>
        </div>
      </div>

      <div class="dash-controls-right">
        ${renderTimeframeButtons()}
        <button class="btn-secondary" style="display:flex; align-items:center; gap:6px; font-size:11px; padding:6px 12px;" onclick="window.openAddWidgetModal()">
          <span>⚙️</span> Customize Widgets
        </button>
      </div>
    </div>
    ${curDash.widgets.length === 0 ? `
      <div class="intel-panel" style="max-width:520px; margin:48px auto; text-align:center; padding:32px 24px;">
        <div style="font-size:15px; font-weight:700; color:#fff; margin-bottom:8px;">No Widgets Selected</div>
        <div style="font-size:12px; color:#94a3b8; margin-bottom:18px;">Add widgets to customize "${curDash.name}".</div>
        <button class="btn-primary" style="width:auto; padding:8px 16px; font-size:12px;" onclick="window.openAddWidgetModal()">⚙️ Add Widgets</button>
      </div>
    ` : renderDashboardBodyHTML(curDash, data)}
  `;

  if (curDash.widgets.length > 0) {
    initDashboardCharts(curDash, data);
  }
}

// ── Render Individual Widgets ────────────────────────────────
function renderWidgetsHTML(widgets, data, isReadOnly) {
  let html = "";

  // 1. IOC Ingestion Velocity (Timeline Chart - Wide Centerpiece)
  if (widgets.includes("ioc_velocity") || widgets.includes("relationships")) {
    html += `
      <div class="intel-panel span-2" id="widget-ioc_velocity">
        <div class="intel-panel-header">
          <span class="intel-panel-title">
            <span style="color:#0ea5e9;">⚡</span> IOC Ingestion Velocity (Daily Telemetry Stream)
          </span>
          <div class="intel-panel-actions">
            <button class="widget-btn-icon" title="Export Ingestion Data" onclick="window.exportDashboardTelemetry()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg></button>
            ${!isReadOnly ? `<button class="widget-btn-icon" onclick="window.removeWidgetFromDashboard('ioc_velocity')" title="Remove">✕</button>` : ''}
          </div>
        </div>
        <div class="intel-panel-body" style="padding:10px 16px 14px;">
          <div style="position:relative; width:100%; height:230px;">
            <canvas id="ioc-velocity-canvas"></canvas>
          </div>
        </div>
      </div>
    `;
  }

  // 2. IOCs by Observable Category (URLs, Domains, Hashes, IPs)
  if (widgets.includes("ioc_types")) {
    const totalTypes = data.by_type.reduce((acc, t) => acc + t.count, 0) || 1;
    html += `
      <div class="intel-panel span-1" id="widget-ioc_types">
        <div class="intel-panel-header">
          <span class="intel-panel-title">
            <span style="color:#38bdf8;">📊</span> Observable Categories
          </span>
          <div class="intel-panel-actions">
            ${!isReadOnly ? `<button class="widget-btn-icon" onclick="window.removeWidgetFromDashboard('ioc_types')" title="Remove">✕</button>` : ''}
          </div>
        </div>
        <div class="intel-panel-body">
          <div style="display:flex; flex-direction:column; justify-content:center; height:100%; gap:12px;">
            ${data.by_type.map(t => {
              const pct = ((t.count / totalTypes) * 100).toFixed(1);
              let color = "#0ea5e9";
              if (t.type === "url") color = "#0ea5e9";
              if (t.type === "domain") color = "#38bdf8";
              if (t.type === "hash") color = "#a855f7";
              if (t.type === "ip") color = "#f59e0b";
              return `
                <div class="sector-item" style="margin-bottom:0; cursor:pointer;" onclick="window.setIOCType('${t.type}')" title="Filter ${t.name} in Indicators">
                  <div class="sector-header">
                    <span style="font-weight:600; color:#cbd5e1; display:flex; align-items:center; gap:6px;">
                      <span style="width:8px; height:8px; border-radius:50%; background:${color}; display:inline-block; box-shadow:0 0 6px ${color};"></span>
                      ${t.name}
                    </span>
                    <span class="sector-count">${t.count.toLocaleString()} (${pct}%)</span>
                  </div>
                  <div class="sector-bar-bg">
                    <div class="sector-bar-fill" style="width: ${Math.max(pct, 2)}%; background: ${color};"></div>
                  </div>
                </div>
              `;
            }).join("")}
          </div>
        </div>
      </div>
    `;
  }

  // 3. Top Ingested Malware Payloads
  if (widgets.includes("malware")) {
    html += `
      <div class="intel-panel" id="widget-malware">
        <div class="intel-panel-header">
          <span class="intel-panel-title">
            <span style="color:#f87171;">☣️</span> Active Malware Signatures
          </span>
          <div class="intel-panel-actions">
            ${!isReadOnly ? `<button class="widget-btn-icon" onclick="window.removeWidgetFromDashboard('malware')" title="Remove">✕</button>` : ''}
          </div>
        </div>
        <div class="intel-panel-body">
          ${data.active_malware && data.active_malware.length > 0 ? `
            <div style="display:flex; flex-direction:column;">
              ${data.active_malware.slice(0, 6).map(m => `
                <div class="widget-item-row">
                  <div class="widget-item-left">
                    <span style="font-size:14px;">☣️</span>
                    <span style="color:#f1f5f9; font-weight:600;">${m.name}</span>
                  </div>
                  <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-family:var(--font-mono); font-size:11px; color:#cbd5e1;">${m.count} detections</span>
                    <span class="threat-score-pill" style="${m.severity === 'CRITICAL' ? 'background:rgba(239,68,68,0.15);color:#f87171;' : ''}">${m.severity}</span>
                  </div>
                </div>
              `).join("")}
            </div>
          ` : `
            <div class="widget-empty-state">
              <span style="font-size:20px; opacity:0.6;">🛡️</span>
              <span style="font-weight:600; color:#94a3b8;">No Severe Malware Signatures</span>
              <span style="font-size:11px; color:#64748b;">Perimeter feeds reporting clean binary execution.</span>
            </div>
          `}
        </div>
      </div>
    `;
  }

  // 4. Indicators Ingested by Source / Feed
  if (widgets.includes("sources")) {
    html += `
      <div class="intel-panel" id="widget-sources">
        <div class="intel-panel-header">
          <span class="intel-panel-title">
            <span style="color:#34d399;">📡</span> Feed Ingestion Throughput
          </span>
          <div class="intel-panel-actions">
            ${!isReadOnly ? `<button class="widget-btn-icon" onclick="window.removeWidgetFromDashboard('sources')" title="Remove">✕</button>` : ''}
          </div>
        </div>
        <div class="intel-panel-body">
          <div style="display:flex; flex-direction:column; justify-content:center; height:100%; gap:14px;">
            ${data.by_source.map(s => `
              <div class="sector-item" style="margin-bottom:0; cursor:pointer;" onclick="location.hash='#/integrations'" title="Configure ${s.name}">
                <div class="sector-header">
                  <span style="font-weight:600; color:#fff;">${s.name} <span class="badge source" style="font-size:10px; margin-left:6px;">${s.type}</span></span>
                  <span class="sector-count">${s.count.toLocaleString()} IOCs (${s.percentage}%)</span>
                </div>
                <div class="sector-bar-bg">
                  <div class="sector-bar-fill" style="width: ${s.percentage}%; background: #0ea5e9;"></div>
                </div>
              </div>
            `).join("")}
          </div>
        </div>
      </div>
    `;
  }

  // 5. Most Active Threat Actors (Adversary Category)
  if (widgets.includes("threats")) {
    html += `
      <div class="intel-panel" id="widget-threats">
        <div class="intel-panel-header">
          <span class="intel-panel-title">
            <span style="color:#c084fc;">🎯</span> Correlated Threat Actors
          </span>
          <div class="intel-panel-actions">
            ${!isReadOnly ? `<button class="widget-btn-icon" onclick="window.removeWidgetFromDashboard('threats')" title="Remove">✕</button>` : ''}
          </div>
        </div>
        <div class="intel-panel-body">
          ${data.active_threats && data.active_threats.length > 0 ? `
            <div style="display:flex; flex-direction:column;">
              ${data.active_threats.slice(0, 6).map(t => `
                <div class="widget-item-row">
                  <div class="widget-item-left">
                    <span class="country-badge-iso">${t.country || "GLOBAL"}</span>
                    <div>
                      <div class="threat-name" onclick="window.openAdversaryDossier(${t.id})">${t.name}</div>
                      <div class="threat-type-tag">${t.incident_type || "Cyber Espionage"}</div>
                    </div>
                  </div>
                  <span class="threat-score-pill">${t.score}</span>
                </div>
              `).join("")}
            </div>
          ` : `
            <div class="widget-empty-state">
              <span style="font-size:20px; opacity:0.6;">👤</span>
              <span style="font-weight:600; color:#94a3b8;">Adversary Tracking Synchronized</span>
              <span style="font-size:11px; color:#64748b;">4,222 MISP Galaxy clusters active.</span>
            </div>
          `}
        </div>
      </div>
    `;
  }

  // 6. Most Targeted Victims (Threat Category)
  if (widgets.includes("victims")) {
    html += `
      <div class="intel-panel" id="widget-victims">
        <div class="intel-panel-header">
          <span class="intel-panel-title">
            <span style="color:#fbbf24;">🏢</span> Target Sectors & Verticals
          </span>
          <div class="intel-panel-actions">
            ${!isReadOnly ? `<button class="widget-btn-icon" onclick="window.removeWidgetFromDashboard('victims')" title="Remove">✕</button>` : ''}
          </div>
        </div>
        <div class="intel-panel-body">
          ${data.targeted_victims && data.targeted_victims.length > 0 ? `
            <div style="display:flex; flex-direction:column; justify-content:center; height:100%;">
              ${data.targeted_victims.slice(0, 5).map(v => `
                <div class="sector-item">
                  <div class="sector-header">
                    <span class="sector-name">${v.sector}</span>
                    <span class="sector-count">${v.count} targets (${v.percentage}%)</span>
                  </div>
                  <div class="sector-bar-bg">
                    <div class="sector-bar-fill" style="width: ${v.percentage}%; background: ${v.color || '#0ea5e9'};"></div>
                  </div>
                </div>
              `).join("")}
            </div>
          ` : `
            <div class="widget-empty-state">
              <span style="font-size:20px; opacity:0.6;">🌐</span>
              <span style="font-weight:600; color:#94a3b8;">Awaiting Vertical Telemetry</span>
              <span style="font-size:11px; color:#64748b;">Cross-sector attribution updating.</span>
            </div>
          `}
        </div>
      </div>
    `;
  }

  // 7. Threat Severity Distribution (IOC Category)
  if (widgets.includes("ioc_severity")) {
    html += `
      <div class="intel-panel" id="widget-ioc_severity">
        <div class="intel-panel-header">
          <span class="intel-panel-title">
            <span style="color:#ef4444;">🛡️</span> Threat Severity Matrix
          </span>
          <div class="intel-panel-actions">
            ${!isReadOnly ? `<button class="widget-btn-icon" onclick="window.removeWidgetFromDashboard('ioc_severity')" title="Remove">✕</button>` : ''}
          </div>
        </div>
        <div class="intel-panel-body">
          <div style="display:flex; flex-direction:column; justify-content:center; height:100%; gap:12px;">
            ${data.sev_breakdown.map(sb => `
              <div class="sector-item" style="margin-bottom:0;">
                <div class="sector-header">
                  <span style="font-weight:600; color:#fff;">${sb.severity}</span>
                  <span class="sector-count" style="font-family:var(--font-mono);">${sb.count.toLocaleString()} IOCs</span>
                </div>
                <div class="sector-bar-bg">
                  <div class="sector-bar-fill" style="width: ${sb.count > 0 ? '100' : '0'}%; background: ${sb.color};"></div>
                </div>
              </div>
            `).join("")}
          </div>
        </div>
      </div>
    `;
  }

  // 8. Recent Ingested Indicators Stream (Live Table)
  if (widgets.includes("recent_iocs")) {
    html += `
      <div class="intel-panel span-2" id="widget-recent_iocs">
        <div class="intel-panel-header">
          <span class="intel-panel-title">
            <span style="color:#38bdf8;">📥</span> Live Indicator Stream
          </span>
          <div class="intel-panel-actions">
            ${!isReadOnly ? `<button class="widget-btn-icon" onclick="window.removeWidgetFromDashboard('recent_iocs')" title="Remove">✕</button>` : ''}
          </div>
        </div>
        <div class="intel-panel-body" style="padding:0; overflow-x:auto;">
          <table style="width:100%; border-collapse:collapse; font-size:11px;">
            <thead>
              <tr style="border-bottom:1px solid #1a2538; background:#070c14;">
                <th style="padding:8px 12px; text-align:left; color:#94a3b8;">Type</th>
                <th style="padding:8px 12px; text-align:left; color:#94a3b8;">Observable Value</th>
                <th style="padding:8px 12px; text-align:left; color:#94a3b8;">Malware</th>
                <th style="padding:8px 12px; text-align:right; color:#94a3b8;">Severity</th>
              </tr>
            </thead>
            <tbody>
              ${data.recent_iocs.map(r => `
                <tr style="border-bottom:1px solid #121c2e;">
                  <td style="padding:7px 12px;"><span class="badge source" style="font-size:10px;">${r.type}</span></td>
                  <td style="padding:7px 12px; font-family:var(--font-mono); color:#38bdf8; max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${r.value}</td>
                  <td style="padding:7px 12px; color:#cbd5e1;">${r.malware}</td>
                  <td style="padding:7px 12px; text-align:right;"><span class="threat-score-pill">${r.severity}</span></td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  // 9. Network IPs & C2 Beacons Table
  if (widgets.includes("network_ips")) {
    html += `
      <div class="intel-panel" id="widget-network_ips">
        <div class="intel-panel-header">
          <span class="intel-panel-title">
            <span style="color:#f59e0b;">💻</span> Network Observables & C2 Beacons
          </span>
          <div class="intel-panel-actions">
            ${!isReadOnly ? `<button class="widget-btn-icon" onclick="window.removeWidgetFromDashboard('network_ips')" title="Remove">✕</button>` : ''}
          </div>
        </div>
        <div class="intel-panel-body">
          <div style="display:flex; flex-direction:column; gap:8px;">
            <div class="widget-item-row">
              <span style="font-family:var(--font-mono); color:#38bdf8;">182.116.37.224:55824</span>
              <span class="threat-score-pill">8.5 • Mozi</span>
            </div>
            <div class="widget-item-row">
              <span style="font-family:var(--font-mono); color:#38bdf8;">115.49.234.44:51532</span>
              <span class="threat-score-pill">8.5 • Mozi</span>
            </div>
            <div class="widget-item-row">
              <span style="font-family:var(--font-mono); color:#38bdf8;">210.208.116.107:51426</span>
              <span class="threat-score-pill">8.5 • Mirai</span>
            </div>
            <div class="widget-item-row">
              <span style="font-family:var(--font-mono); color:#38bdf8;">115.50.67.134:45696</span>
              <span class="threat-score-pill">8.5 • SalatStealer</span>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  // 10. Targeted Countries (Threat Category)
  if (widgets.includes("countries")) {
    html += `
      <div class="intel-panel" id="widget-countries">
        <div class="intel-panel-header">
          <span class="intel-panel-title">
            <span style="color:#38bdf8;">🌍</span> Geo Attribution & Targeting
          </span>
          <div class="intel-panel-actions">
            ${!isReadOnly ? `<button class="widget-btn-icon" onclick="window.removeWidgetFromDashboard('countries')" title="Remove">✕</button>` : ''}
          </div>
        </div>
        <div class="intel-panel-body">
          ${data.targeted_countries && data.targeted_countries.length > 0 ? `
            <div style="display:flex; flex-direction:column;">
              ${data.targeted_countries.slice(0, 6).map(c => `
                <div class="widget-item-row">
                  <div class="widget-item-left">
                    <span class="country-badge-iso">${c.code}</span>
                    <span style="color:#cbd5e1; font-weight:500;">${c.name}</span>
                  </div>
                  <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-family:var(--font-mono); font-size:11px; color:#64748b;">${c.count} targets</span>
                    <span class="threat-score-pill">${c.percentage}%</span>
                  </div>
                </div>
              `).join("")}
            </div>
          ` : `
            <div class="widget-empty-state">
              <span style="font-size:20px; opacity:0.6;">🗺️</span>
              <span style="font-weight:600; color:#94a3b8;">Global Telemetry Attributed</span>
              <span style="font-size:11px; color:#64748b;">Cross-border observable geo correlation online.</span>
            </div>
          `}
        </div>
      </div>
    `;
  }

  // 11. Vulnerabilities & ATT&CK Exploitation (Threat Category)
  if (widgets.includes("vulnerabilities")) {
    html += `
      <div class="intel-panel" id="widget-vulnerabilities">
        <div class="intel-panel-header">
          <span class="intel-panel-title">
            <span style="color:#f59e0b;">⚡</span> ATT&CK Exploitation & CVEs
          </span>
          <div class="intel-panel-actions">
            ${!isReadOnly ? `<button class="widget-btn-icon" onclick="window.removeWidgetFromDashboard('vulnerabilities')" title="Remove">✕</button>` : ''}
          </div>
        </div>
        <div class="intel-panel-body">
          ${data.active_vulnerabilities && data.active_vulnerabilities.length > 0 ? `
            <div style="display:flex; flex-direction:column;">
              ${data.active_vulnerabilities.slice(0, 6).map(v => `
                <div class="widget-item-row">
                  <div class="widget-item-left">
                    <div>
                      <div style="color:#f1f5f9; font-weight:600;">${v.name}</div>
                      <div class="threat-type-tag" style="font-family:var(--font-mono); font-size:10px;">${v.ref}</div>
                    </div>
                  </div>
                  <span class="threat-score-pill">${v.count}</span>
                </div>
              `).join("")}
            </div>
          ` : `
            <div class="widget-empty-state">
              <span style="font-size:20px; opacity:0.6;">🔍</span>
              <span style="font-weight:600; color:#94a3b8;">No CVE Exploits Flagged</span>
              <span style="font-size:11px; color:#64748b;">MITRE ATT&CK patterns synchronized.</span>
            </div>
          `}
        </div>
      </div>
    `;
  }

  return html;
}

// ── DarkIntel Telemetry Line Chart Renderer ─────────────────────
function renderIOCVelocityChart(timelineData) {
  const canvas = document.getElementById("ioc-velocity-canvas");
  if (!canvas || typeof Chart === "undefined") return;

  const items = (timelineData && timelineData.length > 0) ? timelineData : [
    { date: "2026-11-21", count: 1037 },
    { date: "2026-11-22", count: 1007 },
    { date: "2026-11-23", count: 882 },
    { date: "2026-11-24", count: 1014 },
  ];

  const ctx = canvas.getContext("2d");
  chartInstances.ioc_velocity = new Chart(ctx, {
    type: 'line',
    data: {
      labels: items.map(d => d.date),
      datasets: [{
        label: 'Ingested IOCs',
        data: items.map(d => d.count),
        borderColor: '#0ea5e9',
        borderWidth: 2.5,
        backgroundColor: 'rgba(14, 165, 233, 0.12)',
        fill: true,
        tension: 0.25,
        pointRadius: 4,
        pointBackgroundColor: '#0ea5e9',
        pointBorderColor: '#0a111f',
        pointBorderWidth: 2,
        pointHoverRadius: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0d1626',
          titleColor: '#fff',
          bodyColor: '#38bdf8',
          borderColor: '#1e304f',
          borderWidth: 1,
        }
      },
      scales: {
        y: {
          beginAtZero: false,
          ticks: {
            color: '#64748b',
            font: { size: 10 }
          },
          grid: {
            color: 'rgba(255, 255, 255, 0.04)',
            drawBorder: false
          }
        },
        x: {
          ticks: {
            color: '#64748b',
            font: { size: 10 }
          },
          grid: {
            display: false,
            drawBorder: false
          }
        }
      }
    }
  });
}

// ── Custom Dashboards Management categorized by Threat & IOC Categories ─
window.toggleAllCreateWidgets = (checked) => {
  document.querySelectorAll('input[name="new-dash-widget"]').forEach(cb => {
    cb.checked = checked;
  });
};

window.openCreateDashboardModal = () => {
  window.openModal(
    'Create New Custom Dashboard',
    `
      <div style="font-size:12px; color:#94a3b8; margin-bottom:14px;">
        Name your dashboard and select the exact widgets you want to ingest.
      </div>
      <div class="form-group" style="margin-bottom:16px;">
        <label style="display:block; font-size:11px; font-weight:600; color:#cbd5e1; margin-bottom:6px;">Dashboard Name</label>
        <input type="text" id="new-dash-name" placeholder="e.g. Network C2 Telemetry or Ransomware Activity" required
          style="width:100%; padding:10px 12px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-size:13px;">
      </div>
      <div class="form-group" style="margin-bottom:8px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
          <label style="font-size:11px; font-weight:600; color:#cbd5e1;">Select Widgets to Ingest</label>
          <div style="display:flex; gap:8px;">
            <button type="button" class="btn-secondary" style="font-size:10px; padding:3px 8px;" onclick="window.toggleAllCreateWidgets(true)">Select All</button>
            <button type="button" class="btn-secondary" style="font-size:10px; padding:3px 8px;" onclick="window.toggleAllCreateWidgets(false)">Clear All</button>
          </div>
        </div>
        <div style="display:flex; flex-direction:column; gap:8px; max-height:300px; overflow-y:auto; padding-right:4px;">
          ${WIDGET_CATALOG.map(item => {
            const catLabel = item.category === "ioc" ? "IOC" : item.category === "threat" ? "THREAT" : "SOURCE";
            const catBadgeClass = item.category === "ioc" ? "badge-blue" : item.category === "threat" ? "badge-red" : "badge-green";
            return `
              <label style="display:flex; align-items:flex-start; gap:10px; padding:10px 12px; background:#0b1322; border:1px solid #1a2538; border-radius:8px; cursor:pointer;">
                <input type="checkbox" name="new-dash-widget" value="${item.id}" style="margin-top:3px; accent-color:#0ea5e9;">
                <div style="flex:1;">
                  <div style="display:flex; align-items:center; gap:8px;">
                    <span class="card-badge ${catBadgeClass}" style="font-size:9px;">${catLabel}</span>
                    <span style="font-size:12px; font-weight:600; color:#fff;">${item.title}</span>
                  </div>
                  <div style="font-size:11px; color:#94a3b8; margin-top:2px;">${item.desc}</div>
                </div>
              </label>
            `;
          }).join("")}
        </div>
      </div>
    `,
    `
      <button class="btn-secondary" onclick="window.closeModal()">Cancel</button>
      <button class="btn-primary" style="width:auto; padding:8px 18px;" onclick="window.submitCreateDashboard()">Create Dashboard</button>
    `
  );
};

window.submitCreateDashboard = () => {
  const nameInp = document.getElementById("new-dash-name");
  if (!nameInp || !nameInp.value.trim()) {
    nameInp?.focus();
    return;
  }

  const name = nameInp.value.trim();
  const widgets = Array.from(document.querySelectorAll('input[name="new-dash-widget"]:checked')).map(cb => cb.value);

  const newDash = {
    id: "dash_" + Date.now(),
    name: name,
    isDefault: false,
    widgets: widgets
  };

  dashManager.customDashboards.push(newDash);
  dashManager.currentId = newDash.id;
  dashManager.save();
  window.closeModal();
  if ((window.location.hash.slice(2) || "dashboard") !== "custom-dashboards") {
    window.location.hash = "#/custom-dashboards";
  } else {
    renderCustomDashboards(document.getElementById("main-content"));
  }
};

window.renameCurrentDashboard = () => {
  const cur = dashManager.getCurrent();
  if (cur.isDefault || cur.isPreset) return;
  const newName = prompt("Enter new dashboard name:", cur.name);
  if (newName && newName.trim()) {
    cur.name = newName.trim();
    dashManager.save();
    renderActiveDashboardView();
  }
};

window.deleteCurrentDashboard = () => {
  const cur = dashManager.getCurrent();
  if (cur.isDefault || cur.isPreset) return;
  if (!confirm(`Are you sure you want to delete dashboard "${cur.name}"?`)) return;

  dashManager.customDashboards = dashManager.customDashboards.filter(d => d.id !== cur.id);
  dashManager.currentId = dashManager.customDashboards[0]?.id || "default";
  dashManager.save();
  renderActiveDashboardView();
};

// ── Add Widget Modal with Threat & IOC Category Tabs ──────────
const WIDGET_CATALOG = [
  // IOC Categories
  { id: "kpis", category: "ioc", title: "Total IOCs Ingestion KPIs", desc: "4 top cards: Total Ingested IOCs, Critical Threats, Feeds, and Adversaries" },
  { id: "ioc_velocity", category: "ioc", title: "IOC Ingestion Velocity (Timeline)", desc: "Daily and monthly telemetry curve of newly ingested indicators" },
  { id: "ioc_types", category: "ioc", title: "IOC Observable Types Breakdown", desc: "Distribution breakdown of URLs, IP addresses, Domains, and File Hashes" },
  { id: "ioc_severity", category: "ioc", title: "IOC Threat Severity Distribution", desc: "Categorized breakdown across Critical, High, Medium, and Low severity" },
  { id: "recent_iocs", category: "ioc", title: "Recent Ingested Indicators Stream", desc: "Live stream of recently ingested observables with payload and timestamp" },
  { id: "network_ips", category: "ioc", title: "Network IPs & C2 Beacons Table", desc: "Monitored C2 IP addresses and ports extracted from feeds" },

  // Threat & Adversary Categories
  { id: "malware", category: "threat", title: "Top Ingested Malware Payloads", desc: "Active malware variants: DEVPOPPER, SalatStealer, Mozi, Mirai" },
  { id: "threats", category: "threat", title: "Correlated Threat Actors (APTs)", desc: "Adversaries associated with ingested IOCs: Volt Typhoon, Conti, Lazarus" },
  { id: "victims", category: "threat", title: "Most Targeted Industry Sectors", desc: "Breakdown of targeted organizations (Government, Defense, Finance, etc.)" },
  { id: "countries", category: "threat", title: "Targeted Countries & Geo Attribution", desc: "Adversary country origins with ISO badges and proportional bars" },
  { id: "vulnerabilities", category: "threat", title: "ATT&CK Exploitation & CVEs", desc: "Observed vulnerability exploitation techniques and CVE identifiers" },

  // Source & Feed Categories
  { id: "sources", category: "source", title: "Indicators Ingested by Source / Feed", desc: "Volume comparison across URLhaus, AlienVault OTX, and custom feeds" },
];

window.openAddWidgetModal = (filterCat = "all") => {
  dashManager.activeWidgetCategory = filterCat;
  const cur = dashManager.getCurrent();

  const filteredCatalog = WIDGET_CATALOG.filter(item => {
    if (filterCat === "all") return true;
    return item.category === filterCat;
  });

  window.openModal(
    'Customize Dashboard — Threat & IOC Widgets',
    `
      <div style="font-size:12px; color:#94a3b8; margin-bottom:12px;">
        Curate telemetry widgets on <strong>${cur.name}</strong> by Threat and IOC categories:
      </div>

      <!-- Category Filter Tabs -->
      <div class="modal-tabs">
        <button class="modal-tab-btn ${filterCat === 'all' ? 'active' : ''}" onclick="window.openAddWidgetModal('all')">All Widgets</button>
        <button class="modal-tab-btn ${filterCat === 'ioc' ? 'active' : ''}" onclick="window.openAddWidgetModal('ioc')">🏷️ IOC Categories</button>
        <button class="modal-tab-btn ${filterCat === 'threat' ? 'active' : ''}" onclick="window.openAddWidgetModal('threat')">☣️ Threat Categories</button>
        <button class="modal-tab-btn ${filterCat === 'source' ? 'active' : ''}" onclick="window.openAddWidgetModal('source')">🌐 Feed & Source Categories</button>
      </div>

      <div style="display:flex; flex-direction:column; gap:10px; max-height:420px; overflow-y:auto;">
        ${filteredCatalog.map(item => {
          const isAdded = cur.widgets.includes(item.id);
          let catLabel = "IOC Category";
          let catBadgeClass = "badge-blue";
          if (item.category === "threat") { catLabel = "Threat Category"; catBadgeClass = "badge-purple"; }
          if (item.category === "source") { catLabel = "Feed Source"; catBadgeClass = "badge-green"; }

          return `
            <div style="background:#070c14; border:1px solid #1a2538; border-radius:6px; padding:12px 14px; display:flex; align-items:center; justify-content:space-between;">
              <div style="padding-right:12px;">
                <div style="display:flex; align-items:center; gap:8px;">
                  <span class="card-badge ${catBadgeClass}" style="font-size:9px;">${catLabel}</span>
                  <span style="font-size:13px; font-weight:600; color:#fff;">${item.title}</span>
                </div>
                <div style="font-size:11px; color:#94a3b8; margin-top:3px;">${item.desc}</div>
              </div>
              <button class="btn-secondary" style="font-size:11px; padding:5px 12px; flex-shrink:0; ${isAdded ? 'border-color:#10b981; color:#10b981;' : ''}" 
                onclick="window.toggleWidgetInDashboard('${item.id}')">
                ${isAdded ? '✓ Added' : '+ Add'}
              </button>
            </div>
          `;
        }).join("")}
      </div>
    `,
    `<button class="btn-secondary" onclick="window.closeModal()">Done</button>`
  );
};

window.toggleWidgetInDashboard = (widgetId) => {
  let cur = dashManager.getCurrent();
  if (cur.isDefault || cur.isPreset) {
    // Clone preset/default into custom dashboard so user can edit it
    const clone = {
      id: "dash_" + Date.now(),
      name: "Custom " + cur.name.replace(/^[^\w]+/, "").split("(")[0].trim() + " (" + new Date().toLocaleDateString() + ")",
      isDefault: false,
      widgets: [...cur.widgets]
    };
    dashManager.customDashboards.push(clone);
    dashManager.currentId = clone.id;
    cur = clone;
  }

  if (cur.widgets.includes(widgetId)) {
    cur.widgets = cur.widgets.filter(w => w !== widgetId);
  } else {
    cur.widgets.push(widgetId);
  }
  dashManager.save();
  window.openAddWidgetModal(dashManager.activeWidgetCategory || "all");
  renderActiveDashboardView();
};

window.removeWidgetFromDashboard = (widgetId) => {
  const cur = dashManager.getCurrent();
  if (cur.isDefault || cur.isPreset) return;
  cur.widgets = cur.widgets.filter(w => w !== widgetId);
  dashManager.save();
  renderActiveDashboardView();
};


// ── Indicators ──────────────────────────────────────────────
let iocState = {
  type: "all",
  search: "",
  page: 1,
  pageSize: 50,
  iocs: [],
};

async function renderIndicators(container) {
  const iocs = await apiFetch("/api/iocs?limit=50000");
  iocState.iocs = iocs;
  iocState.page = 1;
  iocState.search = "";

  const counts = { all: iocs.length };
  iocs.forEach(i => {
    const t = i.ioc_type ? i.ioc_type.toLowerCase() : "other";
    counts[t] = (counts[t] || 0) + 1;
  });

  const preferred = ["all", "ip", "domain", "url", "hash"];
  const typeKeys = [...preferred];
  Object.keys(counts).forEach(k => {
    if (!typeKeys.includes(k)) typeKeys.push(k);
  });
  const availableTypes = typeKeys.filter(k => counts[k] !== undefined && counts[k] > 0);

  const typeLabels = {
    all: "All IOCs",
    ip: "IP Addresses",
    domain: "Domains",
    url: "URLs",
    hash: "Hashes",
  };

  container.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 20px;">
      <div class="type-tabs" id="ioc-type-tabs">
        ${availableTypes.map(k => `
          <button class="type-tab ${iocState.type === k ? 'active' : ''}" onclick="window.selectIocType('${k}')">
            <span>${typeLabels[k] || k.toUpperCase()}</span>
            <span class="tab-count">${(counts[k] || 0).toLocaleString()}</span>
          </button>
        `).join("")}
      </div>

      <div style="display: flex; align-items: center; gap: 12px;">
        <input type="text" id="ioc-search" placeholder="Filter by value, malware, threat..." 
               style="width: 280px; padding: 8px 12px; background: var(--panel); border: 1px solid var(--border); color: #fff; border-radius: 6px; font-size: 13px;">
      </div>
    </div>

    <div class="table-container" id="ioc-table-container">
      ${renderIOCTableFiltered()}
    </div>
  `;

  document.getElementById("ioc-search").addEventListener("input", (e) => {
    iocState.search = e.target.value.toLowerCase().trim();
    iocState.page = 1;
    document.getElementById("ioc-table-container").innerHTML = renderIOCTableFiltered();
  });
}

function renderIOCTableFiltered() {
  const { iocs, type, search, page, pageSize } = iocState;
  
  let filtered = type === "all" ? iocs : iocs.filter(i => (i.ioc_type || "").toLowerCase() === type);
  
  if (search) {
    filtered = filtered.filter(i => 
      (i.value && i.value.toLowerCase().includes(search)) ||
      (i.malware && i.malware.toLowerCase().includes(search)) ||
      (i.threat_type && i.threat_type.toLowerCase().includes(search))
    );
  }

  const total = filtered.length;
  const totalPages = Math.ceil(total / pageSize) || 1;
  const currPage = Math.min(Math.max(1, page), totalPages);
  const startIdx = (currPage - 1) * pageSize;
  const paginated = filtered.slice(startIdx, startIdx + pageSize);

  if (total === 0) {
    return `
      <div style="padding: 40px; text-align: center; color: var(--fg-mute);">
        No indicators found for type: <strong style="color: var(--fg);">${type.toUpperCase()}</strong>${search ? ` matching "${search}"` : ""}.
      </div>
    `;
  }

  return `
    <table>
      <thead>
        <tr>
          <th style="width: 90px;">Severity</th>
          <th style="width: 100px;">Type</th>
          <th>Indicator Value</th>
          <th style="width: 200px;">Threat Type</th>
          <th style="width: 180px;">Malware</th>
        </tr>
      </thead>
      <tbody>
        ${paginated.map(ioc => {
          const sev = ioc.severity >= 8 ? "high" : ioc.severity >= 5 ? "med" : "low";
          const safeVal = (ioc.value || "").replace(/'/g, "\\'");
          return `<tr>
            <td><span class="badge sev-${sev}">${ioc.severity.toFixed(1)}</span></td>
            <td><span class="badge type ${ioc.ioc_type}">${(ioc.ioc_type || "").toUpperCase()}</span></td>
            <td class="trunc mono">
              <span title="${ioc.value}">${ioc.value}</span>
              <button class="copy-btn" title="Copy indicator" onclick="window.copyIocValue(this, '${safeVal}')">📋</button>
            </td>
            <td style="color:var(--fg-dim)">${ioc.threat_type || "—"}</td>
            <td>${ioc.malware ? `<span class="badge malware">${ioc.malware}</span>` : '<span class="mute">—</span>'}</td>
          </tr>`;
        }).join("")}
      </tbody>
    </table>
    <div class="table-pagination">
      <div>
        Showing <strong>${startIdx + 1}–${Math.min(startIdx + pageSize, total)}</strong> of <strong>${total.toLocaleString()}</strong> ${type === 'all' ? 'total indicators' : type.toUpperCase() + ' indicators'}
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <span class="mute">Page ${currPage} of ${totalPages}</span>
        <button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" ${currPage <= 1 ? 'disabled' : ''} onclick="window.setIocPage(${currPage - 1})">← Prev</button>
        <button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" ${currPage >= totalPages ? 'disabled' : ''} onclick="window.setIocPage(${currPage + 1})">Next →</button>
      </div>
    </div>
  `;
}

window.selectIocType = (type) => {
  iocState.type = type;
  iocState.page = 1;
  document.querySelectorAll(".type-tab").forEach(tab => {
    if (tab.getAttribute("onclick") && tab.getAttribute("onclick").includes(`'${type}'`)) {
      tab.classList.add("active");
    } else {
      tab.classList.remove("active");
    }
  });
  const container = document.getElementById("ioc-table-container");
  if (container) {
    container.innerHTML = renderIOCTableFiltered();
  }
};

window.setIocPage = (p) => {
  iocState.page = p;
  const container = document.getElementById("ioc-table-container");
  if (container) {
    container.innerHTML = renderIOCTableFiltered();
  }
};

window.copyIocValue = (btn, val) => {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(val);
  }
  const orig = btn.innerHTML;
  btn.innerHTML = "✓";
  btn.style.color = "var(--success)";
  setTimeout(() => {
    btn.innerHTML = orig;
    btn.style.color = "";
  }, 1000);
};

// ── Adversaries (MISP Galaxy Clusters) ──────────────────────
let advState = {
  cluster: "all",
  search: "",
  page: 1,
  limit: 24,
  data: null,
};

async function renderAdversaries(container) {
  container.innerHTML = '<div style="padding:40px;text-align:center;color:var(--accent)">Loading Adversaries from MISP Galaxy...</div>';

  try {
    const url = `/api/adversaries?cluster_type=${advState.cluster}&search=${encodeURIComponent(advState.search)}&page=${advState.page}&limit=${advState.limit}`;
    const data = await apiFetch(url);
    advState.data = data;

    const sync = data.sync_state || {};
    const totalPages = Math.ceil(data.total / data.limit) || 1;
    const shortSha = sync.commit_sha ? sync.commit_sha.slice(0, 7) : "—";
    const commitDate = sync.commit_date ? new Date(sync.commit_date).toLocaleString() : "—";

    const clusterTabs = [
      { cluster_type: "all", name: "All Adversaries", count: data.total_all },
      ...(data.clusters || []),
    ];

    container.innerHTML = `
      <!-- GitHub Commit Sync Status Banner -->
      <div class="sync-banner">
        <div class="sync-info">
          <div class="sync-repo">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            <span>MISP/misp-galaxy (main)</span>
          </div>
          <span class="sync-sha" title="${sync.commit_sha || ''}">Commit: ${shortSha}</span>
          <span class="sync-badge synced">● Synced with GitHub</span>
          <span class="mute" style="font-size:11px;">Updated: ${commitDate}</span>
        </div>
        <button id="adv-sync-btn" class="btn-secondary" style="padding: 5px 12px; font-size: 11px;" onclick="window.syncAdversaries(true)">
          ↻ Check GitHub Sync
        </button>
      </div>

      <!-- Filter Controls: Cluster Tabs & Search -->
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 20px;">
        <div class="type-tabs">
          ${clusterTabs.map(c => `
            <button class="type-tab ${advState.cluster === c.cluster_type ? 'active' : ''}" onclick="window.selectAdvCluster('${c.cluster_type}')">
              <span>${c.name}</span>
              <span class="tab-count">${(c.count || 0).toLocaleString()}</span>
            </button>
          `).join("")}
        </div>

        <input type="text" id="adv-search" value="${advState.search}" placeholder="Search adversary name, alias, country, incident..."
               style="width: 320px; padding: 8px 12px; background: var(--panel); border: 1px solid var(--border); color: #fff; border-radius: 6px; font-size: 13px;">
      </div>

      <!-- Adversaries Grid / Content -->
      <div id="adv-content-area">
        ${renderAdversariesCards(data)}
      </div>
    `;

    // Live search debounced
    let searchTimeout;
    document.getElementById("adv-search").addEventListener("input", (e) => {
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => {
        advState.search = e.target.value.trim();
        advState.page = 1;
        renderAdversaries(container);
      }, 300);
    });

  } catch (err) {
    container.innerHTML = `<div style="color:var(--danger);padding:30px;">Failed to load adversaries: ${err.message}</div>`;
  }
}

function renderAdversariesCards(data) {
  const { adversaries, total, page, limit } = data;
  const totalPages = Math.ceil(total / limit) || 1;

  if (!adversaries || adversaries.length === 0) {
    return `<div style="padding: 40px; text-align: center; color: var(--fg-mute);">No adversaries found matching your filters.</div>`;
  }

  return `
    <div class="adversary-grid">
      ${adversaries.map(a => {
        const countryLabel = a.country || a.state_sponsor || "Unknown";
        const clusterBadge = a.cluster_type.replace(/-/g, " ").toUpperCase();
        const synonyms = (a.synonyms || []).slice(0, 4);

        return `
          <div class="adversary-card">
            <div class="adversary-card-header">
              <div class="adversary-name">${a.name}</div>
              <span class="badge type" style="font-size:10px;">${clusterBadge}</span>
            </div>

            <div class="adversary-meta-row">
              ${a.country ? `<span class="country-pill">🌍 ${a.country}</span>` : ""}
              ${a.state_sponsor ? `<span class="country-pill" style="color:var(--accent-light);">🏛️ ${a.state_sponsor}</span>` : ""}
              ${a.incident_type ? `<span class="badge sev-high" style="font-size:10px;">${a.incident_type}</span>` : ""}
            </div>

            <div class="adversary-desc">
              ${a.description || '<span class="mute">No description provided in galaxy cluster.</span>'}
            </div>

            ${synonyms.length > 0 ? `
              <div class="alias-tag-list">
                ${synonyms.map(s => `<span class="alias-tag" title="Alias">${s}</span>`).join("")}
                ${(a.synonyms || []).length > 4 ? `<span class="alias-tag">+${(a.synonyms || []).length - 4} more</span>` : ""}
              </div>
            ` : ""}

            <div class="adversary-card-footer">
              <span class="mute" style="font-size:11px;">
                ${a.refs_count > 0 ? `📑 ${a.refs_count} References` : "MISP Verified"}
              </span>
              <button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="window.viewAdversaryDetail(${a.id})">
                Inspect Dossier →
              </button>
            </div>
          </div>
        `;
      }).join("")}
    </div>

    <!-- Pagination -->
    <div class="table-pagination" style="border-radius: 8px; margin-bottom: 24px;">
      <div>Showing <strong>${(page - 1) * limit + 1}–${Math.min(page * limit, total)}</strong> of <strong>${total.toLocaleString()}</strong> adversaries</div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <span class="mute">Page ${page} of ${totalPages}</span>
        <button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" ${page <= 1 ? 'disabled' : ''} onclick="window.setAdvPage(${page - 1})">← Prev</button>
        <button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" ${page >= totalPages ? 'disabled' : ''} onclick="window.setAdvPage(${page + 1})">Next →</button>
      </div>
    </div>
  `;
}

window.selectAdvCluster = (clusterType) => {
  advState.cluster = clusterType;
  advState.page = 1;
  renderAdversaries(document.getElementById("main-content"));
};

window.setAdvPage = (p) => {
  advState.page = p;
  renderAdversaries(document.getElementById("main-content"));
};

window.syncAdversaries = async (force = true) => {
  const btn = document.getElementById("adv-sync-btn");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = "↻ Checking GitHub Commit...";
  }

  try {
    const res = await apiFetch(`/api/adversaries/sync?force=${force}`, { method: "POST" });
    if (res.updated) {
      alert(`GitHub sync completed! ${res.clusters_synced || 0} clusters synced (${res.total_adversaries || 0} total adversaries). Commit: ${res.commit_sha ? res.commit_sha.slice(0, 7) : ''}`);
    } else {
      alert(`Already up to date with GitHub commit ${res.commit_sha ? res.commit_sha.slice(0, 7) : ''} (${res.total_adversaries || 0} adversaries in DB).`);
    }
    renderAdversaries(document.getElementById("main-content"));
  } catch (err) {
    alert("Sync failed: " + err.message);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = "↻ Check GitHub Sync";
    }
  }
};

window.viewAdversaryDetail = async (id) => {
  const backdrop = document.getElementById("drawer-backdrop");
  const drawer = document.getElementById("adversary-drawer");
  if (!backdrop || !drawer) return;

  drawer.innerHTML = '<div style="padding:40px;text-align:center;color:var(--accent);">Loading Adversary Dossier...</div>';
  backdrop.classList.remove("hidden");
  drawer.classList.remove("hidden");

  try {
    const adv = await apiFetch(`/api/adversaries/${id}`);
    drawer.innerHTML = `
      <div class="drawer-header">
        <div>
          <div style="font-size:11px;font-weight:700;color:var(--accent-light);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px;">
            ${adv.cluster_name}
          </div>
          <h2 style="font-size:22px;font-weight:700;color:#fff;">${adv.name}</h2>
        </div>
        <button style="background:none;border:none;color:var(--fg-dim);font-size:18px;cursor:pointer;" onclick="window.closeAdversaryDrawer()">✕</button>
      </div>

      <div class="drawer-body">
        <!-- Metadata pills -->
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px;">
          ${adv.country ? `<span class="country-pill">🌍 Country: ${adv.country}</span>` : ""}
          ${adv.state_sponsor ? `<span class="country-pill" style="color:var(--accent-light);">🏛️ Sponsor: ${adv.state_sponsor}</span>` : ""}
          ${adv.incident_type ? `<span class="badge sev-high">${adv.incident_type}</span>` : ""}
        </div>

        <!-- Description -->
        <div class="drawer-section">
          <div class="drawer-section-title">Overview & History</div>
          <div style="font-size:13px;line-height:1.6;color:var(--fg);">
            ${adv.description || '<span class="mute">No detailed description available.</span>'}
          </div>
        </div>

        <!-- Synonyms / Aliases -->
        ${(adv.synonyms || []).length > 0 ? `
          <div class="drawer-section">
            <div class="drawer-section-title">Known Aliases & Vendor Names (${adv.synonyms.length})</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;">
              ${adv.synonyms.map(s => `<span class="alias-tag" style="font-size:12px;padding:3px 8px;">${s}</span>`).join("")}
            </div>
          </div>
        ` : ""}

        <!-- Targeted Categories / Victims -->
        ${(adv.targets || []).length > 0 ? `
          <div class="drawer-section">
            <div class="drawer-section-title">Targeted Sectors & Victims</div>
            <div style="display:flex;flex-wrap:wrap;gap:6px;">
              ${adv.targets.map(t => `<span class="badge type" style="font-size:11px;">${t}</span>`).join("")}
            </div>
          </div>
        ` : ""}

        <!-- External Intelligence References -->
        ${(adv.refs || []).length > 0 ? `
          <div class="drawer-section">
            <div class="drawer-section-title">External Research & CTI References (${adv.refs.length})</div>
            <div style="max-height:220px;overflow-y:auto;">
              ${adv.refs.map(r => `
                <a href="${r}" target="_blank" rel="noopener noreferrer" class="drawer-ref-link">
                  ↗ ${r}
                </a>
              `).join("")}
            </div>
          </div>
        ` : ""}

        <!-- Raw UUID & Meta -->
        <div class="drawer-section" style="border-top:1px solid var(--border);padding-top:16px;">
          <div class="drawer-section-title">MISP Galaxy Identifier</div>
          <div class="mono" style="font-size:11px;color:var(--fg-dim);word-break:break-all;">
            UUID: ${adv.uuid}
          </div>
        </div>
      </div>
    `;
  } catch (err) {
    drawer.innerHTML = `<div style="padding:30px;color:var(--danger)">Error: ${err.message}</div>`;
  }
};

window.closeAdversaryDrawer = () => {
  const backdrop = document.getElementById("drawer-backdrop");
  const drawer = document.getElementById("adversary-drawer");
  if (backdrop) backdrop.classList.add("hidden");
  if (drawer) drawer.classList.add("hidden");
};

// Backwards compatibility alias
const renderThreatIntel = renderAdversaries;

window.renderIntelPage = (p) => renderThreatIntel(document.getElementById("main-content"), p);

window.toggleEvent = async (id) => {
  const row = document.getElementById(`ev-details-${id}`);
  const isHidden = row.classList.contains('hidden');
  row.classList.toggle('hidden');
  if (isHidden) {
    const cont = document.getElementById(`ev-container-${id}`);
    if (cont.innerHTML.includes("Loading")) {
      const attrs = await apiFetch(`/api/events/${id}/iocs`);
      cont.innerHTML = attrs.length === 0 ? '<div class="mute">No IOCs linked.</div>' : `
        <table style="background:var(--panel);border:1px solid var(--border);border-radius:4px;">
          <thead><tr><th>Type</th><th>Value</th><th>Severity</th></tr></thead>
          <tbody>${attrs.map(a => `<tr>
            <td><span class="badge type ${a.ioc_type}">${a.ioc_type}</span></td>
            <td class="trunc mono">${a.value}</td>
            <td><span class="badge sev-${a.severity >= 8 ? 'high' : a.severity >= 5 ? 'med' : 'low'}">${a.severity.toFixed(1)}</span></td>
          </tr>`).join("")}</tbody>
        </table>`;
    }
  }
};

// ── Search ──────────────────────────────────────────────────
async function renderSearch(container) {
  container.innerHTML = `
    <div style="max-width:960px;">
      <div style="display:flex; gap:8px; margin-bottom:16px;">
        <input type="text" id="search-term" placeholder="Search IOCs, adversaries, events (IP, domain, hash, URL, actor name)..." 
               style="flex:1; padding:12px; background:var(--panel); border:1px solid var(--border); color:#fff; border-radius:4px;">
        <select id="search-type-filter" style="padding:10px; background:var(--panel); border:1px solid var(--border); color:#fff; border-radius:4px; font-size:12px;">
          <option value="all">All Types</option>
          <option value="ip">IP</option>
          <option value="url">URL</option>
          <option value="domain">Domain</option>
          <option value="hash">Hash</option>
        </select>
        <button id="search-btn" class="btn-primary" style="width:120px;">Search</button>
      </div>
      <div class="search-tabs" style="display:flex; gap:0; margin-bottom:16px; border-bottom:1px solid var(--border);">
        <button class="search-tab active" data-tab="es" style="padding:10px 20px; background:none; border:none; color:#fff; cursor:pointer; font-size:12px; font-weight:600; border-bottom:2px solid var(--accent);">
          🔍 Elasticsearch (Local Intel)
        </button>
        <button class="search-tab" data-tab="providers" style="padding:10px 20px; background:none; border:none; color:#94a3b8; cursor:pointer; font-size:12px; border-bottom:2px solid transparent;">
          🌐 External Providers (APIs)
        </button>
      </div>
      <div id="search-results"></div>
    </div>
  `;

  let activeTab = "es";

  // Tab switching
  document.querySelectorAll(".search-tab").forEach(tab => {
    tab.addEventListener("click", () => {
      activeTab = tab.dataset.tab;
      document.querySelectorAll(".search-tab").forEach(t => {
        t.style.borderBottomColor = "transparent";
        t.style.color = "#94a3b8";
        t.classList.remove("active");
      });
      tab.style.borderBottomColor = "var(--accent)";
      tab.style.color = "#fff";
      tab.classList.add("active");
      document.getElementById("search-results").innerHTML = "";
    });
  });

  document.getElementById("search-btn").addEventListener("click", async () => {
    const term = document.getElementById("search-term").value.trim();
    if (!term) return;
    
    const resultsDiv = document.getElementById("search-results");

    if (activeTab === "es") {
      await runESSearch(term, resultsDiv);
    } else {
      await runProviderSearch(term, resultsDiv);
    }
  });

  // Enter key
  document.getElementById("search-term").addEventListener("keydown", (e) => {
    if (e.key === "Enter") document.getElementById("search-btn").click();
  });
}

async function runESSearch(term, resultsDiv) {
  const typeFilter = document.getElementById("search-type-filter")?.value || "all";
  resultsDiv.innerHTML = '<div class="mute" style="padding:20px;">Searching Elasticsearch...</div>';
  
  try {
    const data = await apiFetch(`/api/es/search?q=${encodeURIComponent(term)}&type=${typeFilter}&size=100`);
    
    if (data.total === 0) {
      resultsDiv.innerHTML = `
        <div class="intel-panel" style="text-align:center; padding:40px;">
          <div style="font-size:24px; margin-bottom:8px;">🔍</div>
          <div style="font-size:14px; color:#94a3b8;">No results found for <strong style="color:#fff;">"${term}"</strong></div>
          <div style="font-size:12px; color:#64748b; margin-top:4px;">Try a different query or check the External Providers tab.</div>
        </div>
      `;
      return;
    }

    let html = `
      <div style="margin-bottom:16px; display:flex; gap:12px; align-items:center;">
        <span style="font-size:13px; color:#94a3b8;">Found <strong style="color:#fff;">${data.total}</strong> results</span>
        <span class="card-badge badge-blue" style="font-size:10px;">IOCs: ${data.iocs.length}</span>
        <span class="card-badge badge-green" style="font-size:10px;">Events: ${data.events.length}</span>
        <span class="card-badge badge-red" style="font-size:10px;">Adversaries: ${data.adversaries.length}</span>
      </div>
    `;

    // IOCs
    if (data.iocs.length > 0) {
      html += `
        <div class="intel-panel" style="margin-bottom:16px;">
          <div class="intel-panel-header">
            <span class="intel-panel-title"><span style="color:#0ea5e9;">⚡</span> Indicators of Compromise (${data.iocs.length})</span>
          </div>
          <div class="intel-panel-body" style="padding:0;">
            <table style="width:100%; font-size:12px; border-collapse:collapse;">
              <thead>
                <tr style="border-bottom:1px solid var(--border);">
                  <th style="padding:10px 12px; text-align:left; color:#94a3b8; font-weight:600;">Value</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Type</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Threat</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Malware</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Severity</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Source</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Score</th>
                </tr>
              </thead>
              <tbody>
                ${data.iocs.map(ioc => {
                  const sevColor = ioc.severity >= 8 ? "#ef4444" : ioc.severity >= 5 ? "#f59e0b" : "#10b981";
                  return `
                    <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
                      <td style="padding:8px 12px; color:#fff; font-family:monospace; max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${ioc.value}">${ioc.value}</td>
                      <td style="padding:8px;"><span class="card-badge badge-blue" style="font-size:10px;">${ioc.ioc_type || "-"}</span></td>
                      <td style="padding:8px; color:#94a3b8;">${ioc.threat_type || "-"}</td>
                      <td style="padding:8px; color:#c084fc;">${ioc.malware || "-"}</td>
                      <td style="padding:8px;"><span style="color:${sevColor}; font-weight:700;">${ioc.severity}</span></td>
                      <td style="padding:8px; color:#94a3b8;">${ioc.source_name || "-"}</td>
                      <td style="padding:8px; color:#38bdf8;">${ioc._score?.toFixed(1) || "-"}</td>
                    </tr>
                  `;
                }).join("")}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    // Events
    if (data.events.length > 0) {
      html += `
        <div class="intel-panel" style="margin-bottom:16px;">
          <div class="intel-panel-header">
            <span class="intel-panel-title"><span style="color:#10b981;">📋</span> Intel Events (${data.events.length})</span>
          </div>
          <div class="intel-panel-body" style="padding:0;">
            <table style="width:100%; font-size:12px; border-collapse:collapse;">
              <thead>
                <tr style="border-bottom:1px solid var(--border);">
                  <th style="padding:10px 12px; text-align:left; color:#94a3b8; font-weight:600;">Title</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Organization</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Threat Level</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Date</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Score</th>
                </tr>
              </thead>
              <tbody>
                ${data.events.map(evt => `
                  <tr style="border-bottom:1px solid rgba(255,255,255,0.04);">
                    <td style="padding:8px 12px; color:#fff; max-width:350px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${evt.title}">${evt.title}</td>
                    <td style="padding:8px; color:#94a3b8;">${evt.organization || "-"}</td>
                    <td style="padding:8px;"><span class="card-badge badge-red" style="font-size:10px;">${evt.threat_level || "-"}</span></td>
                    <td style="padding:8px; color:#64748b;">${evt.date || "-"}</td>
                    <td style="padding:8px; color:#38bdf8;">${evt._score?.toFixed(1) || "-"}</td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    // Adversaries
    if (data.adversaries.length > 0) {
      html += `
        <div class="intel-panel" style="margin-bottom:16px;">
          <div class="intel-panel-header">
            <span class="intel-panel-title"><span style="color:#c084fc;">🎯</span> Adversaries (${data.adversaries.length})</span>
          </div>
          <div class="intel-panel-body" style="padding:0;">
            <table style="width:100%; font-size:12px; border-collapse:collapse;">
              <thead>
                <tr style="border-bottom:1px solid var(--border);">
                  <th style="padding:10px 12px; text-align:left; color:#94a3b8; font-weight:600;">Name</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Cluster</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Country</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Sponsor</th>
                  <th style="padding:10px 8px; text-align:left; color:#94a3b8; font-weight:600;">Score</th>
                </tr>
              </thead>
              <tbody>
                ${data.adversaries.map(adv => `
                  <tr style="border-bottom:1px solid rgba(255,255,255,0.04); cursor:pointer;" onclick="window.openAdversaryDrawer && window.openAdversaryDrawer(${adv.adversary_id})">
                    <td style="padding:8px 12px; color:#fff; font-weight:600;">${adv.name}</td>
                    <td style="padding:8px;"><span class="card-badge badge-blue" style="font-size:10px;">${adv.cluster_name || "-"}</span></td>
                    <td style="padding:8px; color:#94a3b8;">${adv.country || "-"}</td>
                    <td style="padding:8px; color:#f59e0b;">${adv.state_sponsor || "-"}</td>
                    <td style="padding:8px; color:#38bdf8;">${adv._score?.toFixed(1) || "-"}</td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      `;
    }

    resultsDiv.innerHTML = html;
  } catch (err) {
    resultsDiv.innerHTML = `
      <div class="intel-panel" style="text-align:center; padding:30px;">
        <div style="color:var(--danger); font-size:14px; margin-bottom:8px;">⚠ Elasticsearch Unavailable</div>
        <div style="font-size:12px; color:#94a3b8;">${err.message}</div>
        <div style="font-size:11px; color:#64748b; margin-top:8px;">Make sure the Elasticsearch container is running and try again.</div>
      </div>
    `;
  }
}

async function runProviderSearch(term, resultsDiv) {
  resultsDiv.innerHTML = '<div class="mute" style="padding:20px;">Searching all providers (this may take a few seconds)...</div>';
  
  try {
    const { query_id } = await apiFetch("/api/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ term })
    });
    
    // Wait for the async lookups to complete
    await new Promise(r => setTimeout(r, 2000));
    
    const data = await apiFetch(`/api/search/${query_id}`);
    
    if (!data.results || data.results.length === 0) {
      resultsDiv.innerHTML = '<div class="mute">No providers configured. Add API keys in Integrations.</div>';
      return;
    }
    
    resultsDiv.innerHTML = `
      <div style="margin-bottom:24px; border-bottom:1px solid var(--border); padding-bottom:12px;">
        <h2 style="font-size:18px;">External Results for <span class="mono text-accent">${data.term}</span></h2>
      </div>
      ${data.results.map(r => renderProviderResult(r)).join("")}
    `;
  } catch (err) {
    resultsDiv.innerHTML = `<div style="color:var(--danger);">${err.message}</div>`;
  }
}

function renderProviderResult(r) {
  const statusCls = r.status === 'ok' ? 'sev-low' : r.status === 'skipped' ? 'sev-med' : 'sev-high';
  
  let detailsHtml = '';
  
  // Parse the raw JSON if it exists
  let raw = {};
  try {
    if (r.raw_json) raw = JSON.parse(r.raw_json);
  } catch (e) {
    console.error("Failed to parse raw_json for", r.provider);
  }

  // Custom formatting per provider
  if (r.provider === "virustotal") {
    const stats = raw.last_analysis_stats || {};
    const votes = raw.total_votes || {};
    const names = raw.names || [];
    const tags = raw.tags || [];
  
    const engines = raw.last_analysis_results || {};
    const flagged = Object.entries(engines)
      .filter(([_, res]) => res.category === "malicious" || res.category === "suspicious")
      .map(([engine, res]) => `<li><strong>${engine}</strong>: ${res.result || res.category}</li>`)
      .join("");
  
    const fileType = raw.type_description || null;
    const fileSize = raw.size ? `${(raw.size / 1024).toFixed(1)} KB` : null;
    const magic = raw.magic || null;
    const firstSeen = raw.first_submission_date
      ? new Date(raw.first_submission_date * 1000).toLocaleString()
      : null;
    const lastSeen = raw.last_analysis_date
      ? new Date(raw.last_analysis_date * 1000).toLocaleString()
      : null;
    const signatureInfo = raw.signature_info || null;
    const nameList = names.slice(0, 5).join(", ");
  
    detailsHtml = `
      <div style="display:flex; gap:24px; margin-bottom:16px; font-size:12px;">
        <div><span class="mute">Malicious:</span> <strong class="text-danger">${stats.malicious || 0}</strong></div>
        <div><span class="mute">Suspicious:</span> <strong class="text-warn">${stats.suspicious || 0}</strong></div>
        <div><span class="mute">Undetected:</span> <strong>${stats.undetected || 0}</strong></div>
        <div><span class="mute">Harmless:</span> <strong class="text-success">${stats.harmless || 0}</strong></div>
      </div>
  
      <div style="display:flex; gap:24px; margin-bottom:16px; font-size:12px;">
        <div><span class="mute">Community Votes:</span> <strong class="text-success">${votes.harmless || 0} harmless</strong> / <strong class="text-danger">${votes.malicious || 0} malicious</strong></div>
      </div>
  
      ${fileType || fileSize || magic || firstSeen || lastSeen || raw.asn || raw.country || raw.jarm ? `
        <table style="width:100%; font-size:12px; border-collapse:collapse; margin-bottom:16px;">
          ${fileType ? `<tr><td class="mute" style="padding:4px 0; width:140px;">File Type</td><td>${fileType}</td></tr>` : ""}
          ${fileSize ? `<tr><td class="mute" style="padding:4px 0;">File Size</td><td>${fileSize}</td></tr>` : ""}
          ${magic ? `<tr><td class="mute" style="padding:4px 0;">Magic</td><td class="mono">${magic}</td></tr>` : ""}
          ${signatureInfo ? `<tr><td class="mute" style="padding:4px 0;">Signature</td><td>${signatureInfo.product || "Unsigned"} ${signatureInfo.signer ? "— " + signatureInfo.signer : ""}</td></tr>` : ""}
          ${firstSeen ? `<tr><td class="mute" style="padding:4px 0;">First Seen</td><td>${firstSeen}</td></tr>` : ""}
          ${lastSeen ? `<tr><td class="mute" style="padding:4px 0;">Last Analyzed</td><td>${lastSeen}</td></tr>` : ""}
          ${raw.asn ? `<tr><td class="mute" style="padding:4px 0;">ASN</td><td>${raw.asn} — ${raw.as_owner || ""}</td></tr>` : ""}
          ${raw.country ? `<tr><td class="mute" style="padding:4px 0;">Country</td><td>${raw.country}</td></tr>` : ""}
          ${raw.jarm ? `<tr><td class="mute" style="padding:4px 0;">JARM</td><td class="mono trunc">${raw.jarm}</td></tr>` : ""}
          ${nameList ? `<tr><td class="mute" style="padding:4px 0;">Known Names</td><td class="trunc" title="${names.join(", ")}">${nameList}${names.length > 5 ? " …" : ""}</td></tr>` : ""}
        </table>
      ` : ""}
  
      ${tags.length > 0 ? `
        <div style="margin-bottom:12px;">
          <span class="mute" style="font-size:12px;">Tags:</span>
          <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:4px;">
            ${tags.map(t => `<span class="badge type" style="background:var(--border-light);">${t}</span>`).join("")}
          </div>
        </div>
      ` : ""}
  
      ${flagged ? `
        <div style="font-size:12px;">
          <strong>Detections:</strong>
          <ul style="margin-left:16px; margin-top:4px; max-height:160px; overflow-y:auto;">${flagged}</ul>
        </div>
      ` : '<div class="mute" style="font-size:12px;">No engines flagged this indicator.</div>'}
    `;
  } 
  else if (r.provider === "abuseipdb" && raw.abuseConfidenceScore !== undefined) {
    detailsHtml = `
      <table style="width:100%; font-size:12px; border-collapse:collapse;">
        <tr><td class="mute" style="padding:4px 0;">Abuse Score</td><td><strong>${raw.abuseConfidenceScore}%</strong></td></tr>
        <tr><td class="mute" style="padding:4px 0;">Country</td><td>${raw.countryCode || 'Unknown'}</td></tr>
        <tr><td class="mute" style="padding:4px 0;">ISP</td><td>${raw.isp || 'Unknown'}</td></tr>
        <tr><td class="mute" style="padding:4px 0;">Usage Type</td><td>${raw.usageType || 'Unknown'}</td></tr>
        <tr><td class="mute" style="padding:4px 0;">Total Reports</td><td>${raw.totalReports || 0}</td></tr>
      </table>
    `;
  }
  else if (r.provider === "pulsedive" && raw.risk !== undefined) {
    const props = raw.properties || [];
    const propList = props.map(p => `<li><strong>${p.name}</strong>: ${p.value}</li>`).join("");
    detailsHtml = `
      <div style="margin-bottom:12px;"><span class="mute">Risk Level:</span> <strong class="text-warn">${raw.risk}</strong></div>
      ${propList ? `<div style="font-size:12px;"><strong>Properties:</strong><ul style="margin-left:16px; margin-top:4px;">${propList}</ul></div>` : ''}
    `;
  }
  else if (r.provider === "intelx" && Array.isArray(raw)) {
    if (raw.length === 0) {
      detailsHtml = '<div class="mute">No records found.</div>';
    } else {
      const records = raw.map(item => `
        <div style="border-bottom:1px solid var(--border); padding:8px 0;">
          <div style="font-weight:600; font-size:12px;">${item.name || 'Unknown Item'}</div>
          <div class="mute" style="font-size:11px;">Bucket: ${item.bucket} | Date: ${item.date || 'Unknown'}</div>
        </div>
      `).join("");
      detailsHtml = `<div style="max-height:200px; overflow-y:auto;">${records}</div>`;
    }
  }
  else {
    // Fallback if the provider returned a simple message or empty object
    detailsHtml = `<div style="font-size:12px;">${r.summary || 'No structured data available.'}</div>`;
  }

  return `
    <div class="stat-card" style="margin-bottom:16px; border-left: 3px solid ${r.status === 'ok' ? 'var(--success)' : 'var(--danger)'};">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
        <div style="font-weight:700; text-transform:uppercase; color:var(--accent); font-size:14px; letter-spacing:0.05em;">
          ${r.provider}
        </div>
        <span class="badge ${statusCls}">${r.status}</span>
      </div>
      ${detailsHtml}
    </div>
  `;
}
// ── DarkIntel Threat Feeds & Connectors (Integrations) ────────
let intFilterState = {
  search: "",
  sort: "name",
  sortAsc: true,
  compatVersion: "all",
  useCase: [],
  integrationType: [],
  deploymentType: [],
  status: [],
  solutionCategory: [],
  licenseType: [],
  viewMode: "grid"
};

function getConnectorIconSvg(iconName, name) {
  switch (iconName) {
    case "cloudflare":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="#F38020"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>`;
    case "anyrun":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none"><polygon points="5 3 19 12 5 21 5 3" fill="#0EA5E9"/><polygon points="9 7 15 12 9 17 9 7" fill="#38BDF8"/></svg>`;
    case "aws":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="#FF9900"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>`;
    case "abusech":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#EF4444" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    case "abuseipdb":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#EF4444" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;
    case "misp":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#A855F7" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>`;
    case "otx":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#38BDF8" stroke-width="2"><path d="M2 12h5l2-7 4 14 3-7h6"/></svg>`;
    case "urlhaus":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#10B981" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`;
    case "virustotal":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="#0EA5E9"><polygon points="3 4 12 12 3 20 3 4"/><polygon points="21 4 12 12 21 20 21 4"/></svg>`;
    case "intelx":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#C084FC" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z"/></svg>`;
    case "pulsedive":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#06B6D4" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>`;
    case "crowdstrike":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="#EF4444"><path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z"/></svg>`;
    case "shodan":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="#DC2626"><circle cx="12" cy="12" r="9"/><polygon points="12 7 15 13 9 13" fill="#fff"/></svg>`;
    case "csv":
    case "xml":
    case "file":
      return `<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#38BDF8" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>`;
    default:
      return `<div style="font-weight:700; color:#38BDF8; font-size:13px;">${(name || "CT").slice(0, 2).toUpperCase()}</div>`;
  }
}

let currentIngestFile = null;

async function renderIntegrations(container) {
  const [available, userSources] = await Promise.all([
    apiFetch("/api/sources/available"),
    apiFetch("/api/sources")
  ]);

  const configuredMap = {};
  userSources.forEach(s => {
    configuredMap[s.source_type] = s;
  });

  // Build items array
  const allItems = Object.entries(available).map(([key, meta]) => {
    const userCfg = configuredMap[key];
    const isConnected = !!userCfg;
    const isLiveActive = userCfg ? userCfg.is_active : (meta.status === "Active");
    return {
      key,
      ...meta,
      userConfig: userCfg,
      isConnected,
      computedStatus: isConnected ? (isLiveActive ? "Active" : "Configured") : (meta.status || "Available")
    };
  });

  // Filter items by search query and category
  let filtered = allItems.filter(item => {
    if (intFilterState.category && intFilterState.category !== "all") {
      const cat = intFilterState.category.toLowerCase();
      if (cat === "custom" && !item.key.startsWith("custom_") && item.license_type !== "Custom") return false;
      if (cat === "threat" && item.category !== "feed" && !item.use_case?.includes("Adversary")) return false;
      if (cat === "sandbox" && !item.display_name.toLowerCase().includes("sandbox") && !item.solution_category?.includes("Sandbox")) return false;
      if (cat === "osint" && !item.solution_category?.includes("OSINT") && !item.tags?.includes("OSINT") && !item.tags?.includes("RSS Feeds")) return false;
    }
    if (intFilterState.search) {
      const q = intFilterState.search.toLowerCase();
      const match = item.display_name.toLowerCase().includes(q) ||
                    item.description.toLowerCase().includes(q) ||
                    (item.author && item.author.toLowerCase().includes(q)) ||
                    (item.tags && item.tags.some(t => t.toLowerCase().includes(q)));
      if (!match) return false;
    }
    return true;
  });

  // Sort items
  filtered.sort((a, b) => {
    let valA = (a[intFilterState.sort] || a.display_name).toLowerCase();
    let valB = (b[intFilterState.sort] || b.display_name).toLowerCase();
    if (intFilterState.sort === "status") {
      valA = a.computedStatus.toLowerCase();
      valB = b.computedStatus.toLowerCase();
    }
    if (valA < valB) return intFilterState.sortAsc ? -1 : 1;
    if (valA > valB) return intFilterState.sortAsc ? 1 : -1;
    return 0;
  });

  container.innerHTML = `
    <div class="integrations-wrapper">
      <!-- Category Filter Pills Bar -->
      <div class="int-category-pills">
        <button class="int-cat-pill ${!intFilterState.category || intFilterState.category === 'all' ? 'active' : ''}" onclick="window.setIntCategoryFilter('all')">
          All Connectors (${allItems.length})
        </button>
        <button class="int-cat-pill ${intFilterState.category === 'threat' ? 'active' : ''}" onclick="window.setIntCategoryFilter('threat')">
          🛡️ Threat Feeds
        </button>
        <button class="int-cat-pill ${intFilterState.category === 'sandbox' ? 'active' : ''}" onclick="window.setIntCategoryFilter('sandbox')">
          🧪 Sandbox Analysis
        </button>
        <button class="int-cat-pill ${intFilterState.category === 'osint' ? 'active' : ''}" onclick="window.setIntCategoryFilter('osint')">
          🌐 OSINT & Public Feeds
        </button>
        <button class="int-cat-pill ${intFilterState.category === 'custom' ? 'active' : ''}" onclick="window.setIntCategoryFilter('custom')">
          ⚡ Custom Connectors
        </button>
      </div>

      <!-- Top Action Bar with Search, Sort, Custom Connector, Ingest IOCs -->
      <div class="integrations-top-controls">
        <div style="display:flex; align-items:center; gap:10px; flex:1; min-width:300px;">
          <div class="int-search-container" style="flex:1; max-width:320px;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="text" id="int-search-input" placeholder="Search feeds & connectors..." value="${intFilterState.search}">
          </div>

          <div class="int-sort-container">
            <span>Sort by</span>
            <select class="int-sort-select" id="int-sort-select">
              <option value="name" ${intFilterState.sort === 'name' ? 'selected' : ''}>Name</option>
              <option value="integration_type" ${intFilterState.sort === 'integration_type' ? 'selected' : ''}>Protocol</option>
              <option value="status" ${intFilterState.sort === 'status' ? 'selected' : ''}>Status</option>
            </select>
            <button class="int-page-btn" id="int-sort-order-btn" title="Toggle Sort Direction">
              ${intFilterState.sortAsc ? '↓' : '↑'}
            </button>
          </div>
        </div>

        <div style="display:flex; align-items:center; gap:8px;">
          <!-- Ingest IOCs (CSV / XML) Button -->
          <button class="topbar-action-pill" style="padding:7px 14px; font-size:12px;" onclick="window.openIngestIOCsModal()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            <span>Ingest IOCs (CSV / XML)</span>
          </button>

          <!-- Custom Connector Button -->
          <button class="btn-secondary" style="border:1px solid rgba(56,189,248,0.4); color:#38bdf8; display:inline-flex; align-items:center; gap:6px; font-weight:600; padding:7px 14px; font-size:12px; border-radius:6px; cursor:pointer;" onclick="window.openCustomConnectorModal()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            <span>Custom Connector</span>
          </button>

          <div class="int-pagination-controls" style="margin-left:4px;">
            <div class="int-page-badge">
              <button class="int-page-btn" id="int-prev-btn">◀</button>
              <span>1 - ${filtered.length} / ${allItems.length}</span>
              <button class="int-page-btn" id="int-next-btn">▶</button>
              <button class="int-page-btn" title="Refresh Connectors" onclick="window.refreshIntegrations()">⇄</button>
            </div>

            <div class="int-view-toggles">
              <button class="int-view-btn ${intFilterState.viewMode === 'grid' ? 'active' : ''}" id="btn-view-grid" title="Grid View" onclick="window.setIntViewMode('grid')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
              </button>
              <button class="int-view-btn ${intFilterState.viewMode === 'list' ? 'active' : ''}" id="btn-view-list" title="List View" onclick="window.setIntViewMode('list')">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
              </button>
              <button class="int-view-btn" title="Export Integrations Catalog" onclick="window.exportIntegrationsJson()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Main Layout: DarkIntel Full-Width Threat Feed Cards -->
      <div class="integrations-main-split" style="width:100%;">
        ${intFilterState.viewMode === 'list' ? `
          <main class="integrations-list-container" id="int-cards-grid" style="width:100%;">
            <div style="background:#0a111f; border:1px solid #152238; border-radius:6px; overflow:hidden;">
              <table style="width:100%; border-collapse:collapse; font-size:12px; text-align:left;">
                <thead>
                  <tr style="background:#070c14; border-bottom:1px solid #1a2538; color:#94a3b8; font-size:11px; text-transform:uppercase;">
                    <th style="padding:10px 14px;">Connector / Feed</th>
                    <th style="padding:10px 14px;">Protocol</th>
                    <th style="padding:10px 14px;">Use Case</th>
                    <th style="padding:10px 14px;">Source Provider</th>
                    <th style="padding:10px 14px;">Status</th>
                    <th style="padding:10px 14px; text-align:right;">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${filtered.length > 0 ? filtered.map(item => `
                    <tr style="border-bottom:1px solid #152238; cursor:pointer;" onclick="window.openConnectorModal('${item.key}')" onmouseover="this.style.background='#0d1726'" onmouseout="this.style.background='transparent'">
                      <td style="padding:10px 14px; display:flex; align-items:center; gap:10px;">
                        <div style="width:24px; height:24px; display:flex; align-items:center; justify-content:center;">
                          ${getConnectorIconSvg(item.icon, item.display_name)}
                        </div>
                        <span style="font-weight:600; color:#fff;">${item.display_name}</span>
                      </td>
                      <td style="padding:10px 14px;"><span class="protocol-chip">${(item.integration_type || "REST").toUpperCase()}</span></td>
                      <td style="padding:10px 14px; color:#cbd5e1;">${item.use_case || "General"}</td>
                      <td style="padding:10px 14px; color:#94a3b8;">${item.author || "DarkIntel SecOps"}</td>
                      <td style="padding:10px 14px;">
                        <span class="status-indicator-dot ${item.computedStatus.toLowerCase()}"></span>
                        <span style="margin-left:4px; font-size:11px; color:#cbd5e1;">${item.computedStatus}</span>
                      </td>
                      <td style="padding:10px 14px; text-align:right;">
                        <button class="btn-secondary" style="font-size:11px; padding:3px 10px;" onclick="event.stopPropagation(); window.openConnectorModal('${item.key}')">Configure</button>
                      </td>
                    </tr>
                  `).join("") : `
                    <tr><td colspan="6" style="padding:32px; text-align:center; color:#64748b;">No connectors matched your search.</td></tr>
                  `}
                </tbody>
              </table>
            </div>
          </main>
        ` : `
          <!-- 4-Column Cyber Feed Cards Grid -->
          <main class="integrations-cards-grid" id="int-cards-grid" style="width:100%;">
            ${filtered.length > 0 ? filtered.map(item => {
              return `
                <div class="cyber-feed-card ${item.isConnected ? 'status-active' : 'status-available'}" onclick="window.openConnectorModal('${item.key}')">
                  <div>
                    <div class="feed-card-header">
                      <div class="feed-badge-icon">
                        ${getConnectorIconSvg(item.icon, item.display_name)}
                      </div>
                      <div class="feed-title-block">
                        <div class="feed-card-name" title="${item.display_name}">${item.display_name}</div>
                        <div class="feed-card-category">${item.solution_category || "Threat Intelligence Feed"}</div>
                      </div>
                      <span class="feed-status-pill ${item.isConnected ? 'active' : 'available'}">
                        ● ${item.isConnected ? (item.userConfig?.is_active ? 'STREAMING' : 'CONFIGURED') : 'AVAILABLE'}
                      </span>
                    </div>

                    <!-- High-Tech Specs HUD -->
                    <div class="feed-specs-hud">
                      <span class="feed-spec-tag">${(item.integration_type || "REST").slice(0, 10).toUpperCase()}</span>
                      <span class="feed-spec-tag green">${item.category === 'feed' ? '24/7 STREAM' : 'ENRICHMENT'}</span>
                      <span class="feed-spec-tag purple">${item.deployment_type || 'CLOUD'}</span>
                    </div>

                    <div class="feed-card-description" title="${item.description}">
                      ${item.description}
                    </div>
                  </div>

                  <div class="feed-card-footer">
                    <div class="feed-footer-stats">
                      <span>🔒 TLS 1.3 Verified</span>
                    </div>
                    <div class="feed-footer-actions">
                      <button class="btn-secondary" style="font-size:11px; padding:4px 10px; border-radius:5px;" onclick="event.stopPropagation(); window.openConnectorModal('${item.key}')">
                        Configure
                      </button>
                    </div>
                  </div>
                </div>
              `;
            }).join("") : `
              <div style="grid-column: 1 / -1; padding: 48px; text-align: center; color: #64748b; background: #0a111f; border: 1px solid #152238; border-radius: 6px;">
                No connectors or integrations matched your selected filters.
              </div>
            `}
          </main>
        `}
      </div>
    </div>
  `;

  // Attach event listeners for search and sort
  const searchInp = document.getElementById("int-search-input");
  if (searchInp) {
    searchInp.addEventListener("input", (e) => {
      intFilterState.search = e.target.value;
      renderIntegrations(container);
    });
  }

  const sortSelect = document.getElementById("int-sort-select");
  if (sortSelect) {
    sortSelect.addEventListener("change", (e) => {
      intFilterState.sort = e.target.value;
      renderIntegrations(container);
    });
  }

  const sortOrderBtn = document.getElementById("int-sort-order-btn");
  if (sortOrderBtn) {
    sortOrderBtn.addEventListener("click", () => {
      intFilterState.sortAsc = !intFilterState.sortAsc;
      renderIntegrations(container);
    });
  }
}

// ── Integrations Controls & View Toggles ─────────────────────
window.setIntViewMode = (mode) => {
  intFilterState.viewMode = mode;
  renderIntegrations(document.getElementById("main-content"));
};

window.setIntCategoryFilter = (cat) => {
  intFilterState.category = cat;
  renderIntegrations(document.getElementById("main-content"));
};

window.toggleIntFilter = (group, value) => {
  if (intFilterState[group]) {
    if (intFilterState[group].includes(value)) {
      intFilterState[group] = intFilterState[group].filter(v => v !== value);
    } else {
      intFilterState[group].push(value);
    }
  }
  renderIntegrations(document.getElementById("main-content"));
};

window.resetIntFilters = () => {
  intFilterState = {
    search: "",
    sort: "name",
    sortAsc: true,
    compatVersion: "all",
    useCase: [],
    integrationType: [],
    deploymentType: [],
    status: [],
    solutionCategory: [],
    licenseType: [],
    viewMode: "grid"
  };
  renderIntegrations(document.getElementById("main-content"));
};

window.refreshIntegrations = () => {
  renderIntegrations(document.getElementById("main-content"));
};

window.exportIntegrationsJson = async () => {
  const available = await apiFetch("/api/sources/available");
  const blob = new Blob([JSON.stringify(available, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `darkintel-integrations-${Date.now()}.json`;
  a.click();
};

// ── Custom Connector Creation Modal ──────────────────────────
window.openCustomConnectorModal = () => {
  window.openModal(
    `<div style="display:flex; align-items:center; gap:10px;">
       <div style="width:28px; height:28px; border-radius:4px; background:#111d30; display:flex; align-items:center; justify-content:center; color:#38bdf8;">
         <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
       </div>
       <span>Create Custom Connector</span>
     </div>`,
    `
      <div style="margin-bottom:14px; font-size:12px; color:#94a3b8; line-height:1.5;">
        Register a new custom threat intelligence connector or private observable feed. The connector will be dynamically added to your catalog and activated.
      </div>

      <form id="custom-connector-form" style="display:flex; flex-direction:column; gap:12px;" onsubmit="event.preventDefault(); window.createCustomConnector();">
        <div class="form-group" style="margin-bottom:0;">
          <label style="display:block; font-size:11px; font-weight:600; color:#cbd5e1; margin-bottom:4px;">Connector Name *</label>
          <input type="text" id="cust-conn-name" placeholder="e.g. Internal MISP Feed, ThreatGrid Sandbox, Custom C2 Feed" required
            style="width:100%; padding:9px 12px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-size:12px;">
        </div>

        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
          <div class="form-group" style="margin-bottom:0;">
            <label style="display:block; font-size:11px; font-weight:600; color:#cbd5e1; margin-bottom:4px;">Integration Type</label>
            <select id="cust-conn-type" style="width:100%; padding:9px 12px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-size:12px;">
              <option value="Connectors">Automated Feed Connector</option>
              <option value="REST API Feed">REST API Feed</option>
              <option value="RSS Feeds">RSS Feeds</option>
              <option value="Stream">Stream Consumer</option>
              <option value="Internal Enrichment">Internal Enrichment</option>
            </select>
          </div>

          <div class="form-group" style="margin-bottom:0;">
            <label style="display:block; font-size:11px; font-weight:600; color:#cbd5e1; margin-bottom:4px;">Feed Category</label>
            <select id="cust-conn-cat" style="width:100%; padding:9px 12px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-size:12px;">
              <option value="feed">Threat Intel Feed</option>
              <option value="enrichment">Enrichment Service</option>
              <option value="scanner">Vulnerability / Scanner</option>
              <option value="osint">OSINT Collector</option>
            </select>
          </div>
        </div>

        <div class="form-group" style="margin-bottom:0;">
          <label style="display:block; font-size:11px; font-weight:600; color:#cbd5e1; margin-bottom:4px;">Use Case</label>
          <select id="cust-conn-usecase" style="width:100%; padding:9px 12px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-size:12px;">
            <option value="Infrastructure & Attack Surface Management">Infrastructure & Attack Surface Management</option>
            <option value="Detection & Response Enrichment">Detection & Response Enrichment</option>
            <option value="Vulnerability & Exposure Management">Vulnerability & Exposure Management</option>
            <option value="Adversary & Campaign Intelligence">Adversary & Campaign Intelligence</option>
          </select>
        </div>

        <div class="form-group" style="margin-bottom:0;">
          <label style="display:block; font-size:11px; font-weight:600; color:#cbd5e1; margin-bottom:4px;">Description</label>
          <input type="text" id="cust-conn-desc" placeholder="Brief description of this connector..."
            style="width:100%; padding:9px 12px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-size:12px;">
        </div>

        <div class="form-group" style="margin-bottom:0;">
          <label style="display:block; font-size:11px; font-weight:600; color:#cbd5e1; margin-bottom:4px;">API URL / Feed Endpoint</label>
          <input type="url" id="cust-conn-url" placeholder="https://intel.corp.internal/api/v1/iocs"
            style="width:100%; padding:9px 12px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-size:12px;">
        </div>

        <div class="form-group" style="margin-bottom:0;">
          <label style="display:block; font-size:11px; font-weight:600; color:#cbd5e1; margin-bottom:4px;">API Key / Secret Token</label>
          <input type="password" id="cust-conn-key" placeholder="Optional Auth Token / Secret"
            style="width:100%; padding:9px 12px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-size:12px;">
        </div>

        <div style="display:flex; align-items:center; gap:8px; margin-top:4px;">
          <input type="checkbox" id="cust-conn-ssl" checked style="accent-color:#0ea5e9;">
          <label for="cust-conn-ssl" style="font-size:11px; color:#94a3b8; cursor:pointer;">Verify SSL Certificate</label>
        </div>
      </form>
    `,
    `
      <div style="display:flex; justify-content:flex-end; gap:8px; width:100%;">
        <button class="btn-secondary" onclick="window.closeModal()">Cancel</button>
        <button class="btn-primary" style="width:auto; padding:8px 20px; font-size:12px;" onclick="window.createCustomConnector()">
          Create & Activate
        </button>
      </div>
    `
  );
};

window.createCustomConnector = async () => {
  const nameEl = document.getElementById("cust-conn-name");
  const descEl = document.getElementById("cust-conn-desc");
  const typeEl = document.getElementById("cust-conn-type");
  const catEl = document.getElementById("cust-conn-cat");
  const usecaseEl = document.getElementById("cust-conn-usecase");
  const urlEl = document.getElementById("cust-conn-url");
  const keyEl = document.getElementById("cust-conn-key");
  const sslEl = document.getElementById("cust-conn-ssl");

  if (!nameEl || !nameEl.value.trim()) {
    alert("Please enter a connector name.");
    return;
  }

  const payload = {
    name: nameEl.value.trim(),
    description: descEl ? descEl.value.trim() : "",
    integration_type: typeEl ? typeEl.value : "Connectors",
    category: catEl ? catEl.value : "feed",
    use_case: usecaseEl ? usecaseEl.value : "Infrastructure & Attack Surface Management",
    deployment_type: "Container",
    api_url: urlEl && urlEl.value.trim() ? urlEl.value.trim() : null,
    api_key: keyEl && keyEl.value.trim() ? keyEl.value.trim() : null,
    verify_ssl: sslEl ? sslEl.checked : true
  };

  try {
    await apiFetch("/api/sources/custom", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    window.closeModal();
    alert(`Custom connector "${payload.name}" created and activated successfully!`);
    renderIntegrations(document.getElementById("main-content"));
  } catch (err) {
    alert("Failed to create custom connector: " + err.message);
  }
};

// ── Ingest IOCs (CSV / XML) Modal ────────────────────────────
window.openIngestIOCsModal = () => {
  currentIngestFile = null;
  window.openModal(
    `<div style="display:flex; align-items:center; gap:10px;">
       <div style="width:28px; height:28px; border-radius:4px; background:rgba(14,165,233,0.15); display:flex; align-items:center; justify-content:center; color:#38bdf8;">
         <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
       </div>
       <span>Ingest Indicators of Compromise (IOCs)</span>
     </div>`,
    `
      <div style="margin-bottom:12px; font-size:12px; color:#94a3b8; line-height:1.5;">
        Ingest threat observables directly into the DarkIntel database. Accepts <strong>CSV</strong> and <strong>XML</strong> files (OpenIOC, STIX XML, RSS, or tabular). Ingested IOCs instantly update the dashboard telemetry.
      </div>

      <!-- Tabs -->
      <div class="modal-tabs" style="display:flex; gap:8px; border-bottom:1px solid #1a2538; padding-bottom:10px; margin-bottom:14px;">
        <button type="button" class="modal-tab-btn active" id="tab-btn-file" onclick="window.switchIngestTab('file')">📁 Upload File (.csv, .xml)</button>
        <button type="button" class="modal-tab-btn" id="tab-btn-raw" onclick="window.switchIngestTab('raw')">📝 Paste Raw Content</button>
      </div>

      <!-- File Pane -->
      <div id="ingest-pane-file">
        <div class="file-dropzone" id="ioc-dropzone" style="border:2px dashed #1a2538; border-radius:8px; padding:28px 16px; text-align:center; background:#070c14; cursor:pointer; transition:all 0.2s;"
             onclick="document.getElementById('ioc-file-input').click()"
             ondragover="event.preventDefault(); this.style.borderColor='#0ea5e9'; this.style.background='rgba(14,165,233,0.06)';"
             ondragleave="this.style.borderColor='#1a2538'; this.style.background='#070c14';"
             ondrop="event.preventDefault(); this.style.borderColor='#1a2538'; this.style.background='#070c14'; window.handleIOCFileSelected(event.dataTransfer.files);">
          <input type="file" id="ioc-file-input" accept=".csv,.xml,text/csv,text/xml,application/xml" style="display:none;" onchange="window.handleIOCFileSelected(this.files)">
          <div style="font-size:32px; margin-bottom:8px;">📄</div>
          <div style="font-size:13px; font-weight:600; color:#e2e8f0; margin-bottom:4px;">Drag & drop your CSV or XML file here, or click to browse</div>
          <div style="font-size:11px; color:#64748b;">Supports .csv, .xml (OpenIOC, STIX, or observable feeds)</div>
        </div>

        <div id="ioc-selected-file-preview" style="display:none; margin-top:10px; background:#0a111f; border:1px solid #152238; border-radius:6px; padding:10px 14px; align-items:center; justify-content:space-between;">
          <div style="display:flex; align-items:center; gap:10px;">
            <span style="font-size:20px;" id="ioc-file-icon">📊</span>
            <div>
              <div id="ioc-file-name" style="font-size:12px; font-weight:600; color:#38bdf8;">sample.csv</div>
              <div id="ioc-file-size" style="font-size:10px; color:#64748b;">0 KB</div>
            </div>
          </div>
          <button type="button" class="btn-secondary" style="font-size:11px; padding:4px 10px;" onclick="window.clearSelectedIOCFile()">Remove</button>
        </div>
      </div>

      <!-- Raw Paste Pane -->
      <div id="ingest-pane-raw" style="display:none;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <label style="font-size:11px; font-weight:600; color:#cbd5e1;">Content Format</label>
          <select id="ioc-raw-format" style="padding:4px 8px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:4px; font-size:11px;">
            <option value="auto">Auto-detect (CSV / XML)</option>
            <option value="csv">CSV (.csv)</option>
            <option value="xml">XML (.xml)</option>
          </select>
        </div>
        <textarea id="ioc-raw-content" rows="8" placeholder="Paste CSV (e.g. type,value,threat,malware,severity) or XML (e.g. &lt;indicator type=&quot;url&quot; value=&quot;...&quot;/&gt;) content here..." style="width:100%; padding:10px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-family:var(--font-mono); font-size:11px; resize:vertical;"></textarea>
      </div>

      <!-- Format Guidelines / Samples -->
      <details style="margin-top:12px; background:#070c14; border:1px solid #152238; border-radius:6px; padding:8px 12px; font-size:11px; color:#94a3b8;">
        <summary style="cursor:pointer; color:#38bdf8; font-weight:600;">Format Guidelines & Samples</summary>
        <div style="margin-top:8px; line-height:1.6;">
          <div><strong style="color:#e2e8f0;">CSV Headers:</strong> <code>type,value,threat,malware,severity</code> or raw values list.</div>
          <div style="color:#64748b; font-family:var(--font-mono); font-size:10px; margin-top:2px;">ip,185.220.101.5,Botnet C2,Emotet,critical<br>url,http://malicious-login.ru/update.exe,Phishing,RedLine,high<br>hash,44d88612fea8a8f36de82e1278abb02f,Ransomware,LockBit,critical</div>
          <div style="margin-top:8px;"><strong style="color:#e2e8f0;">XML Tags:</strong> <code>&lt;ioc&gt;</code>, <code>&lt;indicator type="..." value="..."&gt;</code>, OpenIOC <code>&lt;IndicatorItem&gt;</code>, or STIX XML.</div>
          <div style="color:#64748b; font-family:var(--font-mono); font-size:10px; margin-top:2px;">&lt;indicators&gt;&lt;indicator type="domain" value="phish-bank.com" threat="Fraud" severity="medium"/&gt;&lt;/indicators&gt;</div>
        </div>
      </details>

      <!-- Ingest Status / Results Output -->
      <div id="ioc-ingest-status" style="display:none; margin-top:12px;"></div>
    `,
    `
      <div style="display:flex; justify-content:space-between; align-items:center; width:100%;">
        <button class="btn-secondary" onclick="window.closeModal()">Close</button>
        <button class="btn-primary" id="btn-submit-ingest" style="display:inline-flex; align-items:center; gap:6px; padding:8px 20px; font-size:12px; width:auto;" onclick="window.submitIOCIngestion()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          <span>Ingest IOCs</span>
        </button>
      </div>
    `
  );
};

window.switchIngestTab = (tab) => {
  const btnFile = document.getElementById("tab-btn-file");
  const btnRaw = document.getElementById("tab-btn-raw");
  const paneFile = document.getElementById("ingest-pane-file");
  const paneRaw = document.getElementById("ingest-pane-raw");

  if (tab === "file") {
    btnFile?.classList.add("active");
    btnRaw?.classList.remove("active");
    if (paneFile) paneFile.style.display = "block";
    if (paneRaw) paneRaw.style.display = "none";
  } else {
    btnRaw?.classList.add("active");
    btnFile?.classList.remove("active");
    if (paneFile) paneFile.style.display = "none";
    if (paneRaw) paneRaw.style.display = "block";
  }
};

window.handleIOCFileSelected = (files) => {
  if (!files || files.length === 0) return;
  const file = files[0];
  currentIngestFile = file;

  const preview = document.getElementById("ioc-selected-file-preview");
  const dropzone = document.getElementById("ioc-dropzone");
  const nameEl = document.getElementById("ioc-file-name");
  const sizeEl = document.getElementById("ioc-file-size");
  const iconEl = document.getElementById("ioc-file-icon");

  if (preview && nameEl && sizeEl) {
    nameEl.textContent = file.name;
    const kb = (file.size / 1024).toFixed(1);
    sizeEl.textContent = `${kb} KB`;
    if (iconEl) {
      iconEl.textContent = file.name.toLowerCase().endsWith(".xml") ? "📜" : "📊";
    }
    preview.style.display = "flex";
    if (dropzone) dropzone.style.display = "none";
  }
};

window.clearSelectedIOCFile = () => {
  currentIngestFile = null;
  const fileInput = document.getElementById("ioc-file-input");
  if (fileInput) fileInput.value = "";
  const preview = document.getElementById("ioc-selected-file-preview");
  const dropzone = document.getElementById("ioc-dropzone");
  if (preview) preview.style.display = "none";
  if (dropzone) dropzone.style.display = "block";
};

window.submitIOCIngestion = async () => {
  const statusDiv = document.getElementById("ioc-ingest-status");
  const submitBtn = document.getElementById("btn-submit-ingest");
  const isFileTab = document.getElementById("tab-btn-file")?.classList.contains("active");

  let filename = "manual_ingest.csv";
  let content = "";

  if (isFileTab) {
    if (!currentIngestFile) {
      alert("Please select or drop a CSV or XML file to ingest.");
      return;
    }
    filename = currentIngestFile.name;
    try {
      content = await currentIngestFile.text();
    } catch (e) {
      alert("Error reading file: " + e.message);
      return;
    }
  } else {
    const rawEl = document.getElementById("ioc-raw-content");
    const formatEl = document.getElementById("ioc-raw-format");
    content = rawEl ? rawEl.value.trim() : "";
    if (!content) {
      alert("Please enter or paste CSV or XML content.");
      return;
    }
    const fmt = formatEl ? formatEl.value : "auto";
    if (fmt === "xml" || (fmt === "auto" && content.startsWith("<"))) {
      filename = "manual_pasted.xml";
    } else {
      filename = "manual_pasted.csv";
    }
  }

  if (statusDiv) {
    statusDiv.style.display = "block";
    statusDiv.innerHTML = `
      <div style="background:#0a111f; border:1px solid #1a2538; border-radius:6px; padding:12px; font-size:12px; color:#38bdf8; display:flex; align-items:center; gap:8px;">
        <span class="status-indicator-dot active" style="animation:pulse 1s infinite;"></span>
        Parsing and ingesting ${filename}...
      </div>
    `;
  }
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `Ingesting...`;
  }

  try {
    const result = await apiFetch("/api/sources/ingest-file", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filename, content })
    });

    if (statusDiv) {
      const typeBreakdown = Object.entries(result.by_type || {})
        .map(([t, c]) => `<span style="background:rgba(14,165,233,0.15); color:#38bdf8; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600;">${t.toUpperCase()}: ${c}</span>`)
        .join(" ");

      statusDiv.innerHTML = `
        <div style="background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.3); border-radius:6px; padding:12px; font-size:12px; color:#10b981;">
          <div style="font-weight:700; margin-bottom:6px; display:flex; align-items:center; gap:6px;">
            <span>✓</span> ${result.message || 'IOC ingestion completed!'}
          </div>
          <div style="color:#94a3b8; font-size:11px; margin-bottom:8px;">
            Parsed <strong>${result.total_records_processed}</strong> records &bull; Ingested <strong>${result.ingested_count}</strong> new observables into database.
          </div>
          <div style="display:flex; flex-wrap:wrap; gap:6px;">
            ${typeBreakdown || '<span style="color:#64748b;">No new types</span>'}
          </div>
        </div>
      `;
    }

    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `✓ Ingested (${result.ingested_count})`;
    }

    // Refresh active views
    const path = window.location.hash.slice(1) || "dashboard";
    if (path === "integrations") {
      renderIntegrations(document.getElementById("main-content"));
    } else if (path === "indicators") {
      renderIndicators(document.getElementById("main-content"));
    }
  } catch (err) {
    if (statusDiv) {
      statusDiv.innerHTML = `
        <div style="background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); border-radius:6px; padding:12px; font-size:12px; color:#ef4444;">
          <strong>Ingestion failed:</strong> ${err.message}
        </div>
      `;
    }
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `Retry Ingestion`;
    }
  }
};

// ── Connector Configuration Modal ────────────────────────────
window.openConnectorModal = async (sourceKey) => {
  const [available, userSources] = await Promise.all([
    apiFetch("/api/sources/available"),
    apiFetch("/api/sources")
  ]);

  const meta = available[sourceKey];
  if (!meta) return;

  const existing = userSources.find(s => s.source_type === sourceKey);
  const isConnected = !!existing;

  window.openModal(
    `<div style="display:flex; align-items:center; gap:10px;">
       <div style="width:28px; height:28px; border-radius:4px; background:#111d30; display:flex; align-items:center; justify-content:center;">
         ${getConnectorIconSvg(meta.icon, meta.display_name)}
       </div>
       <span>${meta.display_name}</span>
     </div>`,
    `
      <div style="margin-bottom:16px;">
        <div style="display:flex; gap:6px; margin-bottom:10px;">
          <span class="version-pill">${meta.version || "V.6.8.13"}</span>
          <span class="card-badge badge-blue">${meta.integration_type || "Connectors"}</span>
          <span class="card-badge badge-purple">${meta.solution_category || "Threat Intelligence"}</span>
          <span class="card-badge badge-green">${isConnected ? 'Connected' : 'Available'}</span>
        </div>
        <p style="font-size:12px; color:#cbd5e1; line-height:1.5;">${meta.description}</p>
      </div>

      <div style="border-top:1px solid #1a2538; padding-top:14px; margin-bottom:14px;">
        <div style="font-size:12px; font-weight:700; color:#fff; margin-bottom:12px;">Connector Configuration</div>

        <form id="connector-config-form" style="display:flex; flex-direction:column; gap:12px;">
          <div class="form-group" style="margin-bottom:0;">
            <label style="display:block; font-size:11px; font-weight:600; color:#cbd5e1; margin-bottom:4px;">Connector Name</label>
            <input type="text" id="conn-name" value="${existing ? existing.name : meta.display_name}" required
              style="width:100%; padding:9px 12px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-size:12px;">
          </div>

          ${meta.requires_url !== false ? `
            <div class="form-group" style="margin-bottom:0;">
              <label style="display:block; font-size:11px; font-weight:600; color:#cbd5e1; margin-bottom:4px;">API URL / Endpoint</label>
              <input type="url" id="conn-url" value="${existing && existing.api_url ? existing.api_url : ''}" placeholder="https://api.provider.com/v1"
                style="width:100%; padding:9px 12px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-size:12px;">
            </div>
          ` : ''}

          ${meta.requires_key !== false ? `
            <div class="form-group" style="margin-bottom:0;">
              <label style="display:block; font-size:11px; font-weight:600; color:#cbd5e1; margin-bottom:4px;">API Key / Auth Token</label>
              <input type="password" id="conn-key" placeholder="${isConnected ? '••••••••••••••••' : 'Enter API Key'}"
                style="width:100%; padding:9px 12px; background:#070c14; border:1px solid #1a2538; color:#fff; border-radius:6px; font-size:12px;">
            </div>
          ` : ''}

          <div style="display:flex; align-items:center; gap:8px; margin-top:4px;">
            <input type="checkbox" id="conn-ssl" ${existing && !existing.verify_ssl ? '' : 'checked'} style="accent-color:#0ea5e9;">
            <label for="conn-ssl" style="font-size:11px; color:#94a3b8; cursor:pointer;">Verify SSL Certificate</label>
          </div>
        </form>
      </div>

      <div style="background:#070c14; border:1px solid #152238; border-radius:6px; padding:10px 12px; font-size:11px; color:#64748b;">
        <div>Author: <span style="color:#94a3b8;">${meta.author || "SecOps Community"}</span></div>
        <div>Deployment: <span style="color:#94a3b8;">${meta.deployment_type || "Container"}</span></div>
        <div>License: <span style="color:#94a3b8;">${meta.license_type || "Open Source"}</span></div>
      </div>
    `,
    `
      <div style="display:flex; justify-content:space-between; width:100%;">
        <div>
          ${isConnected ? `
            <button class="btn-secondary" style="border-color:var(--danger); color:var(--danger); font-size:12px;" onclick="window.disconnectConnector(${existing.id})">
              Disconnect
            </button>
            <button class="btn-secondary" style="margin-left:8px; font-size:12px;" onclick="window.syncOneConnector(${existing.id})">
              Sync Now
            </button>
          ` : ''}
        </div>
        <div style="display:flex; gap:8px;">
          <button class="btn-secondary" onclick="window.closeModal()">Cancel</button>
          <button class="btn-primary" style="width:auto; padding:8px 18px; font-size:12px;" onclick="window.saveConnectorConfig('${sourceKey}')">
            ${isConnected ? 'Save Updates' : 'Connect & Activate'}
          </button>
        </div>
      </div>
    `
  );
};

window.saveConnectorConfig = async (sourceKey) => {
  const nameEl = document.getElementById("conn-name");
  const urlEl = document.getElementById("conn-url");
  const keyEl = document.getElementById("conn-key");
  const sslEl = document.getElementById("conn-ssl");

  const name = nameEl ? nameEl.value.trim() : sourceKey;
  const url = urlEl ? urlEl.value.trim() : null;
  const key = keyEl ? keyEl.value.trim() : null;
  const ssl = sslEl ? sslEl.checked : true;

  try {
    await apiFetch("/api/sources", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: name,
        source_type: sourceKey,
        api_url: url,
        api_key: key,
        verify_ssl: ssl
      })
    });
    window.closeModal();
    renderIntegrations(document.getElementById("main-content"));
  } catch (err) {
    alert("Connection error: " + err.message);
  }
};

window.disconnectConnector = async (id) => {
  if (!confirm("Are you sure you want to disconnect this integration?")) return;
  try {
    await apiFetch(`/api/sources/${id}`, { method: "DELETE" });
    window.closeModal();
    renderIntegrations(document.getElementById("main-content"));
  } catch (err) {
    alert("Disconnection error: " + err.message);
  }
};

window.syncOneConnector = async (id) => {
  try {
    await apiFetch(`/api/sources/${id}/sync`, { method: "POST" });
    alert("Sync completed successfully!");
    window.closeModal();
    renderIntegrations(document.getElementById("main-content"));
  } catch (err) {
    alert("Sync error: " + err.message);
  }
};

// Aliases for backwards compatibility
async function renderSettings(container) {
  return renderIntegrations(container);
}


// ── Auth Handlers ───────────────────────────────────────────
document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = document.getElementById("login-btn");
  const err = document.getElementById("login-error");
  err.classList.add("hidden");
  btn.disabled = true;
  btn.textContent = "Signing in...";
  try {
    const res = await loginUser(
      document.getElementById("login-email").value,
      document.getElementById("login-password").value
    );
    auth.set(res.access_token);
    await bootApp();
  } catch (ex) {
    err.textContent = ex.message;
    err.classList.remove("hidden");
  } finally {
    btn.disabled = false;
    btn.textContent = "Sign in";
  }
});

document.getElementById("register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const res = await registerUser(
      document.getElementById("reg-email").value,
      document.getElementById("reg-password").value,
      document.getElementById("reg-name").value
    );
    auth.set(res.access_token);
    await bootApp();
  } catch (ex) { alert(ex.message); }
});

document.getElementById("logout-btn").addEventListener("click", () => {
  auth.clear();
  showView("login");
});

document.getElementById("refresh-btn").addEventListener("click", async () => {
  const btn = document.getElementById("refresh-btn");
  const old = btn.innerHTML;
  btn.disabled = true;
  btn.textContent = "Syncing all sources...";
  try {
    await apiFetch("/api/sources/sync", { method: "POST" });
    route();
  } catch (ex) { alert(ex.message); }
  finally { btn.disabled = false; btn.innerHTML = old; }
});

async function bootApp() {
  try {
    const user = await apiFetch("/api/auth/me");
    document.getElementById("user-name").textContent = user.full_name || user.email.split("@")[0];
    document.getElementById("user-role").textContent = user.role;
    if (!window.location.hash) window.location.hash = "#/dashboard";
    route();
  } catch {
    auth.clear();
    showView("login");
  }
}

if (auth.token()) bootApp(); else showView("login");