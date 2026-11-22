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
  const path = window.location.hash.slice(2) || "dashboard";

  document.querySelectorAll(".nav-item").forEach((el) => {
    el.classList.remove("active");
    if (el.dataset.page === path) el.classList.add("active");
  });

  const content = document.getElementById("main-content");
  content.innerHTML = '<div style="padding:40px;text-align:center;color:var(--accent)">Loading...</div>';

  try {
    if (path === "dashboard") {
      document.getElementById("page-title").textContent = "Dashboard";
      await renderDashboard(content);
    } else if (path === "indicators") {
      document.getElementById("page-title").textContent = "Indicators";
      await renderIndicators(content);
    } else if (path === "threat-intel") {
      document.getElementById("page-title").textContent = "Threat Intel";
      await renderThreatIntel(content);
    } else if (path === "search") {
      document.getElementById("page-title").textContent = "Indicator Search";
      await renderSearch(content);
    } else if (path === "settings") {
      document.getElementById("page-title").textContent = "Settings";
      await renderSettings(content);
    }
  } catch (err) {
    content.innerHTML = `<div style="color:var(--danger);padding:20px">${err.message}</div>`;
  }
}

// ── Dashboard 
let dashState = {
  timeframe: 7, // Days
  widgets: ["timeline", "type", "source", "malware"] // Default visible
};


async function renderDashboard(container) {
  // 1. Render Layout & Controls
  container.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:24px;">
      <div style="display:flex; gap:8px;">
        <button class="btn-secondary ${dashState.timeframe === 1 ? 'active' : ''}" onclick="window.setTimeframe(1)">24h</button>
        <button class="btn-secondary ${dashState.timeframe === 7 ? 'active' : ''}" onclick="window.setTimeframe(7)">7d</button>
        <button class="btn-secondary ${dashState.timeframe === 30 ? 'active' : ''}" onclick="window.setTimeframe(30)">30d</button>
        <button class="btn-secondary ${dashState.timeframe === 0 ? 'active' : ''}" onclick="window.setTimeframe(0)">All Time</button>
      </div>
      
      <div style="position:relative;">
        <button class="btn-secondary" onclick="document.getElementById('widget-menu').classList.toggle('hidden')">+ Add Widget</button>
        <div id="widget-menu" class="hidden" style="position:absolute; right:0; top:40px; background:var(--panel); border:1px solid var(--border); border-radius:4px; padding:8px; z-index:10; min-width:150px;">
          ${renderWidgetMenuItem('timeline', 'Line Chart')}
          ${renderWidgetMenuItem('type', 'Pie Chart')}
          ${renderWidgetMenuItem('source', 'Bar Chart')}
          ${renderWidgetMenuItem('malware', 'Table')}
        </div>
      </div>
    </div>
    
    <div class="stats-grid" id="kpi-cards">
      <div class="stat-card"><div class="stat-label">Loading...</div></div>
    </div>
    
    <div id="widget-grid" style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
      <!-- Widgets will be injected here -->
    </div>
  `;

  // 2. Fetch Data
  const stats = await apiFetch(`/api/stats`); // Always global stats for KPIs
  const charts = await apiFetch(`/api/stats/charts?days=${dashState.timeframe}`);

  // Update KPIs
  document.getElementById("kpi-cards").innerHTML = `
    <div class="stat-card"><div class="stat-label">Total Indicators</div><div class="stat-value accent">${stats.total_indicators || 0}</div></div>
    <div class="stat-card"><div class="stat-label">Critical Threats (≥8)</div><div class="stat-value danger">${stats.high_severity || 0}</div></div>
    <div class="stat-card"><div class="stat-label">Intel Events</div><div class="stat-value warn">${stats.total_events || 0}</div></div>
    <div class="stat-card"><div class="stat-label">Active Sources</div><div class="stat-value">${stats.active_sources || 0}</div></div>
  `;

  // 3. Render Widgets
  const grid = document.getElementById("widget-grid");
  grid.innerHTML = "";
  
  // Destroy old charts
  Object.values(chartInstances).forEach(c => c.destroy());
  chartInstances = {};

  dashState.widgets.forEach(w => {
    const div = document.createElement("div");
    div.className = "stat-card";
    div.style.position = "relative";

    // Add close button
    div.innerHTML = `
      <button style="position:absolute; top:10px; right:10px; background:none; border:none; color:var(--fg-mute); cursor:pointer;" onclick="window.removeWidget('${w}')">✕</button>
      <div class="stat-label" style="margin-bottom:16px;">${getWidgetTitle(w)}</div>
      <div id="widget-content-${w}" style="height:250px; width:100%; position:relative;"></div>
    `;
    grid.appendChild(div);
  });

  // Render chart canvases or tables inside the widget divs
  setTimeout(() => {
    if (dashState.widgets.includes("timeline")) renderTimelineChart(charts.timeline);
    if (dashState.widgets.includes("type")) renderTypeChart(charts.by_type);
    if (dashState.widgets.includes("source")) renderSourceChart(charts.by_source);
    if (dashState.widgets.includes("malware")) renderMalwareTable(charts.top_malware);
  }, 50);
}

// Helpers
function renderWidgetMenuItem(id, name) {
  const active = dashState.widgets.includes(id);
  return `<div onclick="window.toggleWidget('${id}')" style="padding:8px; font-size:12px; cursor:pointer; display:flex; justify-content:space-between; color:${active ? 'var(--accent)' : 'var(--fg)'}">
    ${name} ${active ? '✓' : ''}
  </div>`;
}

function getWidgetTitle(w) {
  return { timeline: "Threat Velocity", type: "IOC Distribution", source: "Indicators by Source", malware: "Top Malware" }[w];
}

window.setTimeframe = (days) => {
  dashState.timeframe = days;
  renderDashboard(document.getElementById("main-content"));
};

window.toggleWidget = (id) => {
  if (dashState.widgets.includes(id)) {
    dashState.widgets = dashState.widgets.filter(w => w !== id);
  } else {
    dashState.widgets.push(id);
  }
  renderDashboard(document.getElementById("main-content"));
};

window.removeWidget = (id) => window.toggleWidget(id);

// ── Chart Renderers ─────────────────────────────────────────
// ── Chart Renderers ─────────────────────────────────────────
function renderTimelineChart(data) {
  const container = document.getElementById("widget-content-timeline");
  if (!container) return;
  container.innerHTML = `<canvas id="chart-timeline"></canvas>`;
  
  const ctx = document.getElementById("chart-timeline").getContext("2d");
  chartInstances.timeline = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.map(d => d.date),
      datasets: [{
        label: 'New IOCs',
        data: data.map(d => d.count),
        borderColor: '#0EA5E9',
        backgroundColor: 'rgba(14,165,233,0.1)',
        fill: true, 
        tension: 0.4,
        pointRadius: 2
      }]
    },
    options: { 
      responsive: true, 
      maintainAspectRatio: false, 
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } }, x: { grid: { display: false } } }
    }
  });
}

function renderTypeChart(data) {
  const container = document.getElementById("widget-content-type");
  if (!container) return;
  container.innerHTML = `<canvas id="chart-type"></canvas>`;
  
  const ctx = document.getElementById("chart-type").getContext("2d");
  chartInstances.type = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: data.map(d => d.name),
      datasets: [{ 
        data: data.map(d => d.count), 
        backgroundColor: ['#EF4444', '#F59E0B', '#0EA5E9', '#10B981', '#8B5CF6'],
        borderWidth: 0
      }]
    },
    options: { 
      responsive: true, 
      maintainAspectRatio: false, 
      cutout: '65%', 
      plugins: { legend: { position: 'right', labels: { boxWidth: 10, font: { size: 11 } } } } 
    }
  });
}

function renderSourceChart(data) {
  const container = document.getElementById("widget-content-source");
  if (!container) return;
  container.innerHTML = `<canvas id="chart-source"></canvas>`;
  
  const ctx = document.getElementById("chart-source").getContext("2d");
  chartInstances.source = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.map(d => d.name),
      datasets: [{ 
        data: data.map(d => d.count), 
        backgroundColor: '#8B5CF6', 
        borderRadius: 4 
      }]
    },
    options: { 
      responsive: true, 
      maintainAspectRatio: false, 
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } }, x: { grid: { display: false } } }
    }
  });
}

function renderMalwareTable(data) {
  const container = document.getElementById("widget-content-malware");
  if (!container) return;
  
  if (!data || data.length === 0) {
    container.innerHTML = '<div class="mute" style="margin:auto;">No malware data for this timeframe.</div>';
    return;
  }
  
  container.innerHTML = `
    <div style="width:100%; height:100%; overflow-y:auto;">
      <table style="width:100%; font-size:12px; border-collapse:collapse;">
        <thead>
          <tr>
            <th style="text-align:left; padding:8px 0; border-bottom:1px solid var(--border); color:var(--fg-mute);">Family</th>
            <th style="text-align:right; padding:8px 0; border-bottom:1px solid var(--border); color:var(--fg-mute);">Count</th>
          </tr>
        </thead>
        <tbody>
          ${data.map(d => `
            <tr>
              <td style="padding:8px 0; border-bottom:1px solid var(--border);">${d.name}</td>
              <td style="text-align:right; border-bottom:1px solid var(--border); font-family:var(--font-mono);">${d.count}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

// ── Indicators ──────────────────────────────────────────────
async function renderIndicators(container) {
  // Fetch up to 50,000 IOCs
  const iocs = await apiFetch("/api/iocs?limit=50000");

  container.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <div class="mute" style="font-size: 12px;">
        Showing <strong style="color:var(--fg);">${iocs.length}</strong> Indicators
      </div>
      <input type="text" id="ioc-search" placeholder="Filter by value or malware..." 
             style="width: 300px; padding: 8px; background: var(--panel); border: 1px solid var(--border); color: #fff; border-radius: 4px;">
    </div>
    <div class="table-container" id="ioc-table-container">
      ${renderIOCTable(iocs)}
    </div>
  `;

  // Add live filtering
  document.getElementById("ioc-search").addEventListener("input", (e) => {
    const q = e.target.value.toLowerCase();
    const filtered = iocs.filter(i => 
      i.value.toLowerCase().includes(q) || 
      (i.malware && i.malware.toLowerCase().includes(q)) ||
      (i.threat_type && i.threat_type.toLowerCase().includes(q))
    );
    document.getElementById("ioc-table-container").innerHTML = renderIOCTable(filtered);
  });
}

function renderIOCTable(iocs) {
  if (!iocs || iocs.length === 0) {
    return '<div class="mute" style="text-align:center; padding: 24px;">No indicators found.</div>';
  }
  return `
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Type</th>
          <th>Value</th>
          <th>Threat</th>
          <th>Malware</th>
        </tr>
      </thead>
      <tbody>
        ${iocs.map(ioc => {
          const sev = ioc.severity >= 8 ? "high" : ioc.severity >= 5 ? "med" : "low";
          return `<tr>
            <td><span class="badge sev-${sev}">${ioc.severity.toFixed(1)}</span></td>
            <td><span class="badge type ${ioc.ioc_type}">${ioc.ioc_type}</span></td>
            <td class="trunc mono" title="${ioc.value}">${ioc.value}</td>
            <td style="color:var(--fg-dim)">${ioc.threat_type || "—"}</td>
            <td>${ioc.malware ? `<span class="badge malware">${ioc.malware}</span>` : '<span class="mute">—</span>'}</td>
          </tr>`;
        }).join("")}
      </tbody>
    </table>
  `;
}

// ── Threat Intel ────────────────────────────────────────────
async function renderThreatIntel(container, page = 1) {
  const data = await apiFetch(`/api/events?page=${page}&limit=20`);
  if (!data.events || data.events.length === 0) {
    container.innerHTML = '<div class="mute" style="padding:40px;text-align:center;">No events found. Add a source and sync.</div>';
    return;
  }
  const totalPages = Math.ceil(data.total / data.limit);
  container.innerHTML = `
    <div class="table-container">
      <table>
        <thead><tr><th>Threat</th><th>Date</th><th>Org</th><th>Event Info & Galaxies</th><th>Attr.</th><th style="text-align:center;">View</th></tr></thead>
        <tbody>
          ${data.events.map(ev => {
            const sev = ev.threat_level === "1" ? "high" : ev.threat_level === "2" ? "med" : "low";
            return `
            <tr>
              <td><span class="badge sev-${sev}">${ev.threat_level === "1" ? "HIGH" : ev.threat_level === "2" ? "MED" : "LOW"}</span></td>
              <td class="mono" style="color:var(--fg-dim)">${ev.date || "—"}</td>
              <td>${ev.org || "—"}</td>
              <td>
                <div style="font-weight:500;margin-bottom:6px;">${ev.title}</div>
                <div style="display:flex;gap:6px;flex-wrap:wrap;">
                  ${(ev.galaxies || []).map(g => `<span class="badge" style="background:rgba(14,165,233,0.1);color:var(--accent);border-color:rgba(14,165,233,0.3);">⭐ ${g}</span>`).join('')}
                </div>
              </td>
              <td class="mono">${ev.attr_count || 0}</td>
              <td style="text-align:center;"><button class="btn-secondary" onclick="window.toggleEvent(${ev.id})">View</button></td>
            </tr>
            <tr id="ev-details-${ev.id}" class="hidden"><td colspan="6" style="padding:0;background:var(--bg);">
              <div style="padding:24px;" id="ev-container-${ev.id}"><div class="mute">Loading...</div></div>
            </td></tr>`;
          }).join("")}
        </tbody>
      </table>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <div class="mute">Page ${data.page} of ${totalPages}</div>
      <div style="display:flex;gap:8px;">
        <button class="btn-secondary" ${page === 1 ? 'disabled' : ''} onclick="window.renderIntelPage(${page - 1})">← Prev</button>
        <button class="btn-secondary" ${page === totalPages ? 'disabled' : ''} onclick="window.renderIntelPage(${page + 1})">Next →</button>
      </div>
    </div>
  `;
}

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
    <div style="max-width:900px;">
      <div style="display:flex; gap:8px; margin-bottom:24px;">
        <input type="text" id="search-term" placeholder="Enter IP, domain, hash, or email..." 
               style="flex:1; padding:12px; background:var(--panel); border:1px solid var(--border); color:#fff; border-radius:4px;">
        <button id="search-btn" class="btn-primary" style="width:120px;">Search</button>
      </div>
      <div id="search-results"></div>
    </div>
  `;

  document.getElementById("search-btn").addEventListener("click", async () => {
    const term = document.getElementById("search-term").value.trim();
    if (!term) return;
    
    const resultsDiv = document.getElementById("search-results");
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
        resultsDiv.innerHTML = '<div class="mute">No providers configured. Add API keys in Settings.</div>';
        return;
      }
      
      resultsDiv.innerHTML = `
        <div style="margin-bottom:24px; border-bottom:1px solid var(--border); padding-bottom:12px;">
          <h2 style="font-size:18px;">Search Results for <span class="mono text-accent">${data.term}</span></h2>
        </div>
        ${data.results.map(r => renderProviderResult(r)).join("")}
      `;
    } catch (err) {
      resultsDiv.innerHTML = `<div style="color:var(--danger);">${err.message}</div>`;
    }
  });
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
// ── Settings ────────────────────────────────────────────────
async function renderSettings(container) {
  const [available, sources] = await Promise.all([
    apiFetch("/api/sources/available"),
    apiFetch("/api/sources"),
  ]);

  const feedEntries   = Object.entries(available).filter(([, m]) => m.category === "feed");
  const searchEntries = Object.entries(available).filter(([, m]) => m.category === "search");

  const typeOptions = `
    <optgroup label="Feed Sources (run on Sync)">
      ${feedEntries.map(([k, m]) => `<option value="${k}">${m.display_name}</option>`).join("")}
    </optgroup>
    <optgroup label="Search Sources (used on Search page)">
      ${searchEntries.map(([k, m]) => `<option value="${k}">${m.display_name}</option>`).join("")}
    </optgroup>
  `;

  container.innerHTML = `
    <div style="max-width:1000px;">
      <div class="table-container" style="margin-bottom:24px;">
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Category</th><th>URL</th><th>Last Sync</th><th>Actions</th></tr></thead>
          <tbody>
            ${sources.map(s => {
              const meta = available[s.source_type] || {};
              const isFeed = meta.category === "feed";
              return `<tr>
                <td>${s.name}</td>
                <td><span class="badge source">${s.source_type}</span></td>
                <td class="mute" style="font-size:11px;">${meta.category || "—"}</td>
                <td class="mono">${s.api_url || "—"}</td>
                <td class="mono" style="color:var(--fg-dim)">${isFeed && s.last_sync ? new Date(s.last_sync).toLocaleString() : "—"}</td>
                <td style="display:flex;gap:6px;">
                  ${isFeed ? `<button class="btn-secondary" onclick="window.syncSrc(${s.id})">Sync</button>` : `<span class="mute" style="font-size:11px;padding:6px;">Search-only</span>`}
                  <button class="btn-secondary" style="border-color:var(--danger);color:var(--danger)" onclick="window.delSrc(${s.id})">Remove</button>
                </td>
              </tr>`;
            }).join("") || '<tr><td colspan="6" class="mute" style="text-align:center;padding:24px;">No sources configured.</td></tr>'}
          </tbody>
        </table>
      </div>
      <div class="stat-card" style="padding:24px;">
        <h3 style="margin-bottom:16px;">Add Source</h3>
        <form id="add-src" style="display:flex;flex-direction:column;gap:12px;">
          <input type="text" id="src-name" placeholder="Display Name" required style="padding:10px;background:var(--bg);border:1px solid var(--border);color:#fff;border-radius:4px;">
          <select id="src-type" style="padding:10px;background:var(--bg);border:1px solid var(--border);color:#fff;border-radius:4px;">${typeOptions}</select>
          <input type="url" id="src-url" placeholder="API URL" style="padding:10px;background:var(--bg);border:1px solid var(--border);color:#fff;border-radius:4px;">
          <input type="password" id="src-key" placeholder="API Key" style="padding:10px;background:var(--bg);border:1px solid var(--border);color:#fff;border-radius:4px;">
          <label style="display:flex;gap:8px;font-size:12px;color:var(--fg-dim);align-items:center;">
            <input type="checkbox" id="src-ssl" checked> Verify SSL
          </label>
          <button type="submit" class="btn-primary">Connect Source</button>
        </form>
      </div>
    </div>
  `;

  const refresh = () => {
    const m = available[document.getElementById("src-type").value];
    document.getElementById("src-url").style.display = m.requires_url ? "" : "none";
    document.getElementById("src-key").style.display = m.requires_key ? "" : "none";
    document.getElementById("src-ssl").parentElement.style.display = m.requires_ssl_toggle ? "flex" : "none";
  };
  document.getElementById("src-type").addEventListener("change", refresh);
  refresh();

  document.getElementById("add-src").addEventListener("submit", async (e) => {
    e.preventDefault();
    const m = available[document.getElementById("src-type").value];
    try {
      await apiFetch("/api/sources", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: document.getElementById("src-name").value,
          source_type: document.getElementById("src-type").value,
          api_url: m.requires_url ? document.getElementById("src-url").value : null,
          api_key: m.requires_key ? document.getElementById("src-key").value : null,
          verify_ssl: document.getElementById("src-ssl").checked,
        }),
      });
      renderSettings(container);
    } catch (ex) { alert(ex.message); }
  });
}

window.syncSrc = async (id) => {
  try {
    await apiFetch(`/api/sources/${id}/sync`, { method: "POST" });
    route();
  } catch (ex) { alert(ex.message); }
};

window.delSrc = async (id) => {
  if (!confirm("Delete this source and all its data?")) return;
  await apiFetch(`/api/sources/${id}`, { method: "DELETE" });
  route();
};

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