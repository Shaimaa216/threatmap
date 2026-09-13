let map = null;
let riskChart = null;
let lastBulk = [];

const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? "Not available").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
const val = (v) => v === null || v === undefined || v === "" || v === "-" ? "Not available" : v;

function showToast(message) {
  const el = $("toast"); el.textContent = message; el.style.display = "block";
  setTimeout(() => el.style.display = "none", 2600);
}
function showError(id, message) {
  const el = $(id); el.textContent = message; el.classList.remove("hidden");
}
function clearError(id) { $(id).classList.add("hidden"); }

async function api(url, options={}) {
  const res = await fetch(url, options);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || "Request failed.");
  return body;
}

function navigate(page) {
  document.querySelectorAll(".page").forEach(x => x.classList.remove("active"));
  const target = $("page-" + page) || $("page-dashboard");
  target.classList.add("active");
  document.querySelectorAll(".sidebar nav a").forEach(x => x.classList.toggle("active", x.dataset.page === page));
  $("page-title").textContent = page.charAt(0).toUpperCase() + page.slice(1);
  if (page === "dashboard") loadDashboard();
  if (page === "history") loadHistory();
}
window.addEventListener("hashchange", () => navigate(location.hash.slice(1) || "dashboard"));

async function loadDashboard() {
  try {
    const d = await api("/api/dashboard");
    $("stat-total").textContent = d.total;
    $("stat-high").textContent = d.high;
    $("stat-medium").textContent = d.medium;
    $("stat-low").textContent = d.low;
    const ctx = $("risk-chart").getContext("2d");
    if (riskChart) riskChart.destroy();
    riskChart = new Chart(ctx, {type:"doughnut",data:{labels:["Low","Medium","High"],datasets:[{data:[d.low,d.medium,d.high]}]},options:{plugins:{legend:{labels:{color:"#9fb1bd"}}}}});
    $("recent-list").innerHTML = d.recent.length ? d.recent.map(r => `<div class="activity-row"><div><strong>${esc(r.ip)}</strong><small>${esc(r.country || "—")} · ${esc(r.city || "—")}</small></div><span class="badge ${r.risk_level.toLowerCase().split(" ")[0]}">${esc(r.risk_score)}/100</span></div>`).join("") : "<p class='muted'>No analyses yet.</p>";
  } catch (e) { console.error(e); }
}

async function analyze(ip) {
  clearError("error-box");
  $("result").classList.add("hidden");
  try {
    const data = await api("/api/analyze", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ip})});
    renderResult(data);
    location.hash = "analyzer";
  } catch (e) { showError("error-box", e.message); location.hash = "analyzer"; }
}

function renderResult(d) {
  $("result").classList.remove("hidden");
  $("risk-score").textContent = d.risk_score;
  $("risk-level").textContent = d.risk_level;
  $("risk-level").className = d.risk_level.toLowerCase().replace(" ","-");
  $("risk-reasons").innerHTML = d.risk_reasons.map(r => `<div>${esc(r)}</div>`).join("");
  const p = d.proxy || {};
  $("proxy").textContent = d.is_proxy ? "Yes" : "No";
  $("proxy-type").textContent = val(p.proxy_type);
  $("vpn").textContent = p.is_vpn ? "Detected" : "Not detected";
  $("tor").textContent = p.is_tor ? "Detected" : "Not detected";
  $("threat").textContent = val(d.threat);
  $("usage").textContent = val(d.usage_type);
  $("location-text").innerHTML = `<strong>${esc(val(d.city_name))}</strong><br><span class="muted">${esc(val(d.region_name))}, ${esc(val(d.country_name))} · ${esc(val(d.zip_code))}</span>`;
  const fields = [
    ["IP address",d.ip],["Country",d.country_name],["Country code",d.country_code],["Region",d.region_name],
    ["City",d.city_name],["ISP",d.isp],["ASN",d.asn],["AS name",d.as_name],["Domain",d.domain],
    ["Usage type",d.usage_type],["Time zone",d.time_zone],["AS CIDR",d.as_cidr],["Address type",d.address_type]
  ];
  $("network-grid").innerHTML = fields.map(([k,v]) => `<div class="info-item"><span>${k}</span><strong>${esc(val(v))}</strong></div>`).join("");
  if (map) map.remove();
  if (typeof d.latitude === "number" && typeof d.longitude === "number") {
    map = L.map("map").setView([d.latitude,d.longitude],7);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",{attribution:"© OpenStreetMap contributors"}).addTo(map);
    L.marker([d.latitude,d.longitude]).addTo(map).bindPopup(`<strong>${esc(d.ip)}</strong><br>${esc(val(d.city_name))}, ${esc(val(d.country_name))}<br>${esc(val(d.isp))}`).openPopup();
  } else $("map").innerHTML = "<div style='padding:20px;color:#8fa4b3'>Coordinates not available.</div>";
}

$("quick-form").addEventListener("submit", e => {e.preventDefault(); const ip=$("quick-ip").value.trim(); if(!ip) return; $("ip-input").value=ip; analyze(ip);});
$("analyze-form").addEventListener("submit", e => {e.preventDefault(); analyze($("ip-input").value.trim());});

$("bulk-btn").addEventListener("click", async () => {
  clearError("bulk-error");
  const file = $("csv-file").files[0];
  if (!file) return showError("bulk-error","Choose a CSV file first.");
  const form = new FormData(); form.append("file", file);
  try {
    const d = await api("/api/bulk",{method:"POST",body:form});
    lastBulk = d.results;
    $("bulk-wrap").classList.remove("hidden");
    $("bulk-body").innerHTML = d.results.map(r => `<tr><td>${esc(r.ip)}</td><td>${esc(r.country)}</td><td>${esc(r.city)}</td><td>${esc(r.isp)}</td><td>${esc(r.asn)}</td><td>${esc(r.proxy)}</td><td>${r.risk_score ?? "—"}</td><td><span class="badge ${(r.risk_level||"Error").toLowerCase().split(" ")[0]}">${esc(r.risk_level)}</span></td></tr>`).join("");
  } catch(e) { showError("bulk-error",e.message); }
});
$("download-bulk").addEventListener("click", () => {
  if (!lastBulk.length) return;
  const keys = ["ip","country","city","isp","asn","proxy","risk_score","risk_level"];
  const csv = [keys.join(","),...lastBulk.map(r => keys.map(k => `"${String(r[k] ?? "").replaceAll('"','""')}"`).join(","))].join("\n");
  const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([csv],{type:"text/csv"})); a.download="threatmap-bulk-results.csv"; a.click();
});
async function loadHistory() {
  try {
    const rows = await api("/api/history");
    $("history-body").innerHTML = rows.length ? rows.map(r => `<tr><td>${esc(r.ip)}</td><td>${new Date(r.timestamp).toLocaleString()}</td><td>${esc(r.country)}</td><td>${esc(r.city)}</td><td>${esc(r.isp)}</td><td>${esc(r.asn)}</td><td>${r.risk_score}</td><td><span class="badge ${r.risk_level.toLowerCase().split(" ")[0]}">${esc(r.risk_level)}</span></td></tr>`).join("") : "<tr><td colspan='8'>No history yet.</td></tr>";
  } catch(e) { showToast(e.message); }
}
$("clear-history").addEventListener("click", async () => { if(!confirm("Clear all analysis history?")) return; await api("/api/history",{method:"DELETE"}); loadHistory(); showToast("History cleared.");});
$("download-history").addEventListener("click", () => { window.location="/api/history.csv"; });

navigate(location.hash.slice(1) || "dashboard");
