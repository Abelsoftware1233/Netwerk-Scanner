/* ─── State ─────────────────────────────────────────────────────────────── */
const API = "http:87.106.41.140:5008/api";
let selectedHost = null;
let hosts = [];
let radarAngle = 0;
let radarFrame = null;

/* ─── Init ──────────────────────────────────────────────────────────────── */
window.addEventListener("DOMContentLoaded", () => {
  startClock();
  fetchLocalIP();
  drawRadar();
  log("info", "NetScanner Pro gestart");
  log("info", "Klik op ▶ SCAN om hosts te ontdekken");
});

/* ─── Clock ─────────────────────────────────────────────────────────────── */
function startClock() {
  const el = document.getElementById("clock");
  setInterval(() => {
    el.textContent = new Date().toTimeString().slice(0, 8);
  }, 1000);
}

/* ─── Fetch local IP ────────────────────────────────────────────────────── */
async function fetchLocalIP() {
  try {
    const r = await fetch(`${API}/local-ip`);
    const d = await r.json();
    document.getElementById("local-ip").textContent = d.ip;
    document.getElementById("target-input").value = d.network;
    log("ok", `Lokaal IP: ${d.ip}  Netwerk: ${d.network}`);
  } catch {
    document.getElementById("local-ip").textContent = "offline";
    log("warn", "Backend niet bereikbaar – start app.py");
  }
}

/* ─── Scan ───────────────────────────────────────────────────────────────── */
async function startScan() {
  const target = document.getElementById("target-input").value.trim();
  if (!target) return;

  const btn = document.getElementById("scan-btn");
  const btnText = document.getElementById("scan-btn-text");
  btn.classList.add("loading");
  btnText.textContent = "⏳ SCANNING…";
  btnText.parentElement.querySelector("span").classList.add("scanning");

  document.getElementById("host-list").innerHTML =
    `<div class="empty-state">🔭 Scannen…<br>${target}</div>`;

  log("info", `Scan gestart: ${target}`);

  try {
    const r = await fetch(`${API}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target })
    });
    const d = await r.json();
    hosts = d.hosts || [];
    renderHostList(hosts);
    log("ok", `Scan klaar: ${hosts.length} hosts gevonden`);
    hosts.forEach(h => log("data", `  ${h.ip.padEnd(16)} ${h.hostname || "(onbekend)"} ${h.mac ? "– " + h.mac : ""}`));
  } catch (e) {
    log("error", "Scan mislukt: " + e.message);
    document.getElementById("host-list").innerHTML =
      `<div class="empty-state">❌ Backend niet bereikbaar.<br>Start: python app.py</div>`;
  } finally {
    btn.classList.remove("loading");
    btnText.textContent = "▶ SCAN";
  }
}

/* ─── Render host list ──────────────────────────────────────────────────── */
function renderHostList(list) {
  const el = document.getElementById("host-list");
  if (!list.length) {
    el.innerHTML = `<div class="empty-state">Geen hosts gevonden</div>`;
    return;
  }
  el.innerHTML = list.map((h, i) => `
    <div class="host-item" id="host-${i}" onclick="selectHost(${i})">
      <div class="host-dot"></div>
      <div class="host-details">
        <div class="host-ip">${h.ip}</div>
        <div class="host-name">${h.hostname || h.vendor || "onbekend"}</div>
      </div>
    </div>
  `).join("");
}

/* ─── Select host ───────────────────────────────────────────────────────── */
function selectHost(index) {
  // deselect previous
  document.querySelectorAll(".host-item").forEach(el => el.classList.remove("active"));
  const el = document.getElementById(`host-${index}`);
  if (el) el.classList.add("active");

  selectedHost = hosts[index];
  updateCenterInfo(selectedHost);
  log("info", `Host geselecteerd: ${selectedHost.ip}`);
}

function updateCenterInfo(host) {
  document.getElementById("st-active").textContent = host.ip;
  document.getElementById("st-ports").textContent = "Nog niet gescand";
  document.getElementById("st-vuln").textContent = "Onbekend";

  const pDot = document.getElementById("center-ports").querySelector(".dot");
  const vDot = document.getElementById("center-vuln").querySelector(".dot");
  pDot.className = "dot yellow";
  vDot.className = "dot gray";
}

/* ─── Actions ───────────────────────────────────────────────────────────── */
async function action(type) {
  if (!selectedHost && type !== "scan") {
    log("warn", "Selecteer eerst een host uit de lijst");
    showModal("WAARSCHUWING", `<p style="color:var(--amber)">⚠ Selecteer eerst een host uit de lijst links.</p>`);
    return;
  }

  // highlight button
  document.querySelectorAll(".radial-btn").forEach(b => b.classList.remove("active"));
  document.getElementById(`btn-${type}`)?.classList.add("active");
  setTimeout(() => document.getElementById(`btn-${type}`)?.classList.remove("active"), 1500);

  switch (type) {
    case "scan":    await doPortScan(); break;
    case "spy":     doSpy();           break;
    case "connect": doConnect();       break;
    case "mitm":    await doMITM();    break;
    case "attack":  await doAttack();  break;
  }
}

async function doPortScan() {
  if (!selectedHost) { log("warn", "Geen host geselecteerd"); return; }
  const ip = selectedHost.ip;
  log("info", `Poort scan gestart op ${ip}…`);

  try {
    const r = await fetch(`${API}/portscan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    const d = await r.json();

    // update center
    document.getElementById("st-ports").textContent = `${d.port_count} open poorten`;
    const pDot = document.getElementById("center-ports").querySelector(".dot");
    pDot.className = d.port_count > 0 ? "dot yellow" : "dot green";

    const vDot = document.getElementById("center-vuln").querySelector(".dot");
    document.getElementById("st-vuln").textContent = d.vulnerable ? "Mogelijk kwetsbaar" : "Geen bekende lekken";
    vDot.className = d.vulnerable ? "dot red" : "dot green";

    log("ok", `${ip}: ${d.port_count} open poorten`);

    const portsHtml = d.open_ports.length ? `
      <div class="modal-section">
        <h3>OPEN POORTEN</h3>
        ${d.open_ports.map(p => `
          <div class="port-row">
            <span class="port-num">${p.port}</span>
            <span class="port-svc">${p.service}</span>
            <span class="port-ver">${p.version}</span>
          </div>`).join("")}
      </div>` : `<p style="color:var(--green)">✓ Geen open poorten gevonden.</p>`;

    const vulnHtml = d.vuln_hints.length ? `
      <div class="modal-section">
        <h3>BEVEILIGINGSWAARSCHUWINGEN</h3>
        ${d.vuln_hints.map(v => `<div class="vuln-item">${v}</div>`).join("")}
      </div>` : `<div class="modal-section"><div class="safe-item">Geen bekende kwetsbaarheden gedetecteerd</div></div>`;

    showModal(`POORT SCAN – ${ip}`, portsHtml + vulnHtml);

  } catch (e) {
    log("error", "Scan fout: " + e.message);
    showModal("FOUT", `<p style="color:var(--red)">Backend fout: ${e.message}</p>`);
  }
}

function doSpy() {
  const ip = selectedHost.ip;
  log("info", `Spy modus op ${ip}`);

  const html = `
    <div class="modal-section">
      <h3>HOST INFO</h3>
      <div class="port-row"><span class="port-num">IP</span><span class="port-svc">${ip}</span></div>
      <div class="port-row"><span class="port-num">Naam</span><span class="port-svc">${selectedHost.hostname || "onbekend"}</span></div>
      <div class="port-row"><span class="port-num">MAC</span><span class="port-svc">${selectedHost.mac || "onbekend"}</span></div>
      <div class="port-row"><span class="port-num">Vendor</span><span class="port-svc">${selectedHost.vendor || "onbekend"}</span></div>
      <div class="port-row"><span class="port-num">Status</span><span class="port-svc" style="color:var(--green)">● Actief</span></div>
    </div>
    <div class="modal-section">
      <h3>SNELLE TESTS</h3>
      <p style="color:var(--text-dim);font-size:11px">
        Voer handmatig uit in terminal:<br><br>
        <span style="color:var(--green)">ping ${ip}</span><br>
        <span style="color:var(--green)">traceroute ${ip}</span><br>
        <span style="color:var(--green)">nmap -A ${ip}</span><br>
        <span style="color:var(--green)">whois ${ip}</span>
      </p>
    </div>`;
  showModal(`SPY – ${ip}`, html);
}

function doConnect() {
  const ip = selectedHost.ip;
  log("info", `Verbinding info voor ${ip}`);
  const html = `
    <div class="modal-section">
      <h3>VERBINDINGSOPTIES</h3>
      <p style="color:var(--text-dim);font-size:11px;line-height:2">
        <span style="color:var(--blue)">SSH:</span>   <span style="color:var(--green)">ssh gebruiker@${ip}</span><br>
        <span style="color:var(--blue)">RDP:</span>   <span style="color:var(--green)">xfreerdp /v:${ip}</span><br>
        <span style="color:var(--blue)">HTTP:</span>  <a href="http://${ip}" target="_blank" style="color:var(--green)">http://${ip}</a><br>
        <span style="color:var(--blue)">HTTPS:</span> <a href="https://${ip}" target="_blank" style="color:var(--green)">https://${ip}</a><br>
        <span style="color:var(--blue)">FTP:</span>   <span style="color:var(--green)">ftp ${ip}</span>
      </p>
    </div>`;
  showModal(`CONNECT – ${ip}`, html);
}

async function doMITM() {
  const ip = selectedHost.ip;
  log("info", `ARP tabel ophalen voor MITM analyse…`);
  try {
    const r = await fetch(`${API}/mitm-info`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    const d = await r.json();

    const arpHtml = d.arp_table.length ? d.arp_table.map(e => `
      <div class="arp-row">
        <span class="arp-ip">${e.ip}</span>
        <span class="arp-mac">${e.mac}</span>
      </div>`).join("") : "<p style='color:var(--text-dim)'>ARP tabel leeg</p>";

    const html = `
      <div class="modal-section">
        <h3>NETWERK GATEWAY</h3>
        <p style="color:var(--green)">${d.gateway || "onbekend"}</p>
      </div>
      <div class="modal-section">
        <h3>ARP TABEL</h3>
        ${arpHtml}
      </div>
      <div class="modal-section">
        <p style="color:var(--amber);font-size:11px">⚠ ${d.info}</p>
      </div>`;
    showModal(`M.I.T.M. ANALYSE – ${ip}`, html);
    log("ok", `Gateway: ${d.gateway || "onbekend"}, ${d.arp_table.length} ARP entries`);

  } catch (e) {
    log("error", "MITM fout: " + e.message);
    showModal("FOUT", `<p style="color:var(--red)">${e.message}</p>`);
  }
}

async function doAttack() {
  const ip = selectedHost.ip;
  log("warn", `Aanvalsoppervlak analyse voor ${ip}…`);
  try {
    const r = await fetch(`${API}/attack-surface`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    const d = await r.json();

    const riskColor = { Low: "var(--green)", Medium: "var(--amber)", High: "var(--red)" }[d.risk] || "var(--text)";
    const html = `
      <div class="modal-section">
        <h3>RISICO NIVEAU</h3>
        <p style="color:${riskColor};font-size:24px;font-family:var(--display);font-weight:900">${d.risk.toUpperCase()}</p>
      </div>
      <div class="modal-section">
        <h3>BEVINDINGEN</h3>
        ${d.findings.map(f => `<div class="port-row"><span style="color:var(--text)">${f}</span></div>`).join("") || "<p style='color:var(--text-dim)'>Geen bevindingen</p>"}
      </div>
      <div class="modal-section">
        <p style="color:var(--red);font-size:11px">🔴 ${d.disclaimer}</p>
      </div>`;
    showModal(`ATTACK SURFACE – ${ip}`, html);

  } catch (e) {
    log("error", "Attack analyse fout: " + e.message);
    showModal("FOUT", `<p style="color:var(--red)">${e.message}</p>`);
  }
}

/* ─── Modal ──────────────────────────────────────────────────────────────── */
function showModal(title, bodyHtml) {
  document.getElementById("modal-title").textContent = title;
  document.getElementById("modal-body").innerHTML = bodyHtml;
  document.getElementById("modal").classList.add("visible");
  document.getElementById("modal-overlay").classList.add("visible");
}

function closeModal() {
  document.getElementById("modal").classList.remove("visible");
  document.getElementById("modal-overlay").classList.remove("visible");
}

/* ─── Log ────────────────────────────────────────────────────────────────── */
function log(type, msg) {
  const el = document.getElementById("output-log");
  const ts = new Date().toTimeString().slice(0, 8);
  const div = document.createElement("div");
  div.className = `log-entry ${type}`;
  div.innerHTML = `<span class="ts">${ts}</span><span class="msg">${msg}</span>`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

function clearLog() {
  document.getElementById("output-log").innerHTML = "";
}

/* ─── Radar canvas ───────────────────────────────────────────────────────── */
function drawRadar() {
  const canvas = document.getElementById("radar-canvas");
  const ctx = canvas.getContext("2d");

  function resize() {
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
  }
  resize();
  window.addEventListener("resize", resize);

  function frame() {
    const W = canvas.width, H = canvas.height;
    const cx = W / 2, cy = H / 2;
    const maxR = Math.min(W, H) / 2 - 4;

    ctx.clearRect(0, 0, W, H);

    // ── Concentric rings ──
    const rings = 4;
    for (let i = 1; i <= rings; i++) {
      const r = (maxR / rings) * i;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = i === rings
        ? "rgba(0,255,65,0.18)"
        : "rgba(0,255,65,0.07)";
      ctx.lineWidth = i === rings ? 1.5 : 1;
      ctx.stroke();
    }

    // ── Cross hairs ──
    ctx.strokeStyle = "rgba(0,255,65,0.07)";
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 8]);
    ctx.beginPath();
    ctx.moveTo(cx - maxR, cy); ctx.lineTo(cx + maxR, cy);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(cx, cy - maxR); ctx.lineTo(cx, cy + maxR);
    ctx.stroke();
    ctx.setLineDash([]);

    // ── Sweep line ──
    radarAngle -= 0.018;
    const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, maxR);
    grad.addColorStop(0,   "rgba(0,255,65,0.0)");
    grad.addColorStop(0.6, "rgba(0,255,65,0.05)");
    grad.addColorStop(1,   "rgba(0,255,65,0.0)");

    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(radarAngle);

    // sweep wedge
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.arc(0, 0, maxR, -Math.PI / 8, 0);
    ctx.closePath();
    const sweepGrad = ctx.createConicalGradient
      ? ctx.createConicalGradient(0, 0, -Math.PI / 8)
      : null;
    ctx.fillStyle = "rgba(0,255,65,0.06)";
    ctx.fill();

    // bright line
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(maxR, 0);
    ctx.strokeStyle = "rgba(0,255,65,0.7)";
    ctx.lineWidth = 1.5;
    ctx.shadowColor = "rgba(0,255,65,0.8)";
    ctx.shadowBlur = 6;
    ctx.stroke();
    ctx.shadowBlur = 0;

    ctx.restore();

    // ── Host blips ──
    if (hosts.length > 0) {
      hosts.forEach((h, i) => {
        const bAngle = (i / hosts.length) * Math.PI * 2 - Math.PI / 2;
        const dist = maxR * (0.45 + (i % 3) * 0.18);
        const bx = cx + Math.cos(bAngle) * dist;
        const by = cy + Math.sin(bAngle) * dist;
        const isSelected = selectedHost && selectedHost.ip === h.ip;

        // glow
        ctx.beginPath();
        ctx.arc(bx, by, isSelected ? 7 : 5, 0, Math.PI * 2);
        ctx.fillStyle = isSelected ? "rgba(0,255,65,0.35)" : "rgba(0,255,65,0.12)";
        ctx.fill();

        // dot
        ctx.beginPath();
        ctx.arc(bx, by, isSelected ? 4 : 3, 0, Math.PI * 2);
        ctx.fillStyle = isSelected ? "#00ff41" : "#00882a";
        ctx.shadowColor = "#00ff41";
        ctx.shadowBlur = isSelected ? 10 : 4;
        ctx.fill();
        ctx.shadowBlur = 0;

        // label
        ctx.fillStyle = isSelected ? "rgba(0,255,65,0.9)" : "rgba(0,255,65,0.4)";
        ctx.font = `${isSelected ? "bold " : ""}10px 'Share Tech Mono'`;
        ctx.fillText(h.ip, bx + 8, by - 4);
      });
    }

    radarFrame = requestAnimationFrame(frame);
  }

  frame();
}
