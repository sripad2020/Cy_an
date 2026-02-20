/* ═══════════════════ CyberMind X — App Logic ═══════════════════ */

// ─── Particle System ───
(function () {
    const c = document.getElementById('particles'), x = c.getContext('2d');
    let w, h, pts = [];
    function resize() { w = c.width = innerWidth; h = c.height = innerHeight; pts = []; for (let i = 0; i < 90; i++)pts.push({ x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - .5) * .3, vy: (Math.random() - .5) * .3, r: Math.random() * 1.5 + .5, o: Math.random() * .4 + .1 }) }
    function draw() { x.clearRect(0, 0, w, h); pts.forEach((p, i) => { p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > w) p.vx *= -1; if (p.y < 0 || p.y > h) p.vy *= -1; x.beginPath(); x.arc(p.x, p.y, p.r, 0, Math.PI * 2); x.fillStyle = `rgba(0,255,170,${p.o})`; x.fill(); pts.forEach((q, j) => { if (j <= i) return; const d = Math.hypot(p.x - q.x, p.y - q.y); if (d < 120) { x.beginPath(); x.moveTo(p.x, p.y); x.lineTo(q.x, q.y); x.strokeStyle = `rgba(0,229,255,${.06 * (1 - d / 120)})`; x.lineWidth = .5; x.stroke() } }) }); requestAnimationFrame(draw) }
    resize(); addEventListener('resize', resize); draw()
})();

// ─── World Map ───
function renderMap(geo) {
    const marker = document.getElementById('map-marker');
    const infoEl = document.getElementById('map-info');
    if (!geo || !geo.latitude || !geo.longitude) { if (infoEl) infoEl.textContent = '📡 Geolocation unavailable'; return }
    const lat = geo.latitude, lon = geo.longitude;
    // Convert lat/lon to % position on the map image
    // The image covers roughly: lon -180 to 180, lat 90 to -90 (Mercator approximation)
    const px = ((lon + 180) / 360) * 100;
    const py = ((90 - lat) / 180) * 100;
    if (marker) {
        marker.style.left = px + '%';
        marker.style.top = py + '%';
        marker.classList.remove('hidden');
    }
    if (infoEl) infoEl.textContent = '📍 ' + geo.ip + ' — ' + (geo.city || '') + ', ' + (geo.country || '') + ' (' + lat.toFixed(2) + ', ' + lon.toFixed(2) + ')';
}

// ─── DOM Refs ───
const urlIn = document.getElementById('url'),
    scanBtn = document.getElementById('scan-btn'),
    term = document.getElementById('term'),
    termB = document.getElementById('term-body'),
    pfill = document.getElementById('pfill'),
    resultsEl = document.getElementById('results'),
    errEl = document.getElementById('error');

urlIn.addEventListener('keydown', e => { if (e.key === 'Enter') startScan() });

let ld = 0;
function tlog(html) { const e = document.createElement('div'); e.className = 'tl'; e.style.animationDelay = ld + 'ms'; e.innerHTML = html; termB.insertBefore(e, termB.querySelector('.pbar')); termB.scrollTop = termB.scrollHeight; ld += 100 }
function tclear() { termB.querySelectorAll('.tl').forEach(e => e.remove()); ld = 0; pfill.style.width = '0%' }
function prog(p) { pfill.style.width = p + '%' }
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML }

// ─── Scan ───
async function startScan() {
    const t = urlIn.value.trim();
    if (!t) { showErr('Enter a target URL or domain.'); return }
    errEl.classList.remove('show'); resultsEl.classList.add('hidden');
    scanBtn.classList.add('loading'); scanBtn.disabled = true;
    term.classList.remove('hidden'); tclear();

    tlog('<span class="p">[INIT]</span> <span class="i">Target:</span> ' + esc(t)); prog(5);

    const phases = [
        { m: '<span class="p">[DNS]</span> Resolving domain records...', p: 15 },
        { m: '<span class="p">[PHISH]</span> Querying Safe Browsing API...', p: 25 },
        { m: '<span class="p">[WHOIS]</span> Extracting registrar data...', p: 35 },
        { m: '<span class="p">[TLS]</span> Analyzing SSL certificate chain...', p: 45 },
        { m: '<span class="p">[HDR]</span> Inspecting security headers...', p: 55 },
        { m: '<span class="p">[PORT]</span> Scanning 17 common ports...', p: 65 },
        { m: '<span class="p">[SHODAN]</span> Querying threat intelligence...', p: 75 },
        { m: '<span class="p">[ABUSE]</span> Checking IP reputation...', p: 85 },
        { m: '<span class="p">[GEO]</span> Resolving geolocation...', p: 90 }
    ];
    let pi = 0; const iv = setInterval(() => { if (pi < phases.length) { tlog(phases[pi].m); prog(phases[pi].p); pi++ } }, 800);

    try {
        const r = await fetch('/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: t }) });
        clearInterval(iv); prog(95); tlog('<span class="p">[RISK]</span> Computing AI threat score...');
        if (!r.ok) { const e = await r.json(); showErr(e.detail || e.error || 'Scan failed.'); return }
        const d = await r.json(); if (d.error) { showErr(d.error); return }
        await new Promise(r => setTimeout(r, 400)); prog(100);
        tlog('<span class="ok">✓ Scan complete — ' + cnt(d.phishing) + ' phishing · ' + cnt(d.network) + ' network · ' + cnt(d.vulnerability) + ' vuln modules</span>');
        await new Promise(r => setTimeout(r, 500)); term.classList.add('hidden'); render(d);
    } catch (e) { clearInterval(iv); showErr('Connection failed. Is the server running?') }
    finally { scanBtn.classList.remove('loading'); scanBtn.disabled = false }
}
window.startScan = startScan;

function cnt(o) { return o ? Object.keys(o).length : 0 }
function showErr(m) { errEl.textContent = '⚠ ' + m; errEl.classList.add('show'); scanBtn.classList.remove('loading'); scanBtn.disabled = false; term.classList.add('hidden') }

// ─── Render Results ───
function render(d) {
    resultsEl.classList.remove('hidden');
    const risk = d.risk_score || { score: 0, grade: 'A', label: 'Secure' };

    // Metrics
    const ph = d.phishing || {}, net = d.network || {}, vul = d.vulnerability || {};
    const ports = net.ports || {}; const hdr = net.headers || {};
    const totalModules = cnt(ph) + cnt(net) + cnt(vul);
    const vulnCount = (vul.shodan || {}).vuln_count || 0;
    const portsScanned = ports.total_open !== undefined ? ports.total_open : '-';
    const aiConf = Math.max(5, 100 - risk.score);
    document.getElementById('metrics').innerHTML = `
<div class="metric"><div class="metric-icon">🎯</div><div class="metric-val">${risk.score}</div><div class="metric-label">Threat Score</div></div>
<div class="metric"><div class="metric-icon">🔓</div><div class="metric-val">${vulnCount}</div><div class="metric-label">Vulnerabilities</div></div>
<div class="metric"><div class="metric-icon">📡</div><div class="metric-val">${portsScanned}</div><div class="metric-label">Open Ports</div></div>
<div class="metric"><div class="metric-icon">🤖</div><div class="metric-val">${aiConf}%</div><div class="metric-label">AI Confidence</div></div>`;

    // Gauge
    const g = document.getElementById('g-grade'); g.textContent = risk.grade;
    g.className = 'g-grade ' + (risk.score >= 75 ? 'crit' : risk.score >= 50 ? 'hi' : risk.score >= 25 ? 'med' : 'safe');
    document.getElementById('g-score').textContent = risk.score + ' / 100';
    document.getElementById('g-label').textContent = risk.label;
    document.getElementById('g-meta').textContent = 'Target: ' + d.domain + '  ·  ' + new Date(d.timestamp).toLocaleString();
    const arc = document.getElementById('gauge-arc'), circ = 2 * Math.PI * 68;
    arc.setAttribute('stroke-dasharray', circ);
    setTimeout(() => { arc.style.strokeDashoffset = circ - (risk.score / 100) * circ; arc.style.stroke = risk.score >= 75 ? '#ff0040' : risk.score >= 50 ? '#ff2255' : risk.score >= 25 ? '#ff8800' : '#00ffaa' }, 100);

    // World Map
    const geo = vul.ip_geolocation || {};
    renderMap(geo.latitude || geo.longitude ? geo : null);

    // Cards
    renderPh(ph); renderNet(net); renderVul(vul);
    // Threat Model
    if (d.threat_model) renderThreatModel(d.threat_model);
    // Activity Feed
    renderFeed(d);
    resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function sev(s) { return '<span class="badge ' + (s || 'unknown') + '">' + (s || 'unknown') + '</span>' }
function rw(k, v, c) { return '<div class="row"><span class="rk">' + k + '</span><span class="rv ' + (c || '') + '">' + (v ?? 'N/A') + '</span></div>' }

// ─── Domain Intelligence Report ───
function renderPh(p) {
    const sb = p.safe_browsing || {};
    const di = p.domain_info || {};

    // 1. Trust Score Card
    const isSafe = sb.status === 'Safe';
    const isNew = di.is_new;
    const isSuspicious = di.is_suspicious;
    const trustPct = isSuspicious ? 15 : isNew ? 40 : isSafe ? 85 : 55;
    const trustColor = trustPct >= 70 ? 'var(--neon)' : trustPct >= 45 ? 'var(--orange)' : 'var(--red)';
    const trustLabel = trustPct >= 70 ? 'TRUSTED' : trustPct >= 45 ? 'MODERATE RISK' : 'HIGH RISK';

    let h = '';
    h += `<div class="card">
<div class="card-top"><span class="card-name">Domain Trust Score</span>${sev(sb.severity || di.severity)}</div>
<div class="card-body">
<div style="text-align:center;padding:.5rem 0">
<div style="font-family:'Orbitron',sans-serif;font-size:2.2rem;font-weight:800;color:${trustColor};text-shadow:0 0 20px ${trustColor}">${trustPct}</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:.6rem;color:var(--dim);letter-spacing:2px">${trustLabel}</div>
</div>
<div class="sbar" style="height:6px;margin:.5rem 0">
<div class="sbar-fill" style="width:${trustPct}%;background:${trustColor};box-shadow:0 0 8px ${trustColor}"></div>
</div>
${rw('Safe Browsing', sb.status || (sb.reason ? 'Skipped' : 'Unknown'), isSafe ? 'ok' : 'b')}
${rw('Domain Age', di.age_days ? di.age_days + ' days' : 'Unknown', isSuspicious ? 'b' : isNew ? 'w' : 'ok')}
${rw('Registrar', di.registrar)}
</div></div>`;

    // 2. URL Anatomy Card
    const domainStr = di.registrar ? 'Known Registrar ✓' : 'Unknown Registrar';
    const ns = di.name_servers || [];
    const tld = di.creation_date ? 'Registered' : 'Unregistered';
    h += `<div class="card">
<div class="card-top"><span class="card-name">Domain Fingerprint</span><span class="badge ${isSuspicious ? 'high' : 'safe'}">${isSuspicious ? 'suspicious' : 'verified'}</span></div>
<div class="card-body">
${rw('Created', di.creation_date)}
${rw('Expires', di.expiration_date)}
${rw('Registrar', di.registrar)}
${rw('Status', di.is_suspicious ? '⚠ Suspiciously new' : di.is_new ? '🟡 Recently registered' : '✓ Established domain', di.is_suspicious ? 'b' : di.is_new ? 'w' : 'ok')}
${ns.length ? `<div style="margin-top:.4rem"><span class="rk">Name Servers</span><div class="tags">${ns.map(n => '<span class="tag port">' + n + '</span>').join('')}</div></div>` : ''}
${di.error ? rw('Error', di.error, 'w') : ''}
</div></div>`;

    // 3. Threat Intelligence Card (Google Safe Browsing detail)
    const threatsList = sb.threats || [];
    h += `<div class="card">
<div class="card-top"><span class="card-name">Threat Intelligence</span>${sev(sb.severity)}</div>
<div class="card-body">
<div style="display:flex;align-items:center;gap:10px;padding:.5rem 0">
<div style="font-size:2rem">${isSafe ? '🛡️' : '☠️'}</div>
<div>
<div style="font-family:'Orbitron',monospace;font-size:.75rem;color:${isSafe ? 'var(--neon)' : 'var(--red)'}">${isSafe ? 'CLEAN' : 'THREAT DETECTED'}</div>
<div style="font-size:.7rem;color:var(--dim);margin-top:3px">Google Safe Browsing API</div>
</div></div>
${threatsList.length ? '<div style="margin-top:.3rem"><span class="rk">Threat Types</span><div class="tags">' + threatsList.map(t => '<span class="tag risk">' + t + '</span>').join('') + '</div></div>' : ''}
${sb.reason ? rw('Note', sb.reason) : ''}
${sb.error ? rw('Error', sb.error, 'w') : ''}
${rw('Malware', 'Google check', isSafe ? 'ok' : 'b')}
${rw('Social Engineering', 'Google check', isSafe ? 'ok' : 'b')}
${rw('Phishing', 'Google check', isSafe ? 'ok' : 'b')}
</div></div>`;

    document.getElementById('ph-cards').innerHTML = h;
}

// ─── Network ───
function renderNet(n) {
    let h = ''; const ssl = n.ssl || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">SSL / TLS</span>' + sev(ssl.severity) + '</div><div class="card-body">';
    if (ssl.error) h += rw('Error', ssl.error, 'w');
    else { h += rw('TLS', ssl.tls_version, ssl.tls_version?.includes('1.3') ? 'ok' : ''); h += rw('Cipher', ssl.cipher); h += rw('Key Bits', ssl.key_bits); h += rw('Valid To', ssl.valid_to); h += rw('Days Left', ssl.days_remaining, ssl.days_remaining > 90 ? 'ok' : ssl.days_remaining > 30 ? 'w' : 'b'); h += rw('Issuer', ssl.issuer?.organizationName || ssl.issuer?.commonName || '—') }
    h += '</div></div>';
    const hd = n.headers || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">Security Headers</span>' + sev(hd.severity) + '</div><div class="card-body">';
    if (hd.error) h += rw('Error', hd.error, 'w');
    else {
        h += rw('Score', hd.score + '%', hd.score >= 70 ? 'ok' : hd.score >= 40 ? 'w' : 'b'); h += rw('Server', hd.server);
        h += '<div class="sbar"><div class="sbar-fill" style="width:' + hd.score + '%;background:' + (hd.score >= 70 ? 'var(--neon)' : hd.score >= 40 ? 'var(--orange)' : 'var(--red)') + '"></div></div>';
        if (hd.present?.length) h += '<div style="margin-top:.5rem"><span class="rk">Present</span><div class="tags">' + hd.present.map(x => '<span class="tag hok">✓ ' + x.header + '</span>').join('') + '</div></div>';
        if (hd.missing?.length) h += '<div style="margin-top:.3rem"><span class="rk">Missing</span><div class="tags">' + hd.missing.map(x => '<span class="tag hmiss">✗ ' + x.header + '</span>').join('') + '</div></div>'
    }
    h += '</div></div>';
    const dns = n.dns || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">DNS Records</span>' + sev(dns.severity) + '</div><div class="card-body">';
    if (dns.error) h += rw('Error', dns.error, 'w');
    else {
        h += rw('IP', dns.ip_address); h += rw('SPF', dns.has_spf ? '✓ Found' : '✗ Missing', dns.has_spf ? 'ok' : 'w'); h += rw('DMARC', dns.has_dmarc ? '✓ Found' : '✗ Missing', dns.has_dmarc ? 'ok' : 'w');
        if (dns.records) Object.entries(dns.records).filter(([k, v]) => v.length > 0 && k !== 'TXT').forEach(([t, r]) => { h += '<div style="margin-top:.3rem"><span class="rk">' + t + '</span><div class="tags">' + r.slice(0, 5).map(x => '<span class="tag port">' + x + '</span>').join('') + '</div></div>' })
    }
    h += '</div></div>';
    const pt = n.ports || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">Port Scan</span>' + sev(pt.severity) + '</div><div class="card-body">';
    if (pt.error) h += rw('Error', pt.error, 'w');
    else {
        h += rw('IP', pt.ip); h += rw('Open', pt.total_open); h += rw('Risky', pt.risky_ports, pt.risky_ports > 0 ? 'b' : 'ok');
        if (pt.open_ports?.length) h += '<div style="margin-top:.4rem"><span class="rk">Services</span><div class="tags">' + pt.open_ports.map(p => '<span class="tag ' + (p.risk === 'high' ? 'risk' : 'port') + '">' + p.port + '/' + p.service + '</span>').join('') + '</div></div>';
        else h += '<div style="margin-top:.3rem;color:var(--neon);font-size:.72rem">No open ports detected</div>'
    }
    h += '</div></div>';

    // ─── Technology Stack ───
    const ts = n.tech_stack || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">Technology Stack</span>' + sev(ts.severity) + '</div><div class="card-body">';
    if (ts.error) h += rw('Error', ts.error, 'w');
    else {
        const m = ts.meta || {};
        h += rw('Response Time', m.response_time);
        h += rw('Status', m.status_code);
        h += rw('Content Type', m.content_type);
        if (m.info_leak) h += rw('Info Leak', '⚠ Server headers expose technology', 'w');
        if (ts.technologies?.length) {
            h += '<div style="margin-top:.4rem"><span class="rk">Detected (' + ts.count + ')</span><div class="tags">';
            ts.technologies.forEach(t => {
                h += '<span class="tag ' + (t.category === 'Server' ? 'risk' : 'port') + '">' + t.name + ' <span style="opacity:.5;font-size:.55rem">(' + t.category + ')</span></span>';
            });
            h += '</div></div>';
        } else h += '<div style="margin-top:.3rem;color:var(--neon);font-size:.72rem">No technologies detected</div>';
    }
    h += '</div></div>';

    // ─── Cookie Security ───
    const ck = n.cookies || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">Cookie Security</span>' + sev(ck.severity) + '</div><div class="card-body">';
    if (ck.error) h += rw('Error', ck.error, 'w');
    else {
        h += rw('Cookies Found', ck.total || 0);
        h += rw('Security Issues', ck.issues || 0, ck.issues > 0 ? 'b' : 'ok');
        if (ck.cookies?.length) {
            ck.cookies.forEach(c => {
                h += '<div style="margin-top:.5rem;padding:.4rem;background:rgba(255,255,255,.02);border-radius:6px">';
                h += '<div style="font-weight:600;font-size:.75rem;margin-bottom:.3rem">' + c.name + '</div>';
                h += rw('Secure', c.secure ? '✓' : '✗', c.secure ? 'ok' : 'b');
                h += rw('HttpOnly', c.httponly ? '✓' : '✗', c.httponly ? 'ok' : 'b');
                h += rw('SameSite', c.samesite, c.samesite === 'Strict' ? 'ok' : c.samesite === 'Lax' ? 'w' : 'b');
                if (c.flags?.length) h += '<div class="tags" style="margin-top:.3rem">' + c.flags.map(f => '<span class="tag risk">' + f + '</span>').join('') + '</div>';
                h += '</div>';
            });
        } else h += '<div style="margin-top:.3rem;color:var(--neon);font-size:.72rem">No cookies set by server</div>';
    }
    h += '</div></div>';

    // ─── Redirect Chain ───
    const rd = n.redirects || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">Redirect Chain</span>' + sev(rd.severity) + '</div><div class="card-body">';
    if (rd.error) h += rw('Error', rd.error, 'w');
    else {
        h += rw('Hops', rd.hops || 0, rd.hops > 3 ? 'w' : 'ok');
        h += rw('HTTPS Upgrade', rd.https_upgrade ? '✓ Yes' : '✗ No', rd.https_upgrade ? 'ok' : 'w');
        h += rw('Final URL', rd.final_url);
        if (rd.chain?.length > 1) {
            h += '<div style="margin-top:.5rem"><span class="rk">Chain</span>';
            rd.chain.forEach((c, i) => {
                const arrow = i < rd.chain.length - 1 ? ' →' : ' ✓';
                const color = c.status >= 300 && c.status < 400 ? 'var(--orange)' : c.status === 200 ? 'var(--neon)' : 'var(--red)';
                h += '<div style="font-size:.7rem;padding:.25rem 0;color:var(--dim)"><span style="color:' + color + ';font-weight:700">' + c.status + '</span> ' + c.url.substring(0, 60) + (c.url.length > 60 ? '...' : '') + arrow + '</div>';
            });
            h += '</div>';
        }
    }
    h += '</div></div>';

    // ─── Subdomain Discovery ───
    const sd = n.subdomains || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">Subdomain Discovery</span>' + sev(sd.severity) + '</div><div class="card-body">';
    if (sd.error) h += rw('Error', sd.error, 'w');
    else if (sd.reason) h += rw('Note', sd.reason);
    else {
        h += rw('Found', sd.count || 0);
        h += rw('Certificates', sd.total_certs || 0);
        if (sd.subdomains?.length) {
            h += '<div style="margin-top:.4rem"><span class="rk">Subdomains</span><div class="tags">';
            sd.subdomains.slice(0, 15).forEach(s => { h += '<span class="tag port">' + s + '</span>'; });
            if (sd.count > 15) h += '<span class="tag port" style="opacity:.5">+' + (sd.count - 15) + ' more</span>';
            h += '</div></div>';
        } else h += '<div style="margin-top:.3rem;color:var(--neon);font-size:.72rem">No subdomains found</div>';
    }
    h += '</div></div>';

    // ─── WAF / CDN Detection ───
    const wf = n.waf || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">WAF / CDN Detection</span>' + sev(wf.severity) + '</div><div class="card-body">';
    if (wf.error) h += rw('Error', wf.error, 'w');
    else {
        h += rw('Protected', wf.has_protection ? '✓ Yes' : '✗ Not Detected', wf.has_protection ? 'ok' : 'w');
        h += rw('Services', wf.count || 0);
        if (wf.detected?.length) {
            h += '<div style="margin-top:.4rem"><span class="rk">Detected</span><div class="tags">';
            wf.detected.forEach(d => {
                h += '<span class="tag hok">' + d.name + ' <span style="opacity:.5;font-size:.55rem">(' + d.type + ')</span></span>';
            });
            h += '</div></div>';
        } else h += '<div style="margin-top:.3rem;color:var(--orange);font-size:.72rem">⚠ No WAF/CDN detected — server may be directly exposed</div>';
    }
    h += '</div></div>';

    document.getElementById('net-cards').innerHTML = h;
}

// ─── Vulnerability ───
function renderVul(v) {
    let h = ''; const sh = v.shodan || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">Shodan Intel</span>' + sev(sh.severity) + '</div><div class="card-body">';
    if (sh.error) h += rw('Error', sh.error, 'w');
    else if (sh.reason) h += rw('Note', sh.reason);
    else {
        h += rw('IP', sh.ip); h += rw('Org', sh.org); h += rw('OS', sh.os); h += rw('Location', (sh.city || '') + ', ' + (sh.country || '')); h += rw('Vulns', sh.vuln_count, sh.vuln_count > 0 ? 'b' : 'ok');
        if (sh.vulns?.length) h += '<div style="margin-top:.4rem"><span class="rk">CVEs</span><div class="tags">' + sh.vulns.slice(0, 8).map(c => '<span class="tag vuln">' + c + '</span>').join('') + '</div></div>';
        if (sh.services?.length) h += '<div style="margin-top:.3rem"><span class="rk">Services</span><div class="tags">' + sh.services.map(s => '<span class="tag port">' + s.port + '/' + s.product + '</span>').join('') + '</div></div>'
    }
    h += '</div></div>';
    const rp = v.ip_reputation || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">IP Reputation</span>' + sev(rp.severity) + '</div><div class="card-body">';
    if (rp.error) h += rw('Error', rp.error, 'w');
    else if (rp.reason) h += rw('Note', rp.reason);
    else { h += rw('IP', rp.ip); h += rw('Abuse Score', rp.abuse_score + '/100', rp.abuse_score > 25 ? 'b' : 'ok'); h += rw('Reports', rp.total_reports, rp.total_reports > 0 ? 'w' : 'ok'); h += rw('ISP', rp.isp); h += rw('Country', rp.country); h += rw('Whitelisted', rp.is_whitelisted ? 'Yes' : 'No', rp.is_whitelisted ? 'ok' : '') }
    h += '</div></div>';
    const geo = v.ip_geolocation || {};
    h += '<div class="card"><div class="card-top"><span class="card-name">Geolocation</span>' + sev(geo.severity) + '</div><div class="card-body">';
    if (geo.error) h += rw('Error', geo.error, 'w');
    else {
        h += rw('IP', geo.ip); h += rw('City', geo.city); h += rw('Region', geo.region); h += rw('Country', geo.country); h += rw('ISP', geo.isp); h += rw('Org', geo.org); h += rw('Timezone', geo.timezone);
        if (geo.latitude && geo.longitude) h += rw('Coords', geo.latitude + ', ' + geo.longitude)
    }
    h += '</div></div>';
    document.getElementById('vul-cards').innerHTML = h;
}

// ─── Threat Model ───
function renderThreatModel(tm) {
    if (!tm) return;
    const lv = tm.overall_level.toLowerCase();

    // Overview panel with STRIDE chart
    let ov = `<div class="tm-header">
<div class="tm-level">
<div class="tm-level-dot ${lv}"></div>
<div class="tm-level-text ${lv}">${tm.overall_level} THREAT LEVEL</div>
</div>
<div class="tm-stats">
<div class="tm-stat"><div class="tm-stat-val" style="color:var(--red)">${tm.total_threats}</div><div class="tm-stat-label">Threats</div></div>
<div class="tm-stat"><div class="tm-stat-val" style="color:#ff0040">${tm.critical_count}</div><div class="tm-stat-label">Critical</div></div>
<div class="tm-stat"><div class="tm-stat-val" style="color:var(--orange)">${tm.high_count}</div><div class="tm-stat-label">High</div></div>
</div>
</div>`;

    // STRIDE bar chart
    const maxS = Math.max(1, ...tm.stride_summary.map(s => s.count));
    ov += `<div class="stride-chart">`;
    tm.stride_summary.forEach(s => {
        const pct = s.count > 0 ? (s.count / maxS) * 100 : 5;
        ov += `<div class="stride-col">
<div class="stride-bar-wrap"><div class="stride-count" style="color:${s.count > 0 ? 'var(--txt)' : 'var(--dim)'}">${s.count}</div><div class="stride-bar ${s.code.toLowerCase()}" style="height:${pct}%"></div></div>
<div class="stride-code">${s.code}</div>
<div class="stride-name">${s.name}</div>
</div>`;
    });
    ov += `</div>`;
    document.getElementById('tm-overview').innerHTML = ov;

    // Cards
    let h = '';

    // Attack Surface Card
    h += `<div class="card"><div class="card-top"><span class="card-name">Attack Surface</span><span class="badge ${tm.attack_surface.some(a => a.exposure === 'critical') ? 'critical' : tm.attack_surface.some(a => a.exposure === 'high') ? 'high' : 'safe'}">${tm.attack_surface.length} assets</span></div><div class="card-body">`;
    tm.attack_surface.forEach(a => {
        h += `<div class="as-item"><div><div class="as-asset">${a.asset}</div><div class="as-detail">${a.detail}</div></div><span class="as-exposure ${a.exposure}">${a.exposure}</span></div>`;
    });
    h += `</div></div>`;

    // Identified Threats Card
    h += `<div class="card"><div class="card-top"><span class="card-name">Identified Threats</span><span class="badge ${tm.critical_count > 0 ? 'critical' : tm.high_count > 0 ? 'high' : 'safe'}">${tm.total_threats} found</span></div><div class="card-body">`;
    tm.threats.forEach(t => {
        h += `<div class="threat-item">
<div class="threat-marker ${t.impact}"></div>
<div>
<div class="threat-name">${t.threat}</div>
<div class="threat-desc">${t.description}</div>
<div class="threat-badges">
<span class="tbadge l-${t.likelihood.toLowerCase()}">L: ${t.likelihood}</span>
<span class="tbadge i-${t.impact.toLowerCase()}">I: ${t.impact}</span>
<span class="tag vuln">${t.category}</span>
</div>
</div>
</div>`;
    });
    h += `</div></div>`;

    // Mitigations Card
    h += `<div class="card"><div class="card-top"><span class="card-name">Recommended Mitigations</span><span class="badge safe">${tm.mitigations.length} actions</span></div><div class="card-body">`;
    tm.mitigations.forEach(m => {
        h += `<div class="mit-item"><div class="mit-priority ${m.priority}"></div><div class="mit-text">${m.action}</div><span class="mit-cat">${m.category}</span></div>`;
    });
    h += `</div></div>`;

    document.getElementById('tm-cards').innerHTML = h;
}

// ─── Activity Feed ───
function renderFeed(d) {
    const fp = document.getElementById('feed-panel'); let lines = [];
    const ts = () => '<span class="feed-ts">[' + new Date().toLocaleTimeString() + ']</span>';
    lines.push(ts() + '<span class="feed-i"> SCAN INITIATED</span> target: ' + d.domain);
    const sb = d.phishing?.safe_browsing;
    if (sb) lines.push(ts() + (sb.status === 'Safe' ? '<span class="feed-ok"> ✓ Safe Browsing: CLEAN</span>' : '<span class="feed-e"> ✗ Safe Browsing: ' + sb.status + '</span>'));
    const ssl = d.network?.ssl;
    if (ssl && !ssl.error) lines.push(ts() + '<span class="feed-ok"> ✓ TLS ' + ssl.tls_version + '</span> cert valid ' + ssl.days_remaining + ' days');
    else if (ssl?.error) lines.push(ts() + '<span class="feed-w"> ⚠ SSL check failed</span>');
    const hdr = d.network?.headers;
    if (hdr && !hdr.error) lines.push(ts() + '<span class="feed-i"> Headers score: ' + hdr.score + '%</span>');
    const pt = d.network?.ports;
    if (pt && !pt.error) lines.push(ts() + (pt.risky_ports > 0 ? '<span class="feed-e"> ✗ ' + pt.risky_ports + ' risky ports open</span>' : '<span class="feed-ok"> ✓ ' + pt.total_open + ' ports open (none risky)</span>'));
    const sh = d.vulnerability?.shodan;
    if (sh && sh.vuln_count > 0) lines.push(ts() + '<span class="feed-e"> ✗ ' + sh.vuln_count + ' CVEs found via Shodan</span>');
    else if (sh && !sh.error && !sh.reason) lines.push(ts() + '<span class="feed-ok"> ✓ No known CVEs</span>');
    const rep = d.vulnerability?.ip_reputation;
    if (rep && !rep.error && !rep.reason) lines.push(ts() + '<span class="feed-i"> Abuse score: ' + rep.abuse_score + '/100</span>');
    lines.push(ts() + '<span class="feed-ok"> SCAN COMPLETE</span> risk grade: ' + d.risk_score.grade + ' (' + d.risk_score.score + '/100)');
    fp.innerHTML = lines.map(l => '<div class="feed-line">' + l + '</div>').join('');
}
