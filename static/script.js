// Text for both languages lives in i18n.js (loaded before this file).
const $ = (id) => document.getElementById(id);
// Builds an element; text goes in as plain text so a URL can never inject HTML
const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
};

// ---------- language ----------
let lang = 'en';
try { lang = localStorage.getItem('pg-lang') || 'en'; } catch (e) { /* ignore */ }
const t = (key, ...args) => {
    let s = T[lang][key] || T.en[key] || key;
    args.forEach((a, i) => { s = s.split('{' + i + '}').join(a); });
    return s;
};
// element whose text is translated automatically when the language changes
const ic = (tag, cls, key) => { const n = el(tag, cls, t(key)); n.dataset.i18n = key; return n; };
function trReason(text) {
    if (lang !== 'hi') return text;
    if (EXACT_HI[text]) return EXACT_HI[text];
    for (const [re, fn] of PATTERNS_HI) { const m = text.match(re); if (m) return fn(m); }
    return text;
}

const TONE = { Safe: 'safe', Suspicious: 'warn', Phishing: 'danger' };
const ICON = { Safe: 'fa-shield-halved', Suspicious: 'fa-circle-exclamation', Phishing: 'fa-triangle-exclamation' };
const SAMPLE_EMAIL = 'Dear customer,\n\nWe noticed unusual activity on your account. Your account will be suspended within 24 hours.\n' +
    'Verify your password immediately here: http://paypa1-secure-login.verify-account.xyz/signin\n\nSecurity Team';
const SAMPLE_MSGS = {
    kyc: 'Dear SBI customer, your account will be blocked today. Update your KYC immediately: http://sbi-kyc-update.verify-account.xyz/login . Call 9876543210 for help.',
    parcel: 'India Post: Your parcel could not be delivered. Pay Rs 25 redelivery fee within 24 hours: http://bit.ly/3xYz . Install the app to track your parcel.',
    ok: '123456 is your OTP for login to Paytm. Do not share it with anyone. Valid for 5 minutes.'
};
let view = null; // the last result shown, so it can be redrawn in another language

function applyLang() {
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-i18n]').forEach((n) => { n.textContent = t(n.dataset.i18n); });
    document.querySelectorAll('[data-i18n-ph]').forEach((n) => { n.placeholder = t(n.dataset.i18nPh); });
    $('langBtn').textContent = t('lang_switch');
    setMode(document.documentElement.dataset.mode || 'dark');
    if (view) view.show(view.data);
    if (typeof loadActivity === 'function') loadActivity();
}
$('langBtn').addEventListener('click', () => {
    lang = lang === 'en' ? 'hi' : 'en';
    try { localStorage.setItem('pg-lang', lang); } catch (e) { /* ignore */ }
    applyLang();
});

// ---------- colour themes (choice is remembered) ----------
function setTheme(name) {
    document.documentElement.dataset.theme = name;
    try { localStorage.setItem('pg-theme', name); } catch (e) { /* ignore */ }
    document.querySelectorAll('.dot').forEach((d) => d.classList.toggle('on', d.dataset.theme === name));
}
document.querySelectorAll('.dot').forEach((d) => d.addEventListener('click', () => setTheme(d.dataset.theme)));
let savedTheme = 'sunset';
try { savedTheme = localStorage.getItem('pg-theme') || 'sunset'; } catch (e) { /* ignore */ }
setTheme(savedTheme);

// ---------- light / dark mode (choice is remembered) ----------
function setMode(mode) {
    document.documentElement.dataset.mode = mode;
    try { localStorage.setItem('pg-mode', mode); } catch (e) { /* ignore */ }
    $('modeIcon').className = 'fa-solid ' + (mode === 'dark' ? 'fa-sun' : 'fa-moon');
    $('modeBtn').title = t(mode === 'dark' ? 'mode_to_light' : 'mode_to_dark');
}
$('modeBtn').addEventListener('click', () => setMode(document.documentElement.dataset.mode === 'light' ? 'dark' : 'light'));
let savedMode = 'dark';
try { savedMode = localStorage.getItem('pg-mode') || 'dark'; } catch (e) { /* ignore */ }
setMode(savedMode);

// ---------- tabs ----------
document.querySelectorAll('.tab').forEach((tab) => tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('active', x === tab));
    ['url', 'email', 'msg', 'qr'].forEach((name) => $('panel-' + name).classList.toggle('hidden', tab.dataset.tab !== name));
}));

// ---------- talking to the server ----------
async function post(path, body) {
    const res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const data = await res.json();
    if (!res.ok || data.error) throw new Error(data.error || 'Server error');
    return data;
}

async function run(path, body, button, show) {
    $('resultContainer').classList.add('hidden');
    $('loader').classList.remove('hidden');
    button.disabled = true;
    try {
        const data = await post(path, body);
        view = { show, data };
        show(data);
        loadActivity();
    } catch (err) {
        view = null;
        showError(err.message === 'Failed to fetch' ? t('err_conn') : err.message);
    } finally {
        $('loader').classList.add('hidden');
        button.disabled = false;
    }
}

// ---------- result card ----------
function startCard(d, subtitle) {
    const v = d.prediction;
    $('resultContainer').classList.remove('hidden');
    $('resultCard').className = 'result-box ' + TONE[v];
    $('resultFaIcon').className = 'fa-solid ' + ICON[v];
    $('resultTitle').textContent = t('title_' + v);
    $('resultDesc').textContent = t('desc_' + v);
    $('resultUrl').textContent = subtitle;
    $('confText').textContent = d.risk + ' / 100';
    $('progressFill').style.width = '0';
    requestAnimationFrame(() => { $('progressFill').style.width = d.risk + '%'; });
    $('breakdownSection').innerHTML = '';
    $('extra').innerHTML = '';
}

function addList(titleKey, items) {
    $('extra').appendChild(ic('h4', null, titleKey));
    const ul = el('ul');
    items.forEach((text) => ul.appendChild(el('li', null, text)));
    $('extra').appendChild(ul);
}

function formatAge(days) {
    if (days < 60) return t('age_days', days);
    if (days < 730) return t('age_months', Math.round(days / 30));
    return t('age_years', (days / 365).toFixed(1));
}

function showError(message) {
    startCard({ prediction: 'Phishing', risk: 0 }, '');
    $('resultTitle').textContent = t('err_title');
    $('resultDesc').textContent = message;
}

// ---------- "In simple words" box + optional AI explanation ----------
function plainText(d) {
    const keys = (d.keys || []).filter((k) => T.en['pl_' + k]).slice(0, 3);
    const why = keys.length ? keys.map((k) => t('pl_' + k)).join(' ') : t('pl_none');
    return [t('pl_intro_' + d.prediction), why, t('pl_advice_' + d.prediction)].join(' ');
}

function addPlain(d, kind) {
    const box = el('div', 'plain');
    box.appendChild(ic('h4', null, 'h_plain'));
    const text = el('p', null, plainText(d));
    const aiBtn = ic('button', 'ghost', 'ai_btn');
    aiBtn.type = 'button';
    const note = el('p', 'muted');
    aiBtn.addEventListener('click', async () => {
        aiBtn.disabled = true;
        note.textContent = t('ai_wait');
        try {
            let host = '';
            if (kind === 'website link') {
                try { host = new URL(d.url.includes('://') ? d.url : 'http://' + d.url).hostname; } catch (e) { /* ignore */ }
            }
            const out = await post('/explain', { verdict: d.prediction, risk: d.risk, reasons: d.reasons, kind, host, lang });
            text.textContent = out.text;
            note.textContent = t('ai_label');
        } catch (err) {
            note.textContent = t(err.message === 'no_key' ? 'ai_nokey' : 'ai_fail');
        } finally {
            aiBtn.disabled = false;
        }
    });
    box.append(text, aiBtn, note);
    $('extra').appendChild(box);
}

function showUrl(d) {
    startCard(d, d.url);
    const badge = (key, flagged) => $('breakdownSection').appendChild(
        el('span', 'badge ' + (flagged ? 'flagged' : ''), t(key) + ': ' + t(flagged ? 'failed' : 'passed')));
    $('breakdownSection').appendChild(el('span', 'badge info', t('decided') + ': ' + t('src_' + d.source)));
    const h = d.heuristics || {};
    badge('b_ip', h.has_ip);
    badge('b_len', h.length > 75);
    badge('b_at', h.has_at);
    badge('b_words', h.suspicious_keywords);
    badge('b_black', (d.blacklist || []).length > 0);

    addPlain(d, 'website link');
    addList('h_why', d.reasons.length ? d.reasons.map(trReason) : [t('no_signs')]);
    if (d.deep) {
        const age = d.deep.domain_age_days;
        addList('h_deep', [t('domain_age', age === null || age === undefined ? t('unknown') : formatAge(age)),
            t('ssl_line', trReason(d.deep.ssl))].concat((d.deep.notes || []).map(trReason)));
    }
    if (d.page_notes && d.page_notes.length) addList('h_page', d.page_notes.map(trReason));
    if (d.top_factors && d.top_factors.length) {
        $('extra').appendChild(ic('h4', null, 'h_factors'));
        d.top_factors.forEach((f) => {
            const row = el('div', 'factor');
            const head = el('div');
            head.append(el('span', null, f.name + ': ' + f.value), el('span', 'muted', f.importance + '%'));
            const track = el('div', 'fbar');
            const fill = el('div');
            fill.style.width = Math.min(f.importance, 100) + '%';
            track.appendChild(fill);
            row.append(head, track);
            $('extra').appendChild(row);
        });
    }
}

function showEmail(d, kind) {
    startCard(d, t('email_sub', d.links.length));
    addPlain(d, kind || 'email');
    addList('h_why', d.reasons.map(trReason));
    if (d.links.length) {
        $('extra').appendChild(ic('h4', null, 'h_links'));
        const ul = el('ul');
        d.links.forEach((l) => ul.appendChild(el('li', 'r-' + l.prediction.toLowerCase(), t('res_' + l.prediction) + ' (' + l.risk + '): ' + l.url)));
        $('extra').appendChild(ul);
    }
}

// ---------- URL form, samples, email ----------
$('phishForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const url = $('urlInput').value.trim();
    if (!url) return;
    run('/predict', { url, deep: $('deepScan').checked, page: $('pageScan').checked }, $('scanBtn'), showUrl);
});

document.querySelectorAll('[data-url]').forEach((b) => b.addEventListener('click', () => {
    $('urlInput').value = b.dataset.url;
    $('phishForm').requestSubmit();
}));

$('emailSample').addEventListener('click', () => { $('emailText').value = SAMPLE_EMAIL; });
$('emailBtn').addEventListener('click', () => {
    const text = $('emailText').value.trim();
    $('emailMsg').textContent = text ? '' : t('email_empty');
    if (text) run('/email', { text }, $('emailBtn'), showEmail);
});

// ---------- SMS / WhatsApp message scanner ----------
function showMessage(d) {
    showEmail(d, 'SMS or WhatsApp message');
    $('resultUrl').textContent = t('msg_sub', d.links.length);
}
document.querySelectorAll('[data-msg]').forEach((b) => b.addEventListener('click', () => { $('msgText').value = SAMPLE_MSGS[b.dataset.msg]; }));
$('msgBtn').addEventListener('click', () => {
    const text = $('msgText').value.trim();
    $('msgMsg').textContent = text ? '' : t('msg_empty');
    if (text) run('/message', { text }, $('msgBtn'), showMessage);
});

// ---------- QR code scanner (the picture is read in the browser, nothing is uploaded) ----------
function readQr(file) {
    const msg = $('qrMsg');
    if (!file) return;
    if (typeof jsQR !== 'function') { msg.textContent = t('qr_nolib'); return; }
    msg.textContent = t('qr_reading');
    const img = new Image();
    const objectUrl = URL.createObjectURL(file);
    img.onload = () => {
        URL.revokeObjectURL(objectUrl);
        const scale = Math.min(1, 1000 / Math.max(img.width, img.height));
        const canvas = $('qrCanvas');
        canvas.width = Math.round(img.width * scale);
        canvas.height = Math.round(img.height * scale);
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        canvas.classList.remove('hidden');
        const pixels = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(pixels.data, canvas.width, canvas.height, { inversionAttempts: 'attemptBoth' });
        if (!code) { msg.textContent = t('qr_none'); return; }
        const text = code.data.trim();
        if (/^(https?:\/\/|www\.)/i.test(text)) {
            msg.textContent = t('qr_link');
            run('/predict', { url: text, deep: false, page: false }, $('qrDrop'), (d) => { showUrl(d); $('resultUrl').textContent = t('from_qr', d.url); });
        } else {
            msg.textContent = t('qr_text', text.slice(0, 80));
        }
    };
    img.onerror = () => { msg.textContent = t('qr_badfile'); };
    img.src = objectUrl;
}
$('qrFile').addEventListener('change', (e) => { readQr(e.target.files[0]); e.target.value = ''; });
['dragover', 'dragenter'].forEach((ev) => $('qrDrop').addEventListener(ev, (e) => { e.preventDefault(); $('qrDrop').classList.add('over'); }));
['dragleave', 'drop'].forEach((ev) => $('qrDrop').addEventListener(ev, () => $('qrDrop').classList.remove('over')));
$('qrDrop').addEventListener('drop', (e) => { e.preventDefault(); readQr(e.dataTransfer.files[0]); });

// ---------- bulk check ----------
const bulk = el('section', 'sec');
bulk.appendChild(ic('h3', null, 'bulk_title'));
bulk.appendChild(ic('p', 'muted', 'bulk_hint'));
const bulkRow = el('div', 'row');
const fileInput = el('input');
fileInput.type = 'file';
fileInput.accept = '.csv,.txt';
const bulkBtn = ic('button', 'btn', 'bulk_btn');
bulkBtn.type = 'button';
bulkRow.append(fileInput, bulkBtn);
const bulkMsg = el('p', 'muted');
const bulkBody = el('tbody');
const bulkTable = el('table');
const bulkHead = el('tr');
['th_url', 'th_result', 'th_risk', 'th_reason'].forEach((k) => bulkHead.appendChild(ic('th', null, k)));
bulkTable.appendChild(el('thead')).appendChild(bulkHead);
bulkTable.appendChild(bulkBody);
const bulkWrap = el('div', 'wrap');
bulkWrap.appendChild(bulkTable);
bulkWrap.classList.add('hidden');
const bulkDownload = ic('button', 'btn', 'bulk_dl');
bulkDownload.type = 'button';
bulkDownload.classList.add('hidden');
bulk.append(bulkRow, bulkMsg, bulkWrap, bulkDownload);
let lastBulk = [];

const csvCell = (v) => '"' + String(v === null || v === undefined ? '' : v).replace(/"/g, '""') + '"';
bulkDownload.addEventListener('click', () => {
    const lines = [['url', 'result', 'risk', 'main reason'].map(csvCell).join(',')];
    lastBulk.forEach((r) => lines.push([r.url, r.prediction, r.risk, r.reason].map(csvCell).join(',')));
    const link = el('a');
    link.href = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' }));
    link.download = 'bulk_results.csv';
    link.click();
    URL.revokeObjectURL(link.href);
});

bulkBtn.addEventListener('click', async () => {
    if (!fileInput.files.length) { bulkMsg.textContent = t('bulk_choose'); return; }
    const body = new FormData();
    body.append('file', fileInput.files[0]);
    bulkBtn.disabled = true;
    bulkMsg.textContent = t('bulk_wait');
    try {
        const res = await fetch('/bulk', { method: 'POST', body });
        const data = await res.json();
        if (!res.ok) { bulkMsg.textContent = data.error || t('err_title'); return; }
        lastBulk = data.results;
        bulkBody.innerHTML = '';
        data.results.forEach((r) => {
            const tr = el('tr');
            tr.append(el('td', 'u', r.url), el('td', 'r-' + r.prediction.toLowerCase(), t('res_' + r.prediction)),
                el('td', null, r.risk === null ? '-' : r.risk), el('td', null, r.reason ? trReason(r.reason) : '-'));
            bulkBody.appendChild(tr);
        });
        bulkWrap.classList.remove('hidden');
        bulkDownload.classList.remove('hidden');
        const bad = data.results.filter((r) => r.prediction === 'Phishing').length;
        const maybe = data.results.filter((r) => r.prediction === 'Suspicious').length;
        bulkMsg.textContent = t('bulk_done', data.count, bad, maybe) + (data.skipped ? t('bulk_skipped', data.skipped) : '');
        loadActivity();
    } catch (err) {
        bulkMsg.textContent = t('bulk_fail');
    } finally {
        bulkBtn.disabled = false;
    }
});

// ---------- charts dashboard (drawn as SVG, so no chart library is needed) ----------
const SVGNS = 'http://www.w3.org/2000/svg';
const svg = (tag, attrs) => {
    const n = document.createElementNS(SVGNS, tag);
    Object.entries(attrs || {}).forEach(([k, v]) => n.setAttribute(k, v));
    return n;
};
const COLORS = { Safe: 'var(--safe)', Suspicious: 'var(--warn)', Phishing: 'var(--danger)' };
const VERDICTS = ['Safe', 'Suspicious', 'Phishing'];

const dash = el('section', 'sec');
dash.appendChild(ic('h3', null, 'dash_title'));
const dashBody = el('div');
dash.appendChild(dashBody);

function renderDashboard(stats, data) {
    dashBody.innerHTML = '';
    if (!stats.total) { dashBody.appendChild(ic('p', 'muted', 'dash_empty')); return; }
    const grid = el('div', 'charts');

    // donut: share of Safe / Suspicious / Phishing
    const box1 = el('div', 'chart-box');
    box1.appendChild(ic('h4', null, 'dash_split'));
    const donut = svg('svg', { viewBox: '0 0 100 100', class: 'donut', role: 'img' });
    const circumference = 2 * Math.PI * 38;
    let offset = 0;
    VERDICTS.forEach((k) => {
        const part = stats[k] / stats.total;
        if (!part) return;
        const arc = svg('circle', { cx: 50, cy: 50, r: 38, fill: 'none', 'stroke-width': 14, transform: 'rotate(-90 50 50)',
            'stroke-dasharray': (part * circumference) + ' ' + circumference, 'stroke-dashoffset': -offset });
        arc.style.stroke = COLORS[k];
        donut.appendChild(arc);
        offset += part * circumference;
    });
    const centre = svg('text', { x: 50, y: 56, 'text-anchor': 'middle', 'font-size': 18, 'font-weight': 700 });
    centre.textContent = stats.total;
    centre.style.fill = 'var(--ink)';
    donut.appendChild(centre);
    box1.appendChild(donut);
    const legend = el('div', 'legend');
    VERDICTS.forEach((k) => {
        const item = el('span', 'legend-item');
        const dot = el('i');
        dot.style.background = COLORS[k];
        item.append(dot, document.createTextNode(t('res_' + k) + ': ' + stats[k]));
        legend.appendChild(item);
    });
    box1.appendChild(legend);

    // stacked bars: scans per day for the last 7 days
    const box2 = el('div', 'chart-box');
    box2.appendChild(ic('h4', null, 'dash_week'));
    const max = Math.max(1, ...data.days.map((d) => d.Safe + d.Suspicious + d.Phishing));
    const bars = svg('svg', { viewBox: '0 0 300 145', class: 'bars', role: 'img' });
    bars.appendChild(svg('line', { x1: 0, y1: 118, x2: 300, y2: 118, stroke: 'var(--line)' }));
    data.days.forEach((d, i) => {
        const x = 8 + i * 41;
        let y = 118;
        VERDICTS.forEach((k) => {
            const h = (d[k] / max) * 90;
            if (!h) return;
            y -= h;
            const rect = svg('rect', { x, y, width: 30, height: h, rx: 3 });
            rect.style.fill = COLORS[k];
            bars.appendChild(rect);
        });
        const total = d.Safe + d.Suspicious + d.Phishing;
        if (total) {
            const num = svg('text', { x: x + 15, y: y - 4, 'text-anchor': 'middle', 'font-size': 9 });
            num.textContent = total;
            num.style.fill = 'var(--mute)';
            bars.appendChild(num);
        }
        const day = svg('text', { x: x + 15, y: 134, 'text-anchor': 'middle', 'font-size': 9 });
        day.textContent = d.date.slice(8, 10) + '/' + d.date.slice(5, 7);
        day.style.fill = 'var(--mute)';
        bars.appendChild(day);
    });
    box2.appendChild(bars);
    grid.append(box1, box2);
    dashBody.appendChild(grid);

    // most common warning signs
    if (data.top_reasons.length) {
        const box3 = el('div', 'chart-box');
        box3.appendChild(ic('h4', null, 'dash_top'));
        const biggest = data.top_reasons[0].count;
        data.top_reasons.forEach((r) => {
            const row = el('div', 'factor');
            const head = el('div');
            head.append(el('span', null, t('rc_' + r.key)), el('span', 'muted', r.count));
            const track = el('div', 'fbar');
            const fill = el('div');
            fill.style.width = (r.count / biggest) * 100 + '%';
            track.appendChild(fill);
            row.append(head, track);
            box3.appendChild(row);
        });
        dashBody.appendChild(box3);
    }
}

// ---------- scan activity ----------
const activity = el('section', 'sec');
activity.appendChild(ic('h3', null, 'act_title'));
const statRow = el('div', 'stats');
const statEls = {};
[['total', 'st_total'], ['Safe', 'res_Safe'], ['Suspicious', 'res_Suspicious'], ['Phishing', 'res_Phishing']].forEach(([key, labelKey]) => {
    const box = el('div', 'stat s-' + key.toLowerCase());
    statEls[key] = el('strong', null, '0');
    box.append(statEls[key], ic('span', null, labelKey));
    statRow.appendChild(box);
});
const histBody = el('tbody');
const histTable = el('table');
const histHead = el('tr');
['th_time', 'th_scanned', 'th_result', 'th_risk'].forEach((k) => histHead.appendChild(ic('th', null, k)));
histTable.appendChild(el('thead')).appendChild(histHead);
histTable.appendChild(histBody);
const histWrap = el('div', 'wrap');
histWrap.appendChild(histTable);
const actions = el('div', 'row');
const dl = ic('a', 'btn', 'act_dl');
dl.href = '/export.csv';
const clearBtn = ic('button', 'btn danger', 'act_clear');
clearBtn.type = 'button';
clearBtn.addEventListener('click', async () => {
    if (!confirm(t('act_confirm'))) return;
    await fetch('/clear', { method: 'POST' });
    loadActivity();
});
actions.append(dl, clearBtn);
activity.append(statRow, histWrap, actions);

// page order under the result card: dashboard, bulk check, scan activity
$('resultContainer').after(activity);
$('resultContainer').after(bulk);
$('resultContainer').after(dash);

async function loadActivity() {
    try {
        const [stats, history, board] = await Promise.all([
            fetch('/stats').then((r) => r.json()), fetch('/history').then((r) => r.json()), fetch('/dashboard').then((r) => r.json())]);
        Object.keys(statEls).forEach((k) => { statEls[k].textContent = stats[k] || 0; });
        renderDashboard(stats, board);
        histBody.innerHTML = '';
        if (!history.length) {
            const td = ic('td', 'muted', 'act_empty');
            td.colSpan = 4;
            histBody.appendChild(el('tr')).appendChild(td);
        }
        history.forEach((h) => {
            const tr = el('tr');
            tr.append(el('td', null, h.created_at), el('td', 'u', h.url), el('td', 'r-' + h.prediction.toLowerCase(), t('res_' + h.prediction)),
                el('td', null, h.confidence === null ? '-' : Math.round(h.confidence)));
            histBody.appendChild(tr);
        });
    } catch (err) {
        console.error('Could not load scan activity:', err);
    }
}

applyLang();