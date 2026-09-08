// Panel Controls — the hosting panel's database-backed settings.
//
// Every control on this page is one row in the shared settings table, so a write
// here changes both load-balanced panel instances. The page is a thin renderer:
// the labels, defaults and bounds all arrive from /api/admin/panel (which reads
// them from database.PANEL_FLAGS / PANEL_LIMITS), so adding a control in the app
// makes it appear here with no edit to this file.
//
// An external file rather than an inline block: this console has no CSP, but the
// script is long enough that keeping it out of the template is worth it.

const $ = s => { try { return document.querySelector(s); } catch(e) { return null; } };

function toast(msg, err=false){
  const t = $('#toast'); if(!t) return;
  t.textContent = msg;
  t.className = 'toast show' + (err ? ' err' : '');
  setTimeout(()=>{ if(t) t.className='toast'; }, 2600);
}

function api(url, opts={}){
  return new Promise(resolve => {
    try {
      const xhr = new XMLHttpRequest();
      xhr.open((opts.method || 'GET'), url, true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      if(window.__deviceFingerprint) xhr.setRequestHeader('X-Device-Fingerprint', window.__deviceFingerprint);
      xhr.timeout = 30000;
      xhr.onload = () => { try { resolve(JSON.parse(xhr.responseText)); } catch(e) { resolve({ok:false, error:'Invalid JSON'}); } };
      xhr.onerror = () => resolve({ok:false, error:'Network error'});
      xhr.ontimeout = () => resolve({ok:false, error:'Request timed out'});
      xhr.send(opts.body || null);
    } catch(e) { resolve({ok:false, error:'Network error: ' + e.message}); }
  });
}

function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

let STATE = { flags: [], limits: [], maintenance_message: '', message_max: 240 };

// Only the newest overview fetch may paint, and a write repaints just its own
// section. Without this, flipping two switches quickly lets the first write's
// refresh revert the second from a response issued before it landed — the same
// guard the Ads page carries.
let loadSeq = 0;

function flag(key){ return STATE.flags.find(f => f.key === key); }

// Maintenance is rendered on its own rather than in the switch list: it is the
// one control that changes what every *other* control means, so it gets the
// banner and the top card.
function renderMaintenance(){
  const on = !!(flag('maintenance') || {}).enabled;

  const banner = $('#maint-banner');
  if(banner){
    banner.innerHTML = on
      ? `<div class="flag-banner sev-warn" style="margin-bottom:18px"><span class="fb-dot"></span>
           <span><strong>Maintenance mode is ON.</strong> Deploys, power actions, file writes and console commands are being refused across both panel instances. Containers already running are unaffected.</span></div>`
      : '';
  }

  const host = $('#maint-control');
  if(host){
    host.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 0">
        <div>
          <div style="font-size:14px">Put the panel into maintenance</div>
          <div style="font-size:11px;color:var(--muted)">Default: off — the panel is fully writable.</div>
        </div>
        <label class="toggle-wrap toggle-danger" style="flex-shrink:0">
          <input type="checkbox" id="maint-toggle" ${on ? 'checked' : ''}>
          <span class="toggle-slider"></span><span class="toggle-knob"></span>
        </label>
      </div>`;
    const el = $('#maint-toggle');
    if(el) el.addEventListener('change', () => setFlag(el, 'maintenance'));
  }
}

function renderStats(){
  const host = $('#stat-strip'); if(!host) return;
  const maint = !!(flag('maintenance') || {}).enabled;
  const byKey = {};
  STATE.limits.forEach(l => { byKey[l.key] = l; });
  const changed = STATE.flags.filter(f => f.enabled !== f.default).length
                + STATE.limits.filter(l => l.value !== l.default).length;
  const val = (k, suffix='') => byKey[k] ? esc(byKey[k].value + suffix) : '—';

  const tiles = [
    {cls: maint ? 'stat stat-warn' : 'stat stat-ok', ic: maint ? '!' : '✓',
     sv: maint ? 'Maintenance' : 'Live', sl: 'Panel state'},
    {cls: 'stat', ic: '#', sv: val('max_servers'), sl: 'Servers / account'},
    {cls: 'stat', ic: 'M', sv: val('memory_mb', ' MB'), sl: 'Memory / server'},
    {cls: 'stat', ic: 'C', sv: val('cpu_percent', '%'), sl: 'CPU / server'},
    {cls: 'stat', ic: 'D', sv: val('disk_mb', ' MB'), sl: 'Disk / server'},
    {cls: 'stat', ic: '~', sv: String(changed), sl: 'Off default'},
  ];
  host.innerHTML = tiles.map(t => `
    <div class="${t.cls}">
      <div class="s-head"><span class="s-ic">${esc(t.ic)}</span><span class="sl">${esc(t.sl)}</span></div>
      <div class="sv">${t.sv}</div>
    </div>`).join('');
}

function renderFlags(){
  const host = $('#flag-list'); if(!host) return;
  // Maintenance has its own card above, so it is not repeated in this list.
  const rows = STATE.flags.filter(f => f.key !== 'maintenance');
  if(!rows.length){ host.innerHTML = '<div class="empty">No switches available.</div>'; return; }
  host.innerHTML = rows.map(f => `
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;padding:12px 0;border-bottom:1px solid var(--line)">
      <div>
        <div style="font-size:14px">${esc(f.label)}
          ${f.enabled === f.default ? '' : '<span class="badge warn" style="margin-left:6px">changed</span>'}
        </div>
        <div style="font-size:11px;color:var(--muted);line-height:1.6">${esc(f.detail)}</div>
        <div style="font-size:11px;color:var(--muted2);margin-top:4px">Default: ${f.default ? 'on' : 'off'} · key <code>${esc(f.key)}</code></div>
      </div>
      <label class="toggle-wrap toggle-sm" style="flex-shrink:0;margin-top:2px">
        <input type="checkbox" data-flag="${esc(f.key)}" ${f.enabled ? 'checked' : ''}>
        <span class="toggle-slider"></span><span class="toggle-knob"></span>
      </label>
    </div>`).join('');
  host.querySelectorAll('input[data-flag]').forEach(el => {
    el.addEventListener('change', () => setFlag(el, el.dataset.flag));
  });
}

function renderLimits(){
  const host = $('#limit-list'); if(!host) return;
  if(!STATE.limits.length){ host.innerHTML = '<div class="empty">No limits available.</div>'; return; }
  host.innerHTML = STATE.limits.map(l => `
    <div style="padding:12px 0;border-bottom:1px solid var(--line)">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px">
        <div style="font-size:14px">${esc(l.label)}
          ${l.value === l.default ? '' : '<span class="badge warn" style="margin-left:6px">changed</span>'}
        </div>
        <div class="field limit-field" style="display:flex;align-items:center;gap:8px;flex-shrink:0;margin-bottom:0">
          <input type="number" data-limit="${esc(l.key)}" value="${esc(l.value)}"
                 min="${esc(l.low)}" max="${esc(l.high)}" step="1"
                 aria-label="${esc(l.label)} (${esc(l.unit)})">
          <button class="btn btn-sm" data-save="${esc(l.key)}">Save</button>
        </div>
      </div>
      <div style="font-size:11px;color:var(--muted2);margin-top:6px">${esc(l.unit)} · allowed ${esc(l.low)}–${esc(l.high)} · default ${esc(l.default)}${l.key === 'max_servers' ? ' · the figure every account gets unless its own page grants it a different one (Panel → a user → Hosting Containers)' : ''}</div>
    </div>`).join('');
  host.querySelectorAll('button[data-save]').forEach(el => {
    el.addEventListener('click', () => setLimit(el.dataset.save));
  });
  // Enter in the number field saves that row, so the button is not the only way.
  host.querySelectorAll('input[data-limit]').forEach(el => {
    el.addEventListener('keydown', ev => {
      if(ev.key === 'Enter'){ ev.preventDefault(); setLimit(el.dataset.limit); }
    });
  });
}

function renderMessage(){
  const box = $('#maint-message'); if(!box) return;
  // Only repainted from a fetch, never from a render triggered by a toggle:
  // overwriting the field while it is being typed into would lose the edit.
  box.value = STATE.maintenance_message || '';
  box.maxLength = STATE.message_max;
  const max = $('#msg-max');
  if(max) max.textContent = String(STATE.message_max);
  countMessage();
}

function countMessage(){
  const box = $('#maint-message'), out = $('#msg-count');
  if(box && out) out.textContent = String(box.value.length);
}

function render(){
  renderMaintenance();
  renderStats();
  renderFlags();
  renderLimits();
}

async function load(){
  const seq = ++loadSeq;
  const r = await api('/api/admin/panel');
  if(seq !== loadSeq) return;
  if(r && r.ok){
    STATE = {
      flags: r.flags || [],
      limits: r.limits || [],
      maintenance_message: r.maintenance_message || '',
      message_max: r.message_max || 240,
    };
    render();
    renderMessage();
  } else {
    toast((r && r.error) || 'Error loading panel controls', true);
  }
}

async function setFlag(el, key){
  const enabled = el.checked;
  el.disabled = true;
  const r = await api('/api/admin/panel/flags/' + encodeURIComponent(key),
                      {method:'PUT', body:JSON.stringify({enabled})});
  el.disabled = false;
  const f = flag(key);
  if(r && r.ok){
    if(f) f.enabled = !!r.enabled;
    toast(((f && f.label) || key) + (r.enabled ? ' enabled' : ' disabled'));
    // Maintenance changes the banner and the state tile, so the whole page is
    // repainted for it; a plain switch only needs its own list back.
    if(key === 'maintenance'){ render(); } else { renderFlags(); renderStats(); }
  } else {
    el.checked = !enabled;
    toast((r && r.error) || 'Failed', true);
  }
}

async function setLimit(key){
  const input = document.querySelector('input[data-limit="' + key + '"]');
  const btn = document.querySelector('button[data-save="' + key + '"]');
  if(!input) return;
  const raw = input.value.trim();
  if(raw === ''){ toast('Enter a number', true); return; }
  if(btn) btn.disabled = true;
  const r = await api('/api/admin/panel/limits/' + encodeURIComponent(key),
                      {method:'PUT', body:JSON.stringify({value: raw})});
  if(btn) btn.disabled = false;
  const l = STATE.limits.find(x => x.key === key);
  if(r && r.ok){
    if(l) l.value = r.value;
    // Repainted from the response, not the input: the stored value is clamped,
    // so echoing what was typed could show a number that is not in force.
    renderLimits();
    renderStats();
    toast(((l && l.label) || key) + ' set to ' + r.value);
  } else {
    if(l) input.value = l.value;
    toast((r && r.error) || 'Failed', true);
  }
}

async function saveMessage(){
  const box = $('#maint-message'), btn = $('#msg-save');
  if(!box) return;
  if(btn) btn.disabled = true;
  const r = await api('/api/admin/panel/maintenance-message',
                      {method:'PUT', body:JSON.stringify({message: box.value})});
  if(btn) btn.disabled = false;
  if(r && r.ok){
    STATE.maintenance_message = r.message || '';
    // The server substitutes the default for an empty submission, so the box is
    // refilled from what was actually stored.
    box.value = STATE.maintenance_message;
    countMessage();
    toast('Banner text saved');
  } else {
    toast((r && r.error) || 'Failed', true);
  }
}

const msgBox = $('#maint-message');
if(msgBox) msgBox.addEventListener('input', countMessage);
const msgBtn = $('#msg-save');
if(msgBtn) msgBtn.addEventListener('click', saveMessage);

load();
