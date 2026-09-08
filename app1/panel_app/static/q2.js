(() => {
  const search = document.getElementById('server-search');
  if (search) {
    search.addEventListener('input', function () {
      const query = this.value.trim().toLowerCase();
      let visible = 0;
      document.querySelectorAll('.server-row-wrap').forEach(function (wrap) {
        
        
        
        const haystack = wrap.dataset.searchText || '';
        const match = !query || haystack.includes(query);
        wrap.style.display = match ? '' : 'none';
        if (match) visible += 1;
      });
      const empty = document.getElementById('search-empty');
      if (empty) empty.hidden = visible !== 0;
    });
  }

  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  
  const PANEL_BASE = document.querySelector('meta[name="panel-base"]')?.content || '';

  const STATUS_LABELS = {
    running: 'Running',
    stopped: 'Stopped',
    exited: 'Exited',
    created: 'Created',
    paused: 'Paused',
    restarting: 'Restarting',
    missing: 'Missing on node',
    installing: 'Installing',
    failed: 'Install failed',
    unknown: 'Unknown',
  };

  const applyStatus = (wrap, info) => {
    const cell = wrap.querySelector('.status-cell');
    if (!cell) return;
    let state = info.status || 'missing';
    if (info.install_status === 'running') state = 'installing';
    else if (info.install_status === 'failed') state = 'failed';
    const dot = cell.querySelector('.status-dot');
    const label = cell.querySelector('strong');
    if (dot) dot.className = `status-dot ${state}`;
    if (label) label.textContent = STATUS_LABELS[state] || state;

    const powerForm = wrap.querySelector('[data-power-form]');
    if (powerForm) {
      const button = powerForm.querySelector('button');
      if (button && info.install_status !== 'running') {
        if (state === 'running') {
          button.className = 'button button-danger-ghost button-small';
          button.value = 'stop';
          button.textContent = 'Stop';
          button.title = 'Stop server';
          button.hidden = false;
        } else if (state !== 'missing') {
          button.className = 'button button-ghost button-small';
          button.value = 'start';
          button.textContent = 'Start';
          button.title = 'Start server';
          button.hidden = false;
        } else if (button) {
          button.hidden = true;
        }
      }
    }
  };

  const refreshStatuses = async () => {
    try {
      const response = await fetch(PANEL_BASE + '/api/servers/status', { credentials: 'same-origin' });
      if (!response.ok) return;
      const data = await response.json();
      if (!data || data.ok === false) return;
      Object.entries(data.servers || {}).forEach(([id, info]) => {
        
        
        
        const selector = `.server-row-wrap [data-server-id="${CSS.escape(id)}"]`;
        const wrap = document.querySelector(selector)?.closest('.server-row-wrap');
        if (wrap) applyStatus(wrap, info);
      });
      const runningStat = document.querySelector('[data-stat-running]');
      if (runningStat) runningStat.textContent = `${data.running} running`;
    } catch (error) {
      
    }
  };

  document.querySelectorAll('[data-power-form]').forEach(function (form) {
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      const button = form.querySelector('button');
      if (!button) return;
      const action = button.value;
      button.disabled = true;
      
      
      button.setAttribute('aria-busy', 'true');
      fetch(form.action, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: action }),
      })
        .then(function (response) { return response.json().catch(() => ({})); })
        .then(function (data) {
          if (data && data.warning) window.showToast?.(data.warning, 'error');
          return refreshStatuses();
        })
        .catch(function () {  })
        .finally(function () {
          button.disabled = false;
          button.removeAttribute('aria-busy');
        });
    });
  });

  
  const BASE_INTERVAL = 6000;
  const MAX_INTERVAL = 30000;
  let pollDelay = BASE_INTERVAL;
  let pollTimer = null;
  let polling = false;

  const schedule = (delay) => {
    if (pollTimer) clearTimeout(pollTimer);
    if (document.hidden) return;
    pollTimer = setTimeout(tick, delay);
  };

  async function tick() {
    if (polling || document.hidden) return;
    polling = true;
    try {
      await refreshStatuses();
      pollDelay = BASE_INTERVAL;
    } catch (error) {
      pollDelay = Math.min(MAX_INTERVAL, Math.round(pollDelay * 1.8));
    } finally {
      polling = false;
      schedule(pollDelay);
    }
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    } else if (document.querySelector('.server-row-wrap')) {
      pollDelay = BASE_INTERVAL;
      tick();
    }
  });

  if (document.querySelector('.server-row-wrap')) tick();
})();
