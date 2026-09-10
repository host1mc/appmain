(() => {
  const root = document.getElementById('server-app');
  if (!root) return;
  const serverId = encodeURIComponent(root.dataset.serverId);
  const runtimeName = (root.dataset.runtime || '').toLowerCase();
  
  
  
  
  const MEMORY_LIMIT_BYTES = (Number(root.dataset.memoryMb) || 0) * 1024 * 1024;
  
  
  
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';

  
  
  
  
  
  const setBusy = (element, busy) => {
    if (!element) return;
    element.disabled = busy;
    if (busy) element.setAttribute('aria-busy', 'true');
    else element.removeAttribute('aria-busy');
  };
  
  const PANEL_BASE = document.querySelector('meta[name="panel-base"]')?.content || '';
  const output = document.getElementById('console-output');
  const statusText = document.getElementById('server-status');
  const statusDot = document.querySelector('.server-status .status-dot');
  const memoryValue = document.getElementById('memory-value');
  const memoryMeter = document.getElementById('memory-meter');
  const cpuValue = document.getElementById('cpu-value');
  const cpuMeter = document.getElementById('cpu-meter');
  const storageValue = document.getElementById('storage-value');
  const storageMeter = document.getElementById('storage-meter');
  const storageTotal = document.getElementById('storage-total');
  const networkValue = document.getElementById('network-value');
  const networkIn = networkValue?.querySelector('.net-in');
  const networkOut = networkValue?.querySelector('.net-out');
  const networkTotal = document.getElementById('network-total');
  const containerId = document.getElementById('container-id');
  const memorySpark = document.getElementById('memory-spark');
  const cpuSpark = document.getElementById('cpu-spark');
  const networkSpark = document.getElementById('network-spark');
  const SPARK_POINTS = 40;
  const memoryHistory = [];
  const cpuHistory = [];
  const networkHistory = [];
  let lastNetworkRx = null;
  let lastNetworkTx = null;
  let lastNetworkAt = 0;
  let currentPath = '';
  let logsCleared = false;
  let consoleSince = 0;
  let streamEpoch = 0;
  let lastState = null;
  const commandHistory = [];
  let historyIndex = -1;
  let historyDraft = '';
  let pkgDir = '.';
  let pkgInstallCommand = runtimeName === 'python' ? 'pip install -r requirements.txt'
    : runtimeName === 'ruby' ? 'bundle install'
      : runtimeName === 'bun' ? 'bun install'
        : runtimeName === 'go' ? 'go mod download'
          : runtimeName === 'php' ? 'composer install'
            : 'npm install';

  const shellQuote = (value) => {
    const text = String(value || '');
    return /^[A-Za-z0-9_./:-]+$/.test(text) ? text : `'${text.replace(/'/g, `'\\''`)}'`;
  };

  const dirname = (path) => path.includes('/') ? path.substring(0, path.lastIndexOf('/')) || '.' : '.';
  const basename = (path) => path.includes('/') ? path.substring(path.lastIndexOf('/') + 1) : path;
  const pathFromPackageDir = (path) => {
    if (pkgDir === '.') return path;
    return path.startsWith(`${pkgDir}/`) ? path.substring(pkgDir.length + 1) : path;

  };

  const startupCommandFor = (path, name) => {
    const ext = (name.split('.').pop() || '').toLowerCase();
    const runPath = pathFromPackageDir(path);
    if (runtimeName === 'python' || ext === 'py') return `python ${shellQuote(runPath)}`;
    if (runtimeName === 'ruby' || ext === 'rb') return `ruby ${shellQuote(runPath)}`;
    if (runtimeName === 'go' || ext === 'go') return basename(runPath) === 'main.go' ? 'go run .' : `go run ${shellQuote(runPath)}`;
    if (runtimeName === 'php' || ext === 'php') return `php ${shellQuote(runPath)}`;
    if (runtimeName === 'bun' || ext === 'ts') return `bun run ${shellQuote(runPath)}`;
    return `node ${shellQuote(runPath)}`;
  };

  const packageInstallFor = (path, name) => {
    const dir = dirname(path);
    const file = shellQuote(basename(path));
    const installers = {
      'package.json': runtimeName === 'bun' ? 'bun install' : 'npm install',
      'requirements.txt': `pip install -r ${file}`,
      'Gemfile': 'bundle install',
      'go.mod': 'go mod download',
      'composer.json': 'composer install',
    };
    const install = installers[name];
    if (!install) return null;
    return {
      dir,
      install,
    };
  };

  const packageButtonLabel = (name) => {
    if (name === 'requirements.txt') return 'Pip Install';
    if (name === 'Gemfile') return 'Bundle Install';
    if (name === 'go.mod') return 'Go Download';
    if (name === 'composer.json') return 'Composer Install';
    return runtimeName === 'bun' ? 'Bun Install' : 'Pkg Install';
  };
  const publicLabel = async (value) => {
    const text = String(value || '');
    if (!text) return '';
    try {
      const bytes = new TextEncoder().encode(`panel-public-label-v1:${text}`);
      const digest = await crypto.subtle.digest('SHA-256', bytes);
      return Array.from(new Uint8Array(digest.slice(0, 4)), (byte) => byte.toString(16).padStart(2, '0')).join('');
    } catch {
      return 'masked';
    }
  };

  const api = async (path, options = {}) => {
    const headers = { ...(options.headers || {}) };
    if (options.method && options.method !== 'GET') {
      if (!(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
      headers['X-CSRF-Token'] = csrf;
    }
    const response = await fetch(PANEL_BASE + path, { credentials: 'same-origin', ...options, headers });
    let data;
    try {
      data = await response.json();
    } catch {
      const text = (await response.text().catch(() => '')).trim().slice(0, 200);
      data = { ok: false, error: text || `Request failed (${response.status})` };
    }
    if (!response.ok || data.ok === false) throw new Error(data.error || `Request failed (${response.status})`);
    if (data && data.warning) window.showToast?.(data.warning, 'error');
    return data;
  };

  
  
  
  
  
  
  
  
  const upload = (path, form, onProgress) => new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open('POST', PANEL_BASE + path);
    request.setRequestHeader('X-CSRF-Token', csrf);
    
    
    
    request.withCredentials = true;
    request.upload.addEventListener('progress', (event) => {
      
      
      
      if (event.lengthComputable) onProgress(event.loaded, event.total);
    });
    request.addEventListener('load', () => {
      let data;
      try {
        data = JSON.parse(request.responseText);
      } catch {
        const text = (request.responseText || '').trim().slice(0, 200);
        data = { ok: false, error: text || `Request failed (${request.status})` };
      }
      if (request.status < 200 || request.status >= 300 || data.ok === false) {
        reject(new Error(data.error || `Request failed (${request.status})`));
        return;
      }
      resolve(data);
    });
    request.addEventListener('error', () => reject(new Error('Upload failed — the connection dropped')));
    request.addEventListener('abort', () => reject(new Error('Upload cancelled')));
    request.send(form);
  });

  const bytes = (value) => {
    const number = Number(value || 0);
    if (number < 1024) return `${number} B`;
    if (number < 1024 ** 2) return `${(number / 1024).toFixed(1)} KB`;
    if (number < 1024 ** 3) return `${(number / 1024 ** 2).toFixed(1)} MB`;
    return `${(number / 1024 ** 3).toFixed(1)} GB`;
  };

  
  
  
  
  
  const netBytes = (value) => {
    const number = Math.max(0, Number(value || 0));
    if (number < 1024 ** 2) return `${(number / 1024).toFixed(1)} KB`;
    if (number < 1024 ** 3) return `${(number / 1024 ** 2).toFixed(1)} MB`;
    return `${(number / 1024 ** 3).toFixed(2)} GB`;
  };

  
  
  
  
  const setNetwork = (rxRate, txRate, rxTotal, txTotal) => {
    if (networkIn) networkIn.textContent = `↓ ${netBytes(rxRate)}/s`;
    if (networkOut) networkOut.textContent = `↑ ${netBytes(txRate)}/s`;
    if (networkTotal) {
      networkTotal.textContent = `${netBytes(rxTotal)} in / ${netBytes(txTotal)} out`;
    }
  };

  
  
  
  
  
  
  const CONSOLE_MAX_CHARS = 262144;

  const appendConsole = (text) => {
    output.textContent += text;
    if (output.textContent.length > CONSOLE_MAX_CHARS) {
      const kept = output.textContent.slice(-CONSOLE_MAX_CHARS);
      const firstBreak = kept.indexOf('\n');
      output.textContent = firstBreak === -1 ? kept : kept.slice(firstBreak + 1);
    }
    output.scrollTop = output.scrollHeight;
  };

  const setStatus = (value) => {
    if (statusText) statusText.textContent = value;
    if (statusDot) statusDot.className = `status-dot ${value}`;
    
    if (value === 'running') {
      if (!wsShouldConnect) {
        wsShouldConnect = true;
        connectWs();
      }
    } else {
      disconnectWs();
    }
  };

  
  
  
  
  
  const drawSpark = (svg, history, value, { max, hotAt } = {}) => {
    if (!svg) return;
    history.push(Math.max(0, value));
    if (history.length > SPARK_POINTS) history.shift();
    const polyline = svg.querySelector('polyline');
    if (!polyline) return;
    const scale = max || Math.max(...history, 1e-9);
    const step = history.length > 1 ? 100 / (history.length - 1) : 0;
    const points = history
      .map((sample, index) => {
        const ratio = Math.max(0, Math.min(1, sample / scale));
        return `${(index * step).toFixed(2)},${(29 - ratio * 28).toFixed(2)}`;
      })
      .join(' ');
    polyline.setAttribute('points', points);
    if (hotAt != null) svg.classList.toggle('hot', value >= hotAt);
  };

  const formatUptime = (iso) => {
    if (!iso) return '';
    const elapsed = Date.now() - new Date(iso).getTime();
    if (!(elapsed >= 0)) return '';
    const totalSeconds = Math.floor(elapsed / 1000);
    const seconds = totalSeconds % 60;
    const minutes = Math.floor(totalSeconds / 60) % 60;
    const hours = Math.floor(totalSeconds / 3600);
    if (hours > 0) return `Up ${hours}h ${minutes}m`;
    if (minutes > 0) return `Up ${minutes}m ${seconds}s`;
    return `Up ${seconds}s`;
  };

  
  
  
  const setConsoleEnabled = (enabled) => {
    const input = document.getElementById('command-input');
    if (!input) return;
    const form = document.getElementById('command-form');
    input.disabled = !enabled;
    form?.querySelector('button[type="submit"]')?.toggleAttribute('disabled', !enabled);
    input.placeholder = enabled
      ? 'Run a command inside the container'
      : 'Start the server to run commands';
  };

  const setPowerEnabled = (enabled, restartEnabled = enabled) => {
    document.querySelectorAll('[data-power]').forEach((button) => {
      const allowed = button.dataset.power === 'restart' ? restartEnabled : enabled;
      button.disabled = !allowed;
    });
  };

  const updateUptime = () => {
    if (document.hidden) return;
    const uptimeEl = document.getElementById('server-uptime');
    if (uptimeEl && uptimeEl.dataset.startedAt) {
      uptimeEl.textContent = formatUptime(uptimeEl.dataset.startedAt);
    }
  };

  const refreshState = async (prefetched) => {
    try {
      const data = prefetched || await api(`/api/servers/${serverId}/state`);
      lastState = data;
      const server = data.server;
      const installing = server.install_status === 'running';
      setPowerEnabled(!installing);
      setStatus(installing ? 'installing' : (server.status || 'unknown'));
      setConsoleEnabled(!installing && server.status === 'running');
      if (server.container_id) {
        const containerLabel = await publicLabel(server.container_id);
        containerId.replaceChildren(
          `Container ${containerLabel}`,
          document.createTextNode(' '),
          (() => {
            const copy = document.createElement('button');
            copy.type = 'button';
            copy.className = 'copy-button';
            copy.textContent = 'Copy';
            copy.dataset.copy = containerLabel;
            return copy;
          })()
        );
        if (server.status === 'running' && server.started_at) {
          const uptime = document.createElement('span');
          uptime.id = 'server-uptime';
          uptime.dataset.startedAt = server.started_at;
          uptime.textContent = formatUptime(server.started_at);
          containerId.append(document.createElement('br'), uptime);
        }
      } else {
        containerId.textContent = 'Container unavailable';
      }
      const used = Number(server.memory_bytes || 0);
      const limit = Number(server.memory_limit || MEMORY_LIMIT_BYTES);
      const memoryPercent = limit ? used / limit * 100 : 0;
      memoryValue.textContent = bytes(used);
      memoryMeter.style.width = `${Math.min(100, memoryPercent)}%`;
      drawSpark(memorySpark, memoryHistory, memoryPercent, { max: 100, hotAt: 90 });
      const cpu = Number(server.cpu_percent || 0);
      cpuValue.textContent = `${cpu.toFixed(1)}%`;
      cpuMeter.style.width = `${Math.min(100, cpu)}%`;
      drawSpark(cpuSpark, cpuHistory, cpu, { max: 100, hotAt: 90 });
      const diskUsed = Number(server.disk_used_bytes || 0);
      const diskTotal = Number(server.disk_total_bytes || 0);
      storageValue.textContent = bytes(diskUsed);
      storageTotal.textContent = `${bytes(diskTotal)} total / ${bytes(server.disk_free_bytes)} free`;
      storageMeter.style.width = `${Math.min(100, diskTotal ? diskUsed / diskTotal * 100 : 0)}%`;
      const rxTotal = Number(server.network_rx_bytes || 0);
      const txTotal = Number(server.network_tx_bytes || 0);
      const now = Date.now();
      if (server.status === 'running' && lastNetworkRx != null && now > lastNetworkAt) {
        const seconds = (now - lastNetworkAt) / 1000;
        
        
        
        
        const rxRate = Math.max(0, (rxTotal - lastNetworkRx) / seconds);
        const txRate = Math.max(0, (txTotal - lastNetworkTx) / seconds);
        setNetwork(rxRate, txRate, rxTotal, txTotal);
        drawSpark(networkSpark, networkHistory, rxRate + txRate);
      } else {
        
        
        setNetwork(0, 0, rxTotal, txTotal);
      }
      lastNetworkRx = rxTotal;
      lastNetworkTx = txTotal;
      lastNetworkAt = now;
    } catch (error) {
      setStatus('unavailable');
      containerId.textContent = error.message;
      setPowerEnabled(true, lastState?.server?.install_status !== 'running');
      setConsoleEnabled(true);
    }
  };

  const refreshLogs = async (prefetched) => {
    try {
      const state = prefetched || lastState || await api(`/api/servers/${serverId}/state`);
      if (state.server.install_status === 'running') {
        const install = await api(`/api/servers/${serverId}/install`);
        if (!logsCleared) {
          output.textContent = `Installing dependencies (this can take a few minutes)…\n\n${install.log || ''}`;
          output.scrollTop = output.scrollHeight;
        }
        return;
      }
      if (state.server.install_status === 'failed') {
        if (!logsCleared) output.textContent = `Installation failed: ${state.server.install_error || 'unknown error'}`;
        return;
      }
      const data = await api(`/api/servers/${serverId}/logs?tail=300`);
      if (!logsCleared) {
        const nearBottom = output.scrollHeight - output.scrollTop - output.clientHeight < 80;
        output.textContent = data.logs || 'No output yet.';
        if (nearBottom) output.scrollTop = output.scrollHeight;
      }
    } catch (error) {
      if (!logsCleared) output.textContent = `Unable to read logs: ${error.message}`;
    }
  };

  document.querySelectorAll('[data-power]').forEach((button) => {
    button.addEventListener('click', async () => {
      setBusy(button, true);
      try {
        await api(`/api/servers/${serverId}/power`, {
          method: 'POST',
          body: JSON.stringify({ action: button.dataset.power }),
        });
        await refreshState();
        await refreshLogs();
        if (ws) { ws.close(); ws = null; wsConnected = false; }
        window.showToast?.(`Server ${button.dataset.power}ed`);
      } catch (error) {
        window.showToast?.(error.message, 'error');
      } finally {
        setBusy(button, false);
      }
    });
  });

  document.getElementById('command-form')?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = document.getElementById('command-input');
    const command = input.value.trim();
    if (!command) return;
    if (commandHistory[commandHistory.length - 1] !== command) commandHistory.push(command);
    if (commandHistory.length > 100) commandHistory.shift();
    historyIndex = -1;
    historyDraft = '';
    setBusy(input, true);
    try {
      await api(`/api/servers/${serverId}/command`, {
        method: 'POST',
        body: JSON.stringify({ command }),
      });
      appendConsole(`\n$ ${command}`);
      input.value = '';
    } catch (error) {
      window.showToast?.(error.message, 'error');
    } finally {
      setBusy(input, false);
      input.focus();
    }
  });

  document.getElementById('command-input')?.addEventListener('keydown', (event) => {
    if (event.key !== 'ArrowUp' && event.key !== 'ArrowDown') return;
    if (!commandHistory.length) return;
    const input = event.currentTarget;
    event.preventDefault();
    if (event.key === 'ArrowUp') {
      if (historyIndex === -1) {
        historyDraft = input.value;
        historyIndex = commandHistory.length - 1;
      } else if (historyIndex > 0) {
        historyIndex -= 1;
      }
    } else {
      if (historyIndex === -1) return;
      if (historyIndex < commandHistory.length - 1) {
        historyIndex += 1;
      } else {
        historyIndex = -1;
      }
    }
    input.value = historyIndex === -1 ? historyDraft : commandHistory[historyIndex];
    const end = input.value.length;
    input.setSelectionRange(end, end);
  });

  document.getElementById('clear-console')?.addEventListener('click', () => {
    logsCleared = true;
    consoleSince = Date.now() / 1000;
    streamEpoch += 1;
    output.textContent = '';
    const stale = ws;
    ws = null;
    wsConnected = false;
    try { stale?.close(); } catch (_) {}
    if (wsShouldConnect) connectWs();
  });

  document.getElementById('download-console')?.addEventListener('click', () => {
    
    
    
    
    
    const text = output.textContent || '';
    if (!text.trim()) {
      window.showToast?.('Console is empty', 'error');
      return;
    }
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `console-${serverId}.log`;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  });

  
  document.getElementById('save-rename')?.addEventListener('click', async () => {
    const button = document.getElementById('save-rename');
    const input = document.getElementById('rename-input');
    const name = input.value.trim();
    if (!name) {
      window.showToast?.('Server name is required', 'error');
      return;
    }
    setBusy(button, true);
    try {
      const data = await api(`/api/servers/${serverId}/rename`, {
        method: 'POST',
        body: JSON.stringify({ name }),
      });
      document.getElementById('server-title').textContent = data.name;
      const context = document.querySelector('.topbar-context');
      if (context) context.textContent = `Servers / ${data.name}`;
      window.showToast?.('Server renamed');
    } catch (error) {
      window.showToast?.(error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  });

  
  (() => {
    const card = document.getElementById('runtime-change-card');
    const select = document.getElementById('runtime-select');
    const input = document.getElementById('startup-input');
    const warning = document.getElementById('runtime-change-warning');
    const applyRuntimeBtn = document.getElementById('apply-runtime-change');
    const cancelRuntimeBtn = document.getElementById('cancel-runtime-change');
    const runtimeStatus = document.getElementById('runtime-apply-status');
    const applyStartupBtn = document.getElementById('apply-startup-change');
    const cancelStartupBtn = document.getElementById('cancel-startup-change');
    const startupStatus = document.getElementById('startup-apply-status');
    if (!card || !select || !input || !warning) return;
    let savedStartup = card.dataset.currentStartup || '';
    let savedRuntimeKey = select.dataset.currentRuntime || '';
    let savedVersionKey = select.dataset.currentVersion || '';
    let lastRuntimeKey = savedRuntimeKey;

    const runtimeDirty = () => select.value !== `${savedRuntimeKey}|${savedVersionKey}`;
    const startupDirty = () => input.value !== savedStartup;

    const syncDirtyUi = () => {
      const rtDirty = runtimeDirty();
      const stDirty = startupDirty();
      warning.hidden = !(rtDirty || stDirty);
      if (cancelRuntimeBtn) cancelRuntimeBtn.hidden = !rtDirty;
      if (applyRuntimeBtn) applyRuntimeBtn.disabled = !rtDirty;
      if (cancelStartupBtn) cancelStartupBtn.hidden = !stDirty;
      if (applyStartupBtn) applyStartupBtn.disabled = !stDirty;
      if (rtDirty || stDirty) {
        document.querySelectorAll('[data-power]').forEach((btn) => { btn.disabled = true; });
      } else {
        const installing = lastState?.server?.install_status === 'running';
        document.querySelectorAll('[data-power]').forEach((btn) => {
          btn.disabled = installing;
        });
        setConsoleEnabled(!installing && lastState?.server?.status === 'running');
      }
    };

    select.addEventListener('change', () => {
      const option = select.selectedOptions[0];
      const nextRuntime = (option && option.dataset.runtime) || '';
      if (nextRuntime && nextRuntime !== lastRuntimeKey) {
        const next = (option && option.dataset.defaultStartup) || '';
        if (next) input.value = next;
        lastRuntimeKey = nextRuntime;
      }
      syncDirtyUi();
    });
    input.addEventListener('input', syncDirtyUi);

    const applyWithTimer = async (button, cancel, statusEl, path, body, okMessage) => {
      if (button) button.disabled = true;
      if (cancel) cancel.disabled = true;
      const startedAt = Date.now();
      const tick = () => {
        if (!statusEl) return;
        const s = Math.floor((Date.now() - startedAt) / 1000);
        statusEl.textContent = `Applying… ${s}s (rebuilding the container can take a few minutes)`;
      };
      tick();
      const timer = setInterval(tick, 1000);
      try {
        const data = await api(path, { method: 'POST', body: JSON.stringify(body) });
        if (data.warning && statusEl) statusEl.textContent = data.warning;
        window.showToast?.(okMessage);
        await new Promise((r) => setTimeout(r, 800));
        window.location.reload();
      } catch (error) {
        const msg = /timed?\s*out/i.test(error.message)
          ? 'The node took too long to answer. The change may still have gone through — reload this page in a minute to check before retrying.'
          : error.message;
        if (statusEl) statusEl.textContent = msg;
        window.showToast?.(msg, 'error');
      } finally {
        clearInterval(timer);
        if (button) button.disabled = false;
        if (cancel) cancel.disabled = false;
        syncDirtyUi();
      }
    };

    applyRuntimeBtn?.addEventListener('click', () => {
      const [runtime, version] = select.value.split('|');
      applyWithTimer(
        applyRuntimeBtn, cancelRuntimeBtn, runtimeStatus,
        `/api/servers/${serverId}/image`,
        { runtime, version },
        'Runtime saved — start the server when the rebuild finishes.',
      );
    });

    applyStartupBtn?.addEventListener('click', () => {
      applyWithTimer(
        applyStartupBtn, cancelStartupBtn, startupStatus,
        `/api/servers/${serverId}/startup`,
        { startup: input.value },
        'Startup saved — start the server when the rebuild finishes.',
      );
    });

    cancelRuntimeBtn?.addEventListener('click', () => {
      select.value = `${savedRuntimeKey}|${savedVersionKey}`;
      lastRuntimeKey = savedRuntimeKey;
      if (runtimeStatus) runtimeStatus.textContent = '';
      syncDirtyUi();
    });

    cancelStartupBtn?.addEventListener('click', () => {
      input.value = savedStartup;
      if (startupStatus) startupStatus.textContent = '';
      syncDirtyUi();
    });

    syncDirtyUi();
  })();

  document.getElementById('reinstall-server')?.addEventListener('click', async () => {
    const button = document.getElementById('reinstall-server');
    if (!window.confirm('Reinstall dependencies? Your files are untouched.')) return;
    setBusy(button, true);
    try {
      await api(`/api/servers/${serverId}/reinstall`, { method: 'POST', body: JSON.stringify({}) });
      const saved = document.getElementById('reinstall-saved');
      saved.hidden = false;
      setTimeout(() => { saved.hidden = true; }, 8000);
      logsCleared = false;
      if (ws) { ws.close(); ws = null; wsConnected = false; }
      await refreshState();
      await refreshLogs();
      window.showToast?.('Reinstall started');
    } catch (error) {
      window.showToast?.(error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  });

  const serverTabs = Array.from(document.querySelectorAll('.server-tabs button'));
  const activateTab = (button, moveFocus) => {
    serverTabs.forEach((item) => {
      const selected = item === button;
      item.classList.toggle('active', selected);
      item.setAttribute('aria-selected', selected ? 'true' : 'false');
      
      
      
      
      item.setAttribute('tabindex', selected ? '0' : '-1');
    });
    document.querySelectorAll('.tab-panel').forEach((panel) => panel.classList.toggle('active', panel.dataset.panel === button.dataset.tab));
    if (moveFocus) button.focus();
    if (button.dataset.tab === 'files') loadFiles(currentPath);
  };
  serverTabs.forEach((button, index) => {
    button.addEventListener('click', () => activateTab(button, false));
    button.addEventListener('keydown', (event) => {
      let next = null;
      if (event.key === 'ArrowRight') next = serverTabs[(index + 1) % serverTabs.length];
      else if (event.key === 'ArrowLeft') next = serverTabs[(index - 1 + serverTabs.length) % serverTabs.length];
      else if (event.key === 'Home') next = serverTabs[0];
      else if (event.key === 'End') next = serverTabs[serverTabs.length - 1];
      if (!next) return;
      event.preventDefault();
      activateTab(next, true);
    });
  });
  
  
  serverTabs.forEach((item) => item.setAttribute('tabindex', item.classList.contains('active') ? '0' : '-1'));

  const fileList = document.getElementById('file-list');
  const breadcrumbs = document.getElementById('breadcrumbs');
  const editor = document.getElementById('editor-dialog');
  const editorTitle = document.getElementById('editor-title');
  const editorPath = document.getElementById('editor-path');
  const editorContent = document.getElementById('editor-content');

  const renderBreadcrumbs = () => {
    const segments = currentPath ? currentPath.split('/') : [];
    const paths = [''];
    segments.forEach((segment, index) => paths.push(segments.slice(0, index + 1).join('/')));
    const names = ['home', ...segments];
    breadcrumbs.replaceChildren(...names.map((name, index) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = name;
      button.dataset.path = paths[index];
      button.addEventListener('click', () => loadFiles(button.dataset.path));
      return button;
    }));
  };

  const FOLDER_GLYPH = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7a2 2 0 0 1 2-2h3.9a2 2 0 0 1 1.6.8l1 1.2H19a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/></svg>';
  const FILE_GLYPH = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z"/><path d="M14 3v5h5"/></svg>';

  const fileNotice = (text) => {
    const notice = document.createElement('div');
    notice.className = 'file-loading';
    notice.textContent = text;
    fileList.replaceChildren(notice);
  };

  const loadFiles = async (path = '') => {
    fileNotice('Loading files…');
    try {
      const data = await api(`/api/servers/${serverId}/files?path=${encodeURIComponent(path)}`);
      currentPath = path;
      renderBreadcrumbs();
      if (!data.entries.length) {
        fileNotice('This folder is empty.');
        return;
      }
      fileList.replaceChildren(...data.entries.map((entry) => {
        const row = document.createElement('div');
        row.className = 'file-row';
        
        
        const tick = document.createElement('input');
        tick.type = 'checkbox';
        tick.className = 'file-tick';
        tick.disabled = entry.is_directory;
        if (!entry.is_directory) {
          tick.dataset.path = entry.path;
          tick.addEventListener('change', () => toggleSelect(entry.path, tick.checked));
        }
        const name = document.createElement('button');
        name.className = 'file-name';
        name.type = 'button';
        const icon = document.createElement('i');
        icon.innerHTML = entry.is_directory ? FOLDER_GLYPH : FILE_GLYPH;
        const label = document.createElement('span');
        label.textContent = entry.name;
        name.append(icon, label);
        name.addEventListener('click', () => entry.is_directory ? loadFiles(entry.path) : openFile(entry.path));
        const type = document.createElement('span');
        type.className = 'file-meta';
        type.textContent = entry.is_directory ? 'Directory' : bytes(entry.size);
        const modified = document.createElement('span');
        modified.className = 'file-meta';
        modified.textContent = new Date(entry.modified_at).toLocaleString();
        const actions = document.createElement('span');
        actions.className = 'file-actions';
        if (!entry.is_directory) {
          const edit = document.createElement('button');
          edit.type = 'button';
          edit.textContent = 'Edit';
          edit.addEventListener('click', (event) => { event.stopPropagation(); openFile(entry.path); });
          actions.append(edit);
          const startup = document.createElement('button');
          startup.type = 'button';
          startup.textContent = 'Startup';
          startup.title = 'Set as the startup command';
          startup.addEventListener('click', (event) => { event.stopPropagation(); setStartupFile(entry.path, entry.name); });
          actions.append(startup);
          const packageConfig = packageInstallFor(entry.path, entry.name);
          if (packageConfig) {
            const pkg = document.createElement('button');
            pkg.type = 'button';
            pkg.textContent = packageButtonLabel(entry.name);
            pkg.title = `Use this ${entry.name} for dependency install`;
            pkg.addEventListener('click', (event) => { event.stopPropagation(); setPkgInstall(entry.path, entry.name); });
            actions.append(pkg);
          }
        }
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.textContent = 'Delete';
        remove.className = 'danger';
        remove.addEventListener('click', (event) => { event.stopPropagation(); deletePath(entry.path); });
        actions.append(remove);
        row.append(tick, name, type, modified, actions);
        return row;
      }));
    } catch (error) {
      fileNotice(error.message);
    }
  };

  const setStartupFile = async (path, name) => {
    const fileCmd = startupCommandFor(path, name);
    const startup = pkgDir === '.' ? `${pkgInstallCommand} && ${fileCmd}` : `cd ${shellQuote(pkgDir)} && ${pkgInstallCommand} && ${fileCmd}`;
    if (!confirm(`Set startup to:\n\n  ${startup}\n\nSave and recreate container?`)) return;
    try {
      await api(`/api/servers/${serverId}/startup`, {
        method: 'POST',
        body: JSON.stringify({ startup }),
      });
      const input = document.getElementById('startup-input');
      if (input) input.value = startup;
      await refreshState();
      await refreshLogs();
      window.showToast?.(`Startup set to ${fileCmd}`);
    } catch (error) { window.showToast?.(error.message, 'error'); }
  };

  const setPkgInstall = async (path, name) => {
    const packageConfig = packageInstallFor(path, name);
    if (!packageConfig) return;
    pkgDir = packageConfig.dir;
    pkgInstallCommand = packageConfig.dir === '.' ? packageConfig.install : packageConfig.install.replace(/^cd\s+.+?\s+&&\s+/, '');
    const currentStartup = document.getElementById('startup-input')?.value || '';
    const strippedStartup = currentStartup
      .replace(/^(?:cd\s+(?:'[^']*'|[^&]+)\s*&&\s*)?(?:npm install|bun install|pip install -r (?:'[^']*'|[^&]+)|bundle install|go mod download|composer install)\s*&&\s*/, '')
      .trim();
    const runCommand = strippedStartup || (
      runtimeName === 'python' ? 'python main.py'
        : runtimeName === 'ruby' ? 'ruby main.rb'
          : runtimeName === 'go' ? 'go run .'
            : runtimeName === 'php' ? 'php main.php'
              : runtimeName === 'bun' ? 'bun run index.ts'
                : 'node index.js'
    );
    const startup = pkgDir === '.' ? `${pkgInstallCommand} && ${runCommand}` : `cd ${shellQuote(pkgDir)} && ${pkgInstallCommand} && ${runCommand}`;
    if (!confirm(`Use ${name} for dependency install?\n\nStartup will be:\n  ${startup}\n\nSave and recreate?`)) return;
    try {
      await api(`/api/servers/${serverId}/startup`, {
        method: 'POST',
        body: JSON.stringify({ startup }),
      });
      const input = document.getElementById('startup-input');
      if (input) input.value = startup;
      await refreshState();
      await refreshLogs();
      window.showToast?.(`Dependency install set from ${name}`);
    } catch (error) { window.showToast?.(error.message, 'error'); }
  };

  const uploadZip = async (file) => {
    const form = new FormData();
    form.append('zip', file, file.name);
    form.append('dest', currentPath || '');
    const progress = document.getElementById('upload-progress');
    const progressLabel = document.getElementById('upload-progress-label');
    const progressFill = document.getElementById('upload-progress-fill');
    const progressTrack = document.getElementById('upload-progress-track');
    const progressMeta = document.getElementById('upload-progress-meta');
    
    
    
    
    const TRANSFER_SHARE = 90;
    const setBar = (pct) => {
      if (progressFill) progressFill.style.width = `${pct}%`;
      if (progressTrack) progressTrack.setAttribute('aria-valuenow', Math.round(pct));
    };
    progress.hidden = false;
    setBar(0);
    progressLabel.textContent = `Uploading ${file.name}…`;
    progressMeta.textContent = `${bytes(file.size)} · preparing`;
    try {
      const result = await upload(`/api/servers/${serverId}/extract`, form, (loaded, total) => {
        const ratio = total ? loaded / total : 0;
        setBar(ratio * TRANSFER_SHARE);
        if (ratio >= 1) {
          
          
          progressLabel.textContent = `Extracting ${file.name}…`;
          progressMeta.textContent = `${bytes(file.size)} · extracting on the node`;
        } else {
          progressMeta.textContent = `${Math.round(ratio * 100)}% · ${bytes(loaded)} / ${bytes(total)}`;
        }
      });
      setBar(100);
      progressLabel.textContent = 'ZIP extracted';
      const target = currentPath ? ` into ${currentPath}/` : ' into /';
      progressMeta.textContent = `${result.extracted} files extracted${target}`;
      window.showToast?.(`${result.extracted} files extracted from ${file.name}`);
      await loadFiles(currentPath);
    } catch (error) {
      progressLabel.textContent = 'Extract failed';
      progressMeta.textContent = error.message;
      window.showToast?.(error.message, 'error');
    } finally {
      setTimeout(() => { progress.hidden = true; }, 4000);
    }
  };

  const openFile = async (path) => {
    try {
      const data = await api(`/api/servers/${serverId}/file?path=${encodeURIComponent(path)}`);
      editorTitle.textContent = path;
      editorPath.value = path;
      editorContent.value = data.content;
      editor.showModal();
      editorContent.focus();
    } catch (error) { window.showToast?.(error.message, 'error'); }
  };

  const deletePath = async (path) => {
    if (!confirm(`Delete ${path}?`)) return;
    try {
      await api(`/api/servers/${serverId}/file`, { method: 'DELETE', body: JSON.stringify({ path }) });
      await loadFiles(currentPath);
    } catch (error) { window.showToast?.(error.message, 'error'); }
  };

  const deletePaths = async (paths) => {
    if (!paths.length || !confirm(`Delete ${paths.length} item${paths.length > 1 ? 's' : ''}?`)) return;
    try {
      for (const path of paths) {
        await api(`/api/servers/${serverId}/file`, { method: 'DELETE', body: JSON.stringify({ path }) });
      }
      selectedPaths.clear();
      updateSelectionBar();
      await loadFiles(currentPath);
    } catch (error) {
      selectedPaths.clear();
      updateSelectionBar();
      window.showToast?.(error.message, 'error');
      await loadFiles(currentPath);
    }
  };

  
  let selectedPaths = new Set();
  const selectionBar = document.getElementById('selection-bar');
  const selectionCount = document.getElementById('selection-count');
  const selectAllTick = document.getElementById('select-all');
  const fileSelectAll = document.querySelector('.file-select-all');

  const updateSelectionBar = () => {
    const count = selectedPaths.size;
    selectionCount.textContent = `${count} selected`;
    selectionBar.hidden = count === 0;
    if (count === 0 && selectAllTick) selectAllTick.checked = false;
  };

  const toggleSelect = (path, checked) => {
    if (checked) selectedPaths.add(path); else selectedPaths.delete(path);
    updateSelectionBar();
  };

  if (fileSelectAll && selectAllTick) {
    fileSelectAll.addEventListener('click', (e) => { e.stopPropagation(); });
    selectAllTick.addEventListener('change', () => {
      const checkboxes = fileList.querySelectorAll('.file-row input[type="checkbox"]');
      
      
      checkboxes.forEach(cb => { if (cb.disabled) return; cb.checked = selectAllTick.checked; toggleSelect(cb.dataset.path, selectAllTick.checked); });
    });
  }

  document.getElementById('delete-selected')?.addEventListener('click', async () => {
    const paths = [...selectedPaths];
    await deletePaths(paths);
  });

  document.getElementById('new-file')?.addEventListener('click', () => {
    editorTitle.textContent = 'New file';
    editorPath.value = currentPath ? `${currentPath}/` : '';
    editorContent.value = '';
    editor.showModal();
    editorPath.focus();
  });

  document.getElementById('new-folder')?.addEventListener('click', async () => {
    const name = prompt('Folder name');
    if (!name) return;
    const path = currentPath ? `${currentPath}/${name}` : name;
    try {
      await api(`/api/servers/${serverId}/directory`, { method: 'POST', body: JSON.stringify({ path }) });
      await loadFiles(currentPath);
    } catch (error) { window.showToast?.(error.message, 'error'); }
  });

  const uploadFiles = async (files, preserveFolders = false) => {
    const list = [...files];
    if (!list.length) return;
    const BATCH_SIZE = 1500;
    const BATCH_BYTES = 128 * 1024 * 1024;
    const totalBytes = list.reduce((sum, file) => sum + (file.size || 0), 0);
    const startedAt = performance.now();
    let sentBytes = 0;
    
    
    
    
    let inflightBytes = 0;
    let done = 0;
    let lastTickAt = startedAt;
    let lastTickBytes = 0;
    let emaSpeed = 0;

    const progress = document.getElementById('upload-progress');
    const progressLabel = document.getElementById('upload-progress-label');
    const progressFill = document.getElementById('upload-progress-fill');
    const progressTrack = document.getElementById('upload-progress-track');
    const progressMeta = document.getElementById('upload-progress-meta');
    progress.hidden = false;

    const render = (state) => {
      const shown = Math.min(totalBytes, sentBytes + inflightBytes);
      const pct = totalBytes ? (shown / totalBytes) * 100 : (done / list.length) * 100;
      if (progressFill) progressFill.style.width = `${Math.min(100, pct).toFixed(1)}%`;
      if (progressTrack) progressTrack.setAttribute('aria-valuenow', Math.round(Math.min(100, Math.max(0, pct))));
      if (state === 'running') {
        const now = performance.now();
        const elapsed = (now - lastTickAt) / 1000;
        
        
        
        
        if (elapsed >= 0.25) {
          const rate = (shown - lastTickBytes) / elapsed;
          emaSpeed = emaSpeed ? emaSpeed * 0.6 + rate * 0.4 : rate;
          lastTickAt = now;
          lastTickBytes = shown;
        }
        progressLabel.textContent = `Uploading ${done + 1}-${Math.min(done + BATCH_SIZE, list.length)} of ${list.length} files…`;
        progressMeta.textContent =
          `${pct.toFixed(0)}% · ${bytes(shown)} / ${bytes(totalBytes)} · ${bytes(emaSpeed)}/s`;
      } else if (state === 'done') {
        const avg = totalBytes / Math.max(0.05, (performance.now() - startedAt) / 1000);
        progressLabel.textContent = 'Upload complete';
        progressMeta.textContent = `${list.length} files · ${bytes(totalBytes)} · ${bytes(avg)}/s average`;
      } else {
        progressLabel.textContent = 'Upload failed';
        progressMeta.textContent = `${pct.toFixed(0)}% · ${bytes(shown)} / ${bytes(totalBytes)}`;
      }
    };
    render('running');

    try {
      for (let i = 0; i < list.length;) {
        const batch = [];
        let batchBytes = 0;
        while (i < list.length && batch.length < BATCH_SIZE && batchBytes < BATCH_BYTES) {
          const file = list[i++];
          batch.push(file);
          batchBytes += file.size || 0;
        }
        const form = new FormData();
        batch.forEach((file) => {
          const relativeName = preserveFolders && file.webkitRelativePath ? file.webkitRelativePath : file.name;
          const path = currentPath ? `${currentPath}/${relativeName}` : relativeName;
          form.append('files', file, file.name);
          form.append('paths', path);
        });
        await upload(`/api/servers/${serverId}/upload`, form, (loaded, total) => {
          
          
          
          
          inflightBytes = total ? Math.min(batchBytes, (loaded / total) * batchBytes) : 0;
          render('running');
        });
        sentBytes += batchBytes;
        inflightBytes = 0;
        done += batch.length;
        render('running');
      }
      render('done');
      await loadFiles(currentPath);
    } catch (error) {
      
      
      inflightBytes = 0;
      render('failed');
      window.showToast?.(error.message, 'error');
    } finally {
      setTimeout(() => { progress.hidden = true; }, 5000);
    }
  };

  const filesInput = document.getElementById('upload-files-input');
  const folderInput = document.getElementById('upload-folder-input');
  document.getElementById('upload-files')?.addEventListener('click', () => filesInput?.click());
  document.getElementById('upload-folder')?.addEventListener('click', () => folderInput?.click());
  filesInput?.addEventListener('change', async () => {
    await uploadFiles(filesInput.files);
    filesInput.value = '';
  });
  folderInput?.addEventListener('change', async () => {
    await uploadFiles(folderInput.files, true);
    folderInput.value = '';
  });

  const zipInput = document.getElementById('upload-zip-input');
  document.getElementById('upload-zip')?.addEventListener('click', () => zipInput?.click());
  zipInput?.addEventListener('change', async () => {
    const file = zipInput.files[0];
    zipInput.value = '';
    if (file) await uploadZip(file);
  });

  
  
  
  
  
  
  let dragDepth = 0;
  const setDragActive = (active) => fileList.classList.toggle('drag-over', active);
  const isFileDrag = (event) => Array.from(event.dataTransfer?.types || []).includes('Files');
  fileList?.addEventListener('dragenter', (event) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    dragDepth += 1;
    setDragActive(true);
  });
  fileList?.addEventListener('dragover', (event) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
  });
  fileList?.addEventListener('dragleave', () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) setDragActive(false);
  });
  fileList?.addEventListener('drop', async (event) => {
    if (!isFileDrag(event)) return;
    event.preventDefault();
    dragDepth = 0;
    setDragActive(false);
    const dropped = event.dataTransfer.files;
    if (dropped && dropped.length) await uploadFiles(dropped);
  });

  const closeEditor = () => editor.open && editor.close();
  document.getElementById('close-editor')?.addEventListener('click', closeEditor);
  document.getElementById('cancel-editor')?.addEventListener('click', closeEditor);

  document.getElementById('editor-form')?.addEventListener('submit', async (event) => {
    const submitter = event.submitter;
    if (!submitter || submitter.id !== 'save-file') return;
    event.preventDefault();
    setBusy(submitter, true);
    try {
      await api(`/api/servers/${serverId}/file`, {
        method: 'PUT',
        body: JSON.stringify({ path: editorPath.value, content: editorContent.value }),
      });
      editor.close();
      await loadFiles(currentPath);
    } catch (error) { window.showToast?.(error.message, 'error'); }
    finally { setBusy(submitter, false); }
  });

  const BASE_INTERVAL = 4000;
  const MAX_INTERVAL = 30000;
  let pollTimer = null;
  let pollDelay = BASE_INTERVAL;
  let polling = false;

  
  let ws = null;
  let wsConnected = false;
  let wsReconnectTimer = null;
  let wsShouldConnect = false;
  const WS_BASE_INTERVAL = 3000;
  const WS_MAX_INTERVAL = 30000;
  let wsRetryDelay = WS_BASE_INTERVAL;

  function wsUrl() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    let url = `${proto}//${location.host}${PANEL_BASE}/ws/console/${serverId}`;
    if (consoleSince > 0) url += `?since=${encodeURIComponent(consoleSince.toFixed(3))}`;
    return url;
  }

  function connectWs() {
    if (ws || !wsShouldConnect) return;
    const epoch = streamEpoch;
    try {
      ws = new WebSocket(wsUrl());
    } catch (_) { scheduleWsReconnect(); return; }

    ws.onopen = () => {
      if (epoch !== streamEpoch) return;
      wsConnected = true;
      wsRetryDelay = WS_BASE_INTERVAL;
      if (!logsCleared) {
        output.textContent = '';
      }
    };

    ws.onmessage = (event) => {
      if (epoch !== streamEpoch) return;
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'connected') {
          if (!logsCleared) {
            output.textContent = '';
          }
        } else if (msg.type === 'log') {
          appendConsole(msg.data);
        } else if (msg.type === 'error') {
          appendConsole(`\n[ws error] ${msg.message}\n`);
        }
      } catch (_) {}
    };

    ws.onclose = () => {
      if (epoch !== streamEpoch) return;
      wsConnected = false;
      ws = null;
      if (wsShouldConnect) scheduleWsReconnect();
    };

    ws.onerror = () => {
      wsConnected = false;
    };
  }

  function disconnectWs() {
    wsShouldConnect = false;
    wsConnected = false;
    wsRetryDelay = WS_BASE_INTERVAL;
    if (wsReconnectTimer) { clearTimeout(wsReconnectTimer); wsReconnectTimer = null; }
    if (ws) { ws.close(); ws = null; }
  }

  function scheduleWsReconnect() {
    if (wsReconnectTimer || document.hidden) return;
    const delay = wsRetryDelay;
    wsRetryDelay = Math.min(wsRetryDelay * 2, WS_MAX_INTERVAL);
    wsReconnectTimer = setTimeout(() => {
      wsReconnectTimer = null;
      if (wsShouldConnect && !wsConnected) connectWs();
    }, delay);
  }

  const scheduleNextPoll = (delay) => {
    if (pollTimer) clearTimeout(pollTimer);
    if (document.hidden) return;
    pollTimer = setTimeout(runPollCycle, delay);
  };

  async function runPollCycle() {
    if (polling || document.hidden) return;
    polling = true;
    try {
      const data = await api(`/api/servers/${serverId}/state`);
      await refreshState(data);
      if (!wsConnected) {
        await refreshLogs(data);
      }
      pollDelay = BASE_INTERVAL;
    } catch (error) {
      setStatus('unavailable');
      if (containerId) containerId.textContent = error.message || 'Node unavailable';
      if (output && !logsCleared && (output.textContent || '').includes('Connecting to node')) {
        output.textContent = 'Hosting node is offline. You can still open other pages or delete this server — that frees your slot and queues the container for an admin.';
      }
      setPowerEnabled(true, lastState?.server?.install_status !== 'running');
      setConsoleEnabled(false);
      pollDelay = Math.min(MAX_INTERVAL, Math.round(pollDelay * 1.8));
    } finally {
      polling = false;
      scheduleNextPoll(pollDelay);
    }
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    } else {
      pollDelay = BASE_INTERVAL;
      runPollCycle();
      if (wsShouldConnect && !wsConnected) {
        wsRetryDelay = WS_BASE_INTERVAL;
        scheduleWsReconnect();
      }
    }
  });

  setInterval(updateUptime, 1000);
  runPollCycle();
})();
