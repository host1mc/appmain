(() => {
  const form = document.getElementById('deploy-form');
  const modal = document.getElementById('deploy-modal');
  if (form && modal) {
    const title = document.getElementById('deploy-modal-title');
    const message = document.getElementById('deploy-modal-message');
    const live = document.getElementById('deploy-live');
    const progress = document.getElementById('deploy-progress');
    const actions = document.getElementById('deploy-modal-actions');
    let timer;
    let canDismiss = false;
    const dismissControls = modal.querySelectorAll('.deploy-modal-close, #deploy-modal-actions [data-deploy-close]');
    
    
    
    const controls = [...form.elements].filter((el) => !el.disabled);
    let deadline;
    const warn = (event) => { event.preventDefault(); event.returnValue = ''; };
    const lock = () => {
      
      
      
      controls.forEach((el) => { el.disabled = true; });
      window.addEventListener('beforeunload', warn);
      
      
      
      
      
      if (!deadline) {
        deadline = setTimeout(() => setState(
          'error',
          'This is taking longer than expected',
          'The hosting node has not confirmed this server yet. Check your dashboard before trying again.',
          'You can close this message.',
        ), 600000);
      }
    };
    const unlock = () => {
      controls.forEach((el) => { el.disabled = false; });
      window.removeEventListener('beforeunload', warn);
      if (deadline) { clearTimeout(deadline); deadline = undefined; }
      if (timer) { clearTimeout(timer); timer = undefined; }
    };
    const close = () => {
      if (!canDismiss) return;
      modal.hidden = true;
      if (timer) clearTimeout(timer);
    };
    modal.querySelectorAll('[data-deploy-close]').forEach((el) => el.addEventListener('click', close));
    const setState = (kind, heading, copy, detail) => {
      canDismiss = kind !== 'loading';
      modal.classList.toggle('is-success', kind === 'success');
      modal.classList.toggle('is-error', kind === 'error');
      title.textContent = heading; message.textContent = copy; live.textContent = detail || '';
      progress.hidden = kind !== 'loading';
      actions.hidden = kind !== 'success';
      dismissControls.forEach((el) => { el.hidden = kind === 'loading'; });
      
      
      
      if (kind === 'loading') lock(); else unlock();
    };
    const statusUrl = new URL(form.action, window.location.href);
    statusUrl.pathname = statusUrl.pathname.replace(/\/servers\/?$/, '/api/servers/status');
    // Plain-language help per status for error replies that carry no usable
    // body (a proxy 502 page, an empty response). Anything the server actually
    // says — JSON ``error`` or short text — is shown instead of these.
    const statusHelp = {
      400: 'The request was invalid — check the form and try again.',
      401: 'Your session has expired — sign in again, then retry.',
      403: 'This action is not allowed right now.',
      409: 'Something changed underneath — reload and try again.',
      413: 'The upload is too large — upload files one at a time.',
      429: 'Too many requests — wait a moment and try again.',
      500: 'The panel hit an internal error — try again in a bit.',
      502: 'Hosting node is offline right now — your data is safe. Try again in a bit.',
      503: 'No container space or node busy right now — try again in a bit.',
    };
    const readServerMessage = async (response) => {
      try {
        const text = await response.text();
        if (!text || text.length > 500) return null;
        if (/<\s*!?doctype|<\s*html/i.test(text)) return null;
        try {
          const data = JSON.parse(text);
          if (data && typeof data.error === 'string' && data.error.trim()) return data.error.trim();
        } catch (_) { /* not JSON — treat the text itself as the message */ }
        const clean = text.trim();
        return clean || null;
      } catch (_) { return null; }
    };
    const poll = async (serverId, serverUrl) => {
      const again = (delay) => { timer = setTimeout(() => poll(serverId, serverUrl), delay); };
      try {
        const response = await fetch(statusUrl.toString(), { credentials: 'same-origin' });
        
        
        if (!response.ok) return again(3000);
        const data = await response.json();
        const servers = data.servers || {};
        const errors = data.errors || {};

        if (errors[serverId]) {
          return setState('error', 'Container Creation Failed', errors[serverId], 'Please check node configuration or status and try again.');
        }

        if (!Object.prototype.hasOwnProperty.call(servers, serverId)) {
          return setState('error', 'Server could not be created', 'The hosting node did not finish creating this server.', 'You can close this message and try again.');
        }
        const info = servers[serverId] || {};
        if (info.status === 'failed' || info.error) {
          return setState('error', 'Container Creation Failed', info.error || 'The node failed to create the container.', 'Please resolve the issue and try again.');
        }
        const status = info.status || 'creating';
        const install = info.install_status || 'running';
        live.textContent = install !== 'idle' ? `Live status: ${status} (${install})` : `Live status: ${status}`;
        
        
        
        
        
        if (!info.known || install === 'running') return again(2500);
        setState('success', 'Server created', 'Opening your server panel...', 'Provisioning completed successfully.');
        
        
        window.location.assign(serverUrl);
      } catch (_) { again(3000); }
    };
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      
      const turnstileWidget = form.querySelector('.cf-turnstile');
      if (turnstileWidget) {
        const turnstileResp = form.querySelector('[name="cf-turnstile-response"]');
        if (!turnstileResp || !turnstileResp.value) {
          modal.hidden = false;
          setState('error', 'Verification Required', 'Please complete the Cloudflare Turnstile challenge above the submit button.', 'Solve the CAPTCHA check and try again.');
          return;
        }
      }
      
      const payload = new FormData(form);
      modal.hidden = false; setState('loading', 'Creating your server', 'Starting the container on the hosting node...', 'Waiting for live updates...');
      try {
        const response = await fetch(form.action, {
          method: 'POST',
          body: payload,
          credentials: 'same-origin',
          redirect: 'follow',
          headers: { 'X-Requested-With': 'fetch' },
        });
        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          const data = await response.json();
          if (!response.ok || !data.ok || !data.server_id || !data.status_key || !data.server_url) {
            const errDetail = (data && data.error) ? data.error : 'Container creation failed.';
            setState('error', 'Server could not be created', errDetail, 'Please fix the error and try again.');
            return;
          }
          poll(data.status_key, data.server_url);
          return;
        }
        const serverUrl = response.url;
        const match = serverUrl.match(/\/servers\/([^/?#]+)\/?(?:[?#]|$)/);
        if (!response.ok) {
          const serverMsg = await readServerMessage(response);
          setState('error', 'Server could not be created',
            serverMsg || ('Server returned HTTP error ' + response.status + ' — ' + (statusHelp[response.status] || 'Please try again.')),
            'Nothing was created — safe to try again.');
          return;
        }
        if (!match) {
          if (response.redirected && serverUrl) {
            
            
            unlock();
            window.location.assign(serverUrl);
            return;
          }
          setState('error', 'Server could not be created', 'Target server URL could not be resolved.', 'Please try again.');
          return;
        }
        poll(match[1], serverUrl);
      } catch (err) {
        const detail = (err && err.message) ? err.message : 'We could not start deployment right now.';
        setState('error', 'Server could not be created', detail, 'Please close this message and try again.');
      }
    });
  }
  const dataElement = document.getElementById('runtime-data');
  if (!dataElement) return;
  const radios = [...document.querySelectorAll('input[name="runtime"]')];
  const version = document.getElementById('runtime-version');
  const startup = document.getElementById('startup-command');
  const summary = document.getElementById('allocation-runtime');
  
  
  
  if (!version || !startup || !summary || !radios.length) return;

  let runtimes;
  try {
    runtimes = JSON.parse(dataElement.textContent || '{}');
  } catch (error) {
    
    
    return;
  }

  const labelFor = (value) => {
    const runtime = runtimes[value];
    if (!runtime) return '';
    return `${runtime.label} ${version.value}`;
  };

  const update = () => {
    const selected = radios.find((radio) => radio.checked);
    if (!selected || !runtimes[selected.value]) return;
    const runtime = runtimes[selected.value];
    const previous = version.value;
    const versions = Array.isArray(runtime.versions) ? runtime.versions : [];
    version.replaceChildren(...versions.map((item) => {
      const option = document.createElement('option');
      option.value = item;
      option.textContent = `${runtime.label} ${item}`;
      option.selected = item === (previous || runtime.default_version);
      return option;
    }));
    startup.value = runtime.default_startup || '';
    summary.textContent = labelFor(selected.value);
  };

  radios.forEach((radio) => radio.addEventListener('change', update));
  version.addEventListener('change', () => {
    const selected = radios.find((radio) => radio.checked);
    
    
    
    if (selected) summary.textContent = labelFor(selected.value);
  });
  update();
})();
