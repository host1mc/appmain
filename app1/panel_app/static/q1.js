(() => {
  const menu = document.getElementById('mobile-menu');
  const scrim = document.getElementById('sidebar-scrim');
  const setNavOpen = (open) => {
    document.body.classList.toggle('nav-open', open);
    menu?.setAttribute('aria-expanded', open ? 'true' : 'false');
  };
  const closeNav = () => setNavOpen(false);
  menu?.addEventListener('click', () => setNavOpen(!document.body.classList.contains('nav-open')));
  scrim?.addEventListener('click', closeNav);
  
  
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && document.body.classList.contains('nav-open')) closeNav();
  });

  
  
  
  
  
  (() => {
    const btn = document.getElementById('sidebar-toggle');
    if (!btn) return;
    btn.addEventListener('click', () => {
      
      
      const collapsed = !document.body.classList.contains('sidebar-collapsed');
      document.body.classList.toggle('sidebar-collapsed', collapsed);
      btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
      
      
      const secure = location.protocol === 'https:' ? '; Secure' : '';
      document.cookie = `sb_collapsed=${collapsed ? '1' : '0'}; path=/; max-age=31536000; SameSite=Lax${secure}`;
    });
  })();

  function showToast(message, type = 'success') {
    let region = document.getElementById('toast-region');
    if (!region) {
      region = document.createElement('div');
      region.id = 'toast-region';
      region.setAttribute('aria-live', 'polite');
      document.body.appendChild(region);
    }
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    region.appendChild(toast);
    setTimeout(() => toast.classList.add('toast-out'), 3500);
    setTimeout(() => toast.remove(), 4000);
  }
  window.showToast = showToast;

  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';

  function jsonPost(url, payload) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify(payload)
    }).then(async (response) => {
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.ok) throw new Error(data.error || 'Request failed');
      return data;
    });
  }
  window.jsonPost = jsonPost;

  
  
  
  
  document.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-copy]');
    if (!button) return;
    const value = button.dataset.copy;
    
    
    
    if (!navigator.clipboard?.writeText) {
      showToast('Copying needs a secure (https) connection', 'error');
      return;
    }
    button.setAttribute('aria-busy', 'true');
    try {
      await navigator.clipboard.writeText(value);
      showToast('Copied to clipboard');
    } catch (error) {
      showToast('Could not copy', 'error');
    } finally {
      button.removeAttribute('aria-busy');
    }
  });

  
  
  
  
  document.addEventListener('submit', (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const submitter = event.submitter
      || form.querySelector('button:not([type]), [type="submit"]');
    
    
    
    const confirmText = (submitter && submitter.dataset.confirm) || form.dataset.confirm;
    if (confirmText && !window.confirm(confirmText)) {
      event.preventDefault();
      return;
    }
    if (event.defaultPrevented) return;
    if (form.dataset.submitting === '1') {
      event.preventDefault();
      return;
    }
    form.dataset.submitting = '1';
    if (submitter) {
      submitter.setAttribute('aria-busy', 'true');
      
      
      
      setTimeout(() => { submitter.disabled = true; }, 0);
    }
  });

  
  
  
  
  window.addEventListener('pageshow', (event) => {
    if (!event.persisted) return;
    document.querySelectorAll('form[data-submitting="1"]').forEach((form) => {
      delete form.dataset.submitting;
      form.querySelectorAll(
        'button:not([type])[aria-busy="true"], [type="submit"][aria-busy="true"]'
      ).forEach((submitter) => {
        submitter.disabled = false;
        submitter.removeAttribute('aria-busy');
      });
    });
  });

  
  
  
  
  
  
  const guardRetry = document.getElementById('guard-retry');
  if (guardRetry) {
    guardRetry.addEventListener('click', () => {
      
      
      
      
      
      if (typeof window.__blockedGuardRetry === 'function') { window.__blockedGuardRetry(); return; }
      window.location.reload();
    });
  }
})();
