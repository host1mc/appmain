(function () {
  'use strict';

  var meta = document.querySelector('meta[name="csrf-token"]');
  var csrf = meta ? meta.getAttribute('content') : '';
  var inflight = false;

  function isLocalPath(value) {
    if (typeof value !== 'string') return false;
    if (value.charAt(0) !== '/' || value.charAt(1) === '/') return false;
    if (value.indexOf('\\') !== -1) return false;
    for (var i = 0; i < value.length; i++) {
      var code = value.charCodeAt(i);

      if (code < 32 || code === 127) return false;
    }
    return true;
  }

  function go(path) {

    if (inflight) return;
    if (!isLocalPath(path)) return;
    inflight = true;
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/nav', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    if (csrf) xhr.setRequestHeader('X-CSRF-Token', csrf);
    xhr.timeout = 15000;
    xhr.onload = function () {
      inflight = false;
      if (xhr.status === 200) {
        try {
          var r = JSON.parse(xhr.responseText);

          if (r && r.ok && isLocalPath(r.url)) { window.location.href = r.url; return; }
        } catch (e) {  }
      }
      window.location.href = path;
    };
    xhr.onerror = function () { inflight = false; window.location.href = path; };
    xhr.ontimeout = function () { inflight = false; window.location.href = path; };
    xhr.onabort = function () { inflight = false; };
    xhr.send(JSON.stringify({ path: path }));
  }

  document.addEventListener('click', function (e) {
    if (inflight) return;
    if (e.defaultPrevented || e.button !== 0) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    if (!a) return;
    if (a.target === '_blank' || a.hasAttribute('data-no-mask')) return;
    var href = a.getAttribute('href') || '';
    if (href.charAt(0) !== '/' || href.charAt(1) === '/' || href === '/') return;
    if (href.indexOf('/api/') === 0 || href.indexOf('/static/') === 0) return;
    if (href.indexOf('?') !== -1 || href.indexOf('#') !== -1) return;

    if (!isLocalPath(href)) return;
    e.preventDefault();
    go(href);
  });

  window.maskedNav = function (path) { go(path); };
})();
