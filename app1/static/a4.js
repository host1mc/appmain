(function () {
  'use strict';

  var EYE =
    '<svg class="eye-on" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"' +
    ' stroke-linecap="round" stroke-linejoin="round" width="18" height="18" aria-hidden="true">' +
    '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>' +
    '<svg class="eye-off" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"' +
    ' stroke-linecap="round" stroke-linejoin="round" width="18" height="18" aria-hidden="true">' +
    '<path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 10 8 10 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>' +
    '<path d="M6.61 6.61A18.15 18.15 0 0 0 2 12s3 8 10 8a9.7 9.7 0 0 0 5.39-1.61"/><path d="m2 2 20 20"/></svg>';

  function score(v) {
    if (!v) return 0;
    var variety = 0;
    if (/[a-z]/.test(v)) variety++;
    if (/[A-Z]/.test(v)) variety++;
    if (/[0-9]/.test(v)) variety++;
    if (/[^A-Za-z0-9]/.test(v)) variety++;

    if (v.length < 8) return 1;
    if (v.length >= 14 && variety >= 3) return 4;
    if (v.length >= 10 && variety >= 2) return 3;
    if (variety >= 2) return 2;
    return 2;
  }

  var LABELS = ['', 'Too short — use 8 characters or more',
    'Weak — add a number or symbol', 'Good', 'Strong'];

  function addToggle(input) {
    var wrap = input.parentNode;
    if (!wrap || wrap.className.indexOf('pw-wrap') === -1) return;

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'pw-toggle';
    btn.setAttribute('aria-pressed', 'false');
    btn.setAttribute('aria-label', 'Show password');
    btn.innerHTML = EYE;

    btn.addEventListener('click', function () {
      var shown = btn.getAttribute('aria-pressed') === 'true';
      shown = !shown;
      btn.setAttribute('aria-pressed', String(shown));
      btn.setAttribute('aria-label', shown ? 'Hide password' : 'Show password');
      input.type = shown ? 'text' : 'password';

      var pos = input.value.length;
      try { input.setSelectionRange(pos, pos); } catch (e) {  }
      input.focus();
    });

    wrap.appendChild(btn);
  }

  function addMeter(input) {
    var meter = document.createElement('div');
    meter.className = 'pw-meter';
    meter.setAttribute('data-score', '0');
    meter.innerHTML =
      '<div class="pw-bar"><span></span></div>' +
      '<p class="pw-label" aria-live="polite"></p>';

    var host = input.parentNode;
    host.parentNode.insertBefore(meter, host.nextSibling);

    var fill = meter.querySelector('.pw-bar span');
    var label = meter.querySelector('.pw-label');

    input.addEventListener('input', function () {
      var s = score(input.value);
      if (!s) {
        meter.className = 'pw-meter';
        meter.setAttribute('data-score', '0');
        fill.style.width = '0';
        label.textContent = '';
        return;
      }
      meter.className = 'pw-meter on';
      meter.setAttribute('data-score', String(s));
      fill.style.width = (s * 25) + '%';
      label.textContent = LABELS[s];
    });
  }

  function initValidation() {
    if (!document.querySelector('[data-msg]')) return;

    function box(el) { return el.id ? document.getElementById(el.id + '-error') : null; }

    function mark(el) {
      var b = box(el);
      if (b) b.textContent = el.getAttribute('data-msg') || el.validationMessage;
      el.setAttribute('aria-invalid', 'true');
    }

    function unmark(el) {
      var b = box(el);
      if (b) b.textContent = '';
      el.removeAttribute('aria-invalid');
    }

    document.addEventListener('invalid', function (e) {
      if (!e.target || !e.target.id) return;
      e.preventDefault();
      mark(e.target);
    }, true);

    document.addEventListener('input', function (e) {
      var el = e.target;
      if (el && el.id && el.hasAttribute('aria-invalid') && el.validity && el.validity.valid) unmark(el);
    }, true);

    document.addEventListener('submit', function (e) {
      var form = e.target;
      if (form.querySelectorAll) {
        var stale = form.querySelectorAll('[aria-invalid]');
        for (var i = 0; i < stale.length; i++) unmark(stale[i]);
      }
      var btn = e.submitter || (form.querySelector && form.querySelector('button[type="submit"], button:not([type])'));
      if (btn && !btn.disabled) {
        var busy = btn.getAttribute('data-busy-label');
        if (busy) btn.textContent = busy;
        btn.setAttribute('aria-busy', 'true');
        btn.disabled = true;
      }
    }, true);
  }

  function init() {
    var inputs = document.querySelectorAll('.pw-wrap input[type="password"]');
    for (var i = 0; i < inputs.length; i++) {
      addToggle(inputs[i]);
      if (inputs[i].hasAttribute('data-strength')) addMeter(inputs[i]);
    }

    initValidation();

    var summary = document.querySelector('[data-error-summary]');
    if (summary) summary.focus();

    if (!document.querySelector('.flash')) {
      var first = document.querySelector('[data-autofocus]');
      if (first && !first.value) first.focus();
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
