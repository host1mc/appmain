/*
 * fp-guard.js — shared device fingerprint + ad-block guard.
 *
 * One script for every page. Behaviour is driven by <body data-guard="...">:
 *   data-guard="gate"  -> ad blocker fully blocks the page (auth flows)
 *   data-guard="warn"  -> ad-block UI stands down (showBanner is a no-op here)
 *   data-guard="off"   -> fingerprint only, no ad-block UI (the default)
 *
 * Any <form data-fp-form> on the page gets its <input data-fp-input> filled
 * with the current device fingerprint on load and again right before submit.
 *
 * The fingerprint is a SHA-256 hex digest of stable device signals when the
 * page is served over a secure context (crypto.subtle), and falls back to a
 * deterministic non-crypto hash otherwise so the value is always populated.
 *
 * Ad-block detection probes three baits — a same-origin script, cosmetic DOM
 * bait, and third-party ad hosts (netBaits, always on) — and flags the visitor
 * the moment any one trips; it fails open on anything it cannot measure.
 * Append ?guarddebug=1 to any page to log each signal, or read
 * window.__adblockSignals in the console.
 */
(function () {
  'use strict';

  // Falls back to "off", not "warn". This copy serves the operator console,
  // which carries no advertising and has no /blocked route to send anyone to, so
  // there is nothing here for an ad-block gate to protect and nowhere for it to
  // go. Every admin template sets data-guard="off" explicitly; the fallback is
  // what a template that forgets the attribute lands on, and defaulting that to
  // "warn" is what put the red ad-block banner on admin_embed.html. An absent
  // attribute now means "no ad-block UI" instead of "banner".
  var GUARD = (document.body && document.body.dataset.guard) || 'off';

  function $(sel, root) {
    try { return (root || document).querySelector(sel); } catch (e) { return null; }
  }

  /* -------------------------------------------------------------------- *
   *  Fingerprint
   * -------------------------------------------------------------------- */

  function canvasSignal() {
    try {
      var c = document.createElement('canvas');
      c.width = 240; c.height = 60;
      var ctx = c.getContext('2d');
      if (!ctx) return '';
      ctx.textBaseline = 'top';
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('fp-guard ⚡', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('fp-guard ⚡', 4, 17);
      return c.toDataURL();
    } catch (e) { return ''; }
  }

  function webglSignal() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return '';
      var dbg = gl.getExtension('WEBGL_debug_renderer_info');
      if (!dbg) return '';
      return [
        gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL),
        gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)
      ].join('~');
    } catch (e) { return ''; }
  }

  function collectSignals() {
    var nav = navigator || {};
    var parts = [
      nav.userAgent || '',
      nav.language || '',
      (nav.languages || []).join(','),
      String(nav.hardwareConcurrency || ''),
      String(nav.deviceMemory || ''),
      String(nav.platform || ''),
      String(screen.width) + 'x' + String(screen.height),
      String(screen.colorDepth || ''),
      String(new Date().getTimezoneOffset()),
      (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; } })(),
      canvasSignal(),
      webglSignal()
    ];
    return parts.join('|||');
  }

  // Deterministic fallback hash (FNV-ish) for non-secure contexts.
  function fallbackHash(str) {
    var h = 0;
    for (var i = 0; i < str.length; i++) {
      h = ((h << 5) - h) + str.charCodeAt(i);
      h |= 0;
    }
    return 'fb_' + Math.abs(h).toString(16);
  }

  function computeFingerprint() {
    var raw = collectSignals();
    if (window.crypto && window.crypto.subtle && window.isSecureContext) {
      try {
        var data = new TextEncoder().encode(raw);
        return window.crypto.subtle.digest('SHA-256', data).then(function (buf) {
          var bytes = Array.prototype.slice.call(new Uint8Array(buf));
          return bytes.map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
        }).catch(function () { return fallbackHash(raw); });
      } catch (e) { /* fall through */ }
    }
    return Promise.resolve(fallbackHash(raw));
  }

  function safe(fn) {
    try { return fn(); } catch (e) { return null; }
  }

  function canvasHash() {
    var sig = canvasSignal();
    if (!sig) return '';
    var h = 0;
    for (var i = 0; i < sig.length; i++) {
      h = ((h << 5) - h) + sig.charCodeAt(i);
      h |= 0;
    }
    return 'ch_' + Math.abs(h).toString(16);
  }

  function webglDetail() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return null;
      var dbg = gl.getExtension('WEBGL_debug_renderer_info');
      var out = { available: true };
      if (dbg) {
        out.vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
        out.renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
      }
      out.version = gl.getParameter(gl.VERSION);
      out.shadingLanguageVersion = gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
      out.maxTextureSize = gl.getParameter(gl.MAX_TEXTURE_SIZE);
      var ext = gl.getSupportedExtensions() || [];
      out.extensionCount = ext.length;
      out.extensions = ext.slice(0, 24).join(',');
      var prec = gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT);
      out.highFloatPrecision = prec ? prec.precision : null;
      gl.getExtension('WEBGL_lose_context') && gl.getExtension('WEBGL_lose_context').loseContext();
      return out;
    } catch (e) { return null; }
  }

  function networkInfo() {
    var nav = navigator || {};
    if (!nav.connection) return null;
    return {
      onLine: nav.onLine != null ? nav.onLine : null,
      effectiveType: nav.connection.effectiveType || null,
      downlink: nav.connection.downlink != null ? nav.connection.downlink : null,
      rtt: nav.connection.rtt != null ? nav.connection.rtt : null,
      saveData: nav.connection.saveData != null ? !!nav.connection.saveData : null
    };
  }

  function visualPrefs() {
    try {
      var m = window.matchMedia;
      if (!m) return null;
      return {
        colorScheme: m('(prefers-color-scheme: dark)').matches ? 'dark' : 'light',
        reducedMotion: m('(prefers-reduced-motion: reduce)').matches,
        reducedData: m('(prefers-reduced-data: reduce)').matches,
        forcedColors: m('(forced-colors: active)').matches,
        contrast: m('(prefers-contrast: more)').matches ? 'more' : (m('(prefers-contrast: less)').matches ? 'less' : 'no-preference')
      };
    } catch (e) { return null; }
  }

  function storageInfo() {
    var out = {};
    out.localStorage = !!safe(function () { localStorage.setItem('__fp', '1'); localStorage.removeItem('__fp'); return true; });
    out.sessionStorage = !!safe(function () { sessionStorage.setItem('__fp', '1'); sessionStorage.removeItem('__fp'); return true; });
    out.indexedDB = !!safe(function () { return !!window.indexedDB; });
    return out;
  }

  function uaDataSync() {
    try {
      var ud = navigator.userAgentData;
      if (!ud) return null;
      return {
        brands: (ud.brands || []).map(function (b) { return b.brand + ' ' + b.version; }),
        platform: ud.platform || null,
        mobile: ud.mobile != null ? !!ud.mobile : null
      };
    } catch (e) { return null; }
  }

  var FONT_PROBES = ['Arial','Arial Black','Bahnschrift','Calibri','Cambria','Candara','Comic Sans MS','Consolas','Courier New','Franklin Gothic Medium','Futura','Garamond','Georgia','Gill Sans','Helvetica','Impact','KaiTi','Lucida Console','Malgun Gothic','Meiryo','Melvetica','MingLiU','Monaco','Nirmala UI','Palatino','Segoe Print','Segoe UI','Sitka Small','Tahoma','Times New Roman','Trebuchet MS','Verdana','Webdings'];

  function probeFonts() {
    try {
      var c = document.createElement('canvas');
      c.width = 400; c.height = 80;
      var ctx = c.getContext('2d');
      if (!ctx) return [];
      ctx.font = '72px monospace';
      var baseline = ctx.measureText('mmmmmmmmmmlli').width;
      var found = [];
      for (var i = 0; i < FONT_PROBES.length; i++) {
        var f = FONT_PROBES[i];
        ctx.font = '72px "' + f + '", monospace';
        if (ctx.measureText('mmmmmmmmmmlli').width !== baseline) found.push(f);
      }
      return found;
    } catch (e) { return []; }
  }

  function audioSignal() {
    try {
      if (typeof window.OfflineAudioContext === 'undefined') return null;
      var ctx = new OfflineAudioContext(1, 44100, 44100);
      var osc = ctx.createOscillator();
      osc.type = 'triangle';
      osc.frequency.value = 10000;
      var comp = ctx.createDynamicsCompressor();
      comp.threshold.value = -50;
      comp.knee.value = 40;
      comp.ratio.value = 12;
      comp.attack.value = 0;
      comp.release.value = 0.25;
      osc.connect(comp);
      comp.connect(ctx.destination);
      osc.start(0);
      return ctx.startRendering().then(function (buf) {
        var d = buf.getChannelData(0);
        var h = 0;
        for (var i = 0; i < d.length; i += 4) {
          h = ((h << 5) - h) + Math.floor((d[i] * 0.5 + 0.5) * 255);
          h |= 0;
        }
        return { supported: true, hash: 'ah_' + Math.abs(h).toString(16) };
      }).catch(function () { return { supported: true, hash: null }; });
    } catch (e) { return null; }
  }

  function batteryInfo() {
    return new Promise(function (resolve) {
      try {
        if (!navigator.getBattery) { resolve(null); return; }
        navigator.getBattery().then(function (b) {
          resolve({ level: Math.round(b.level * 100), charging: !!b.charging });
        }, function () { resolve(null); });
      } catch (e) { resolve(null); }
    });
  }

  function mediaInfo() {
    return new Promise(function (resolve) {
      try {
        if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) { resolve(null); return; }
        navigator.mediaDevices.enumerateDevices().then(function (list) {
          var counts = { audioinput: 0, audiooutput: 0, videoinput: 0 };
          var labeled = false;
          for (var i = 0; i < list.length; i++) {
            var k = list[i].kind;
            if (counts[k] !== undefined) counts[k]++;
            if (list[i].label) labeled = true;
          }
          resolve({ counts: counts, labelsVisible: labeled });
        }, function () { resolve(null); });
      } catch (e) { resolve(null); }
    });
  }

  function highEntropyUa() {
    return new Promise(function (resolve) {
      try {
        var ud = navigator.userAgentData;
        if (!ud || !ud.getHighEntropyValues) { resolve(null); return; }
        ud.getHighEntropyValues(['architecture', 'bitness', 'model', 'platformVersion']).then(function (v) {
          resolve({ architecture: v.architecture || null, bitness: v.bitness || null, model: v.model || null, platformVersion: v.platformVersion || null });
        }, function () { resolve(null); });
      } catch (e) { resolve(null); }
    });
  }

  /* -------------------------------------------------------------------- *
   *  CreepJS-derived probes (fingerprint_detail only)
   * -------------------------------------------------------------------- *
   *  Techniques re-implemented in this file's own ES5 idiom; no CreepJS code
   *  is vendored. Everything below feeds collectDetail()/asyncDetail() and so
   *  reaches only the display/evidence payload. collectSignals() and
   *  computeFingerprint() are deliberately untouched: the identity hash is
   *  stored per bound device, so adding an input would invalidate every
   *  binding in the database.
   * -------------------------------------------------------------------- */

  var MAIN_VENDOR = null;   // main-thread WEBGL_debug_renderer_info, cached by
  var MAIN_RENDERER = null; // collectDetail so nothing needs a second context.

  function shortHash(str) {
    var s = String(str);
    var h = 0x811c9dc5;
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = (h + (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
    }
    return h.toString(16);
  }

  function domRectProbe() {
    var host = null;
    try {
      if (!document.body) return null;
      host = document.createElement('div');
      host.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:420px;height:240px;visibility:hidden';
      var specs = [
        'width:100.7px;height:20.3px;font-size:11px;padding:1.7px;border:0.7px solid #000',
        'width:33.33px;height:9.9px;margin-left:2.5px;transform:rotate(11.7deg) scale(1.13)',
        'width:0.9px;height:0.9px;transform:skewX(7.3deg) translateY(1.1px)',
        'width:120px;font:italic 13.3px "Times New Roman", serif;letter-spacing:0.7px',
        'display:inline-block;font:15.5px "Segoe UI", Arial, sans-serif;padding:0.3px 1.9px'
      ];
      var els = [];
      var i;
      for (i = 0; i < specs.length; i++) {
        var el = document.createElement('div');
        el.style.cssText = specs[i];
        el.textContent = 'fp-guard █░é中 ' + i;
        host.appendChild(el);
        els.push(el);
      }
      var emoji = document.createElement('span');
      emoji.style.cssText = 'display:inline-block;font:20px sans-serif;white-space:nowrap';
      emoji.textContent = '😀🦄❤️👩‍💻🏳️‍🌈';
      host.appendChild(emoji);
      document.body.appendChild(host);
      // Sizes and host-relative offsets only: raw viewport coordinates move
      // with the scroll position, which would make the digest unstable.
      var base = host.getBoundingClientRect();
      var vals = [];
      for (i = 0; i < els.length; i++) {
        var r = els[i].getBoundingClientRect();
        vals.push(r.width, r.height, r.left - base.left, r.top - base.top);
        var list = els[i].getClientRects();
        vals.push(list ? list.length : -1);
        if (list && list.length) vals.push(list[0].width, list[0].height);
      }
      var er = emoji.getBoundingClientRect();
      return {
        hash: 'dr_' + shortHash(vals.join(',')),
        emojiHash: 'dre_' + shortHash(er.width + ',' + er.height),
        emojiWidth: Math.round(er.width * 100) / 100,
        count: els.length
      };
    } catch (e) {
      return null;
    } finally {
      try { if (host && host.parentNode) host.parentNode.removeChild(host); } catch (e2) {}
    }
  }

  var TM_STACKS = [
    '16px "Arial"',
    'italic 700 17.5px "Times New Roman", serif',
    '13px "Segoe UI", system-ui, sans-serif',
    '15px monospace',
    '20px "Courier New", "Consolas", monospace'
  ];

  function textMetricsProbe() {
    try {
      var c = document.createElement('canvas');
      c.width = 320; c.height = 60;
      var ctx = c.getContext('2d');
      if (!ctx || !ctx.measureText) return null;
      var sample = 'mmMwWLlIi0Oo — fp-guard 123 é中';
      var vals = [];
      var hasBox = false;
      for (var i = 0; i < TM_STACKS.length; i++) {
        ctx.font = TM_STACKS[i];
        var m = safe(function () { return ctx.measureText(sample); });
        if (!m) { vals.push(''); continue; }
        if (m.actualBoundingBoxAscent != null) hasBox = true;
        vals.push(
          m.width,
          m.actualBoundingBoxAscent != null ? m.actualBoundingBoxAscent : '',
          m.actualBoundingBoxDescent != null ? m.actualBoundingBoxDescent : '',
          m.fontBoundingBoxAscent != null ? m.fontBoundingBoxAscent : '',
          m.fontBoundingBoxDescent != null ? m.fontBoundingBoxDescent : '',
          m.actualBoundingBoxLeft != null ? m.actualBoundingBoxLeft : '',
          m.actualBoundingBoxRight != null ? m.actualBoundingBoxRight : ''
        );
      }
      if (!vals.length) return null;
      return {
        hash: 'tm_' + shortHash(vals.join(',')),
        stacks: TM_STACKS.length,
        hasBoundingBox: hasBox
      };
    } catch (e) { return null; }
  }

  // Fixed battery of transcendental calls. The exact double each engine build
  // returns for these is a stable engine/libm signature that barely moves
  // across minor browser updates.
  var MATH_OPS = [
    ['acos', function () { return Math.acos(0.123456789); }],
    ['acosh', function () { return Math.acosh(1e308); }],
    ['acoshSmall', function () { return Math.acosh(1.0000000000000002); }],
    ['asin', function () { return Math.asin(0.123456789); }],
    ['asinh', function () { return Math.asinh(1e308); }],
    ['atan', function () { return Math.atan(2); }],
    ['atanh', function () { return Math.atanh(0.5); }],
    ['atanhSmall', function () { return Math.atanh(1e-7); }],
    ['atan2', function () { return Math.atan2(1e-310, 2); }],
    ['cosh', function () { return Math.cosh(1); }],
    ['coshBig', function () { return Math.cosh(710); }],
    ['expm1', function () { return Math.expm1(1); }],
    ['expm1Small', function () { return Math.expm1(1e-15); }],
    ['sinh', function () { return Math.sinh(1); }],
    ['tanh', function () { return Math.tanh(1); }],
    ['log1p', function () { return Math.log1p(10); }],
    ['log1pSmall', function () { return Math.log1p(1e-16); }],
    ['sinBig', function () { return Math.sin(-1e300); }],
    ['cosBig', function () { return Math.cos(1e300); }],
    ['tanBig', function () { return Math.tan(-1e308); }],
    ['powPi', function () { return Math.pow(Math.PI, -100); }],
    ['powDenormal', function () { return Math.pow(2, -1074); }],
    ['powNear1', function () { return Math.pow(1.0000000000000002, 1e15); }],
    ['exp', function () { return Math.exp(1); }],
    ['hypot', function () { return Math.hypot(0.1, 0.2, 0.3); }],
    ['cbrt', function () { return Math.cbrt(100); }]
  ];

  function mathQuirks() {
    try {
      var parts = [];
      for (var i = 0; i < MATH_OPS.length; i++) {
        var v = safe(MATH_OPS[i][1]);
        var s;
        if (typeof v !== 'number') { s = 'null'; }
        else if (v !== v) { s = 'NaN'; }
        else { s = String(v); }
        parts.push(MATH_OPS[i][0] + '=' + s);
      }
      return { hash: 'mq_' + shortHash(parts.join('|')), count: parts.length };
    } catch (e) { return null; }
  }

  // Deliberate TypeErrors: the wording of .message differs per engine (V8 vs
  // SpiderMonkey vs JavaScriptCore) and per major version.
  var ERROR_OPS = [
    ['nullProp', function () { var o = null; return o.x; }],
    ['undefProp', function () { var u; return u.x; }],
    ['notAFunction', function () { var o = {}; return o.nope(); }],
    ['numberCall', function () { var n = 1; return n(); }],
    ['frozenWrite', function () { var o = Object.freeze({ a: 1 }); o.a = 2; return o.a; }],
    ['circularJson', function () { var a = {}; a.self = a; return JSON.stringify(a); }]
  ];

  function engineErrors() {
    try {
      var msgs = {};
      var joined = [];
      for (var i = 0; i < ERROR_OPS.length; i++) {
        var m = '';
        try {
          ERROR_OPS[i][1]();
          m = '';
        } catch (err) {
          m = (err && err.message) ? String(err.message) : String(err);
        }
        m = m.slice(0, 120);
        msgs[ERROR_OPS[i][0]] = m;
        joined.push(ERROR_OPS[i][0] + '=' + m);
      }
      return { hash: 'ee_' + shortHash(joined.join('|')), messages: msgs };
    } catch (e) { return null; }
  }

  // Presence-only API set: a coarse partitioner that is very stable across
  // minor updates. Dotted paths double as the emitted key names so the admin
  // renderer needs no separate legend.
  var FEATURE_PATHS = [
    'window.OffscreenCanvas', 'window.SharedWorker', 'window.WebAssembly',
    'window.SharedArrayBuffer', 'window.Atomics', 'window.ReportingObserver',
    'window.ResizeObserver', 'window.IntersectionObserver', 'window.PaymentRequest',
    'window.AudioWorklet', 'window.MediaRecorder', 'window.speechSynthesis',
    'window.showOpenFilePicker', 'window.structuredClone', 'window.queueMicrotask',
    'window.trustedTypes', 'window.WeakRef', 'window.FinalizationRegistry',
    'window.CSS.registerProperty', 'window.chrome', 'window.opr', 'window.safari',
    'navigator.credentials', 'navigator.locks', 'navigator.storage',
    'navigator.permissions', 'navigator.serviceWorker', 'navigator.usb',
    'navigator.bluetooth', 'navigator.hid', 'navigator.serial', 'navigator.gpu',
    'navigator.xr', 'navigator.wakeLock', 'navigator.mediaSession',
    'navigator.presentation', 'navigator.virtualKeyboard',
    'navigator.windowControlsOverlay', 'navigator.ink', 'navigator.scheduling',
    'navigator.userActivation', 'navigator.setAppBadge', 'navigator.share',
    'navigator.clipboard', 'navigator.getGamepads', 'navigator.pdfViewerEnabled',
    'document.startViewTransition', 'Intl.DisplayNames', 'Intl.Segmenter',
    'Intl.ListFormat', 'Array.prototype.at', 'String.prototype.replaceAll',
    'Object.hasOwn', 'Promise.any', 'Error.captureStackTrace'
  ];

  function hasPath(path) {
    try {
      var parts = path.split('.');
      var cur = window;
      for (var i = 0; i < parts.length; i++) {
        if (parts[i] === 'window') continue;
        if (cur === null || cur === undefined) return false;
        cur = Object(cur)[parts[i]];
      }
      return cur !== undefined;
    } catch (e) { return false; }
  }

  function featureProbe() {
    try {
      var map = {};
      var bits = '';
      for (var i = 0; i < FEATURE_PATHS.length; i++) {
        var ok = hasPath(FEATURE_PATHS[i]);
        map[FEATURE_PATHS[i]] = ok;
        bits += ok ? '1' : '0';
      }
      return { hash: 'ft_' + shortHash(bits), map: map };
    } catch (e) { return null; }
  }

  // CSS system colours resolve from the OS/UA theme. ActiveText in particular
  // is a known headless tell, and unsupported keywords are themselves a
  // version signal (an ignored assignment reports null).
  var SYS_COLORS = ['ActiveText', 'ButtonBorder', 'ButtonFace', 'ButtonText',
    'Canvas', 'CanvasText', 'Field', 'FieldText', 'GrayText', 'Highlight',
    'HighlightText', 'LinkText', 'Mark', 'MarkText', 'VisitedText',
    'AccentColor', 'AccentColorText', 'SelectedItem', 'SelectedItemText'];

  function cssProbe() {
    var host = null;
    try {
      if (!document.body || !window.getComputedStyle) return null;
      host = document.createElement('div');
      host.style.cssText = 'position:absolute;left:-9999px;top:-9999px;visibility:hidden';
      var cells = [];
      var i;
      for (i = 0; i < SYS_COLORS.length; i++) {
        var cell = document.createElement('span');
        // Assigning through the CSSOM rather than a parsed style attribute:
        // style-src refuses the attribute form, the CSSOM is unaffected.
        try { cell.style.color = SYS_COLORS[i]; } catch (e) {}
        cell.textContent = '.';
        host.appendChild(cell);
        cells.push(cell);
      }
      var plain = document.createElement('div');
      plain.textContent = '.';
      host.appendChild(plain);
      document.body.appendChild(host);
      var colors = {};
      var joined = '';
      for (i = 0; i < SYS_COLORS.length; i++) {
        var val = null;
        // An empty inline value means the engine did not recognise the keyword.
        if (cells[i].style.color) {
          val = safe(function () { var cs = window.getComputedStyle(cells[i]); return cs ? cs.color : null; });
        }
        colors[SYS_COLORS[i]] = val || null;
        joined += SYS_COLORS[i] + ':' + (val || '') + ';';
      }
      var defaults = safe(function () {
        var d = window.getComputedStyle(plain);
        if (!d) return null;
        return {
          fontFamily: d.fontFamily || null,
          fontSize: d.fontSize || null,
          lineHeight: d.lineHeight || null,
          color: d.color || null,
          textSizeAdjust: d.webkitTextSizeAdjust || d.textSizeAdjust || null,
          tabSize: d.tabSize || d.mozTabSize || null,
          fontSynthesis: d.fontSynthesis || null
        };
      });
      return { hash: 'cs_' + shortHash(joined), systemColors: colors, defaults: defaults || null };
    } catch (e) {
      return null;
    } finally {
      try { if (host && host.parentNode) host.parentNode.removeChild(host); } catch (e2) {}
    }
  }

  // navigator.plugins is trivial to fake; a mutually consistent plugin/MIME
  // graph is not. Deliberately lenient about which plugin a MIME type names as
  // its enabledPlugin: stock Chromium ships five PDF plugins whose two MIME
  // types both point back at the first one, so demanding an exact pairing
  // would flag every real Chrome install.
  function pluginMimeProbe() {
    try {
      var nav = navigator || {};
      var plugins = nav.plugins;
      var mimes = nav.mimeTypes;
      if (!plugins || !mimes) return null;
      var pc = plugins.length || 0;
      var mc = mimes.length || 0;
      var mismatches = 0;
      var names = {};
      var i, j;
      for (i = 0; i < pc; i++) {
        if (!plugins[i]) { mismatches++; continue; }
        names[String(plugins[i].name)] = true;
        var inner = plugins[i].length || 0;
        // A plugin advertising no MIME type at all is not something a real
        // browser produces.
        if (!inner) { mismatches++; continue; }
        for (j = 0; j < inner; j++) {
          var mt = plugins[i][j];
          if (!mt || !mt.type) { mismatches++; continue; }
          var back = safe(function () {
            return mimes[mt.type] || (mimes.namedItem ? mimes.namedItem(mt.type) : null);
          });
          if (!back) mismatches++;
        }
      }
      for (i = 0; i < mc; i++) {
        if (!mimes[i]) { mismatches++; continue; }
        var ep = mimes[i].enabledPlugin;
        if (!ep || !names[String(ep.name)]) mismatches++;
      }
      // Plugins with no MIME types (or the reverse) is the classic naive spoof.
      if ((pc > 0) !== (mc > 0)) mismatches++;
      return { pluginsCount: pc, mimeTypesCount: mc, consistent: mismatches === 0, mismatches: mismatches };
    } catch (e) { return null; }
  }

  /* Headless / automation detection, definitive tier only.
   *
   * Two tiers deliberately: 'headless' is reserved for signals a normal
   * browser cannot produce (the webdriver flag, a HeadlessChrome UA on the
   * main thread or in the worker). Everything circumstantial caps at
   * 'suspect' — a software rasteriser, a missing PDF viewer and a taskbar-less
   * screen all occur on real VDI/kiosk desktops, so none of them may be enough
   * to call a visitor a bot on their own.
   */
  var AUTOMATION_CACHE = null;

  function isChromiumBuild() {
    try {
      var ua = navigator.userAgent || '';
      if (/Chrom(e|ium)\//.test(ua) || /Edg\//.test(ua)) return true;
      return !!window.chrome;
    } catch (e) { return false; }
  }

  function automationInfo() {
    var hard = [];
    var soft = [];
    var nav = navigator || {};
    var ua = safe(function () { return nav.userAgent || ''; }) || '';
    var appv = safe(function () { return nav.appVersion || ''; }) || '';
    if (safe(function () { return nav.webdriver === true; }) === true) hard.push('webdriver');
    if (/HeadlessChrome/i.test(ua)) hard.push('uaHeadless');
    if (/HeadlessChrome/i.test(appv)) hard.push('appVersionHeadless');
    // navigator.webdriver is mandatory from Chrome 63 / Firefox 56 on, so a
    // build that new with the property gone has had it deleted.
    var chromeVer = safe(function () { var m = /Chrom(?:e|ium)\/(\d+)/.exec(ua); return m ? parseInt(m[1], 10) : 0; }) || 0;
    var ffVer = safe(function () { var m = /Firefox\/(\d+)/.exec(ua); return m ? parseInt(m[1], 10) : 0; }) || 0;
    if (safe(function () { return 'webdriver' in nav; }) === false && (chromeVer >= 63 || ffVer >= 56)) soft.push('webdriverMissing');
    if (MAIN_RENDERER && /SwiftShader|llvmpipe|Software Rasterizer|Mesa OffScreen/i.test(String(MAIN_RENDERER))) soft.push('softwareRenderer');
    if (safe(function () { return 'pdfViewerEnabled' in nav ? nav.pdfViewerEnabled : null; }) === false && isChromiumBuild()) soft.push('pdfViewerDisabled');
    if (safe(function () { return screen.height === screen.availHeight; }) === true) soft.push('noTaskbar');
    AUTOMATION_CACHE = { hard: hard, soft: soft };
    return { verdict: hard.length ? 'headless' : (soft.length ? 'suspect' : 'clean'), hits: hard.concat(soft) };
  }

  // Re-decides once the worker UA is in. Returns null when the worker added
  // nothing, so the async merge leaves the synchronous verdict alone.
  function automationWithWorker(workerUa) {
    try {
      var c = AUTOMATION_CACHE;
      if (!c || !workerUa) return null;
      if (!/HeadlessChrome/i.test(String(workerUa))) return null;
      if (c.hard.indexOf('workerUaHeadless') !== -1) return null;
      var hard = c.hard.concat(['workerUaHeadless']);
      c.hard = hard;
      return { verdict: 'headless', hits: hard.concat(c.soft) };
    } catch (e) { return null; }
  }

  /* Worker-scope comparison.
   *
   * Spoofing extensions patch the main-thread navigator and routinely forget
   * the worker scopes, so any property that disagrees across the boundary is a
   * strong tamper signal. The worker is built from a Blob URL because this
   * script may not add files; the URL is revoked as soon as the probe settles.
   *
   * A service-worker scope is deliberately NOT attempted: registration needs a
   * real same-origin script URL (blob: is refused) and it would leave a
   * persistent registration behind on a login page. Shared scope is tried
   * first, dedicated second.
   */
  var WORKER_TIMEOUT_MS = 1500;
  var WORKER_SHARED_MS = 600;
  var VOICES_TIMEOUT_MS = 600;

  function workerSource() {
    return [
      'var collect = function () {',
      '  var out = {};',
      '  var nav = self.navigator || {};',
      '  try { out.platform = nav.platform == null ? null : String(nav.platform); } catch (e) { out.platform = null; }',
      '  try { out.userAgent = nav.userAgent == null ? null : String(nav.userAgent); } catch (e) { out.userAgent = null; }',
      '  try { out.hardwareConcurrency = nav.hardwareConcurrency == null ? null : nav.hardwareConcurrency; } catch (e) { out.hardwareConcurrency = null; }',
      '  try { out.deviceMemory = nav.deviceMemory == null ? null : nav.deviceMemory; } catch (e) { out.deviceMemory = null; }',
      '  try { out.language = nav.language == null ? null : String(nav.language); } catch (e) { out.language = null; }',
      '  try { out.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || null; } catch (e) { out.timezone = null; }',
      '  out.webglVendor = null; out.webglRenderer = null;',
      '  try {',
      '    if (typeof OffscreenCanvas !== "undefined") {',
      '      var oc = new OffscreenCanvas(32, 32);',
      '      var gl = oc.getContext("webgl") || oc.getContext("experimental-webgl");',
      '      if (gl) {',
      '        var dbg = gl.getExtension("WEBGL_debug_renderer_info");',
      '        if (dbg) {',
      '          out.webglVendor = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL));',
      '          out.webglRenderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL));',
      '        }',
      '      }',
      '    }',
      '  } catch (e) {}',
      '  return out;',
      '};',
      'self.onmessage = function () {',
      '  try { self.postMessage(collect()); } catch (e) { try { self.postMessage(null); } catch (e2) {} }',
      '};',
      'self.onconnect = function (ev) {',
      '  try {',
      '    var p = ev.ports[0];',
      '    if (p.start) p.start();',
      '    p.postMessage(collect());',
      '  } catch (e) {}',
      '};'
    ].join('\n');
  }

  function workerProbe() {
    return new Promise(function (resolve) {
      var settled = false;
      var timer = null;
      var url = null;
      var dedicated = null;
      var shared = null;

      function done(scope, data) {
        if (settled) return;
        settled = true;
        try { if (timer) clearTimeout(timer); } catch (e) {}
        try { if (dedicated) dedicated.terminate(); } catch (e) {}
        try { if (shared && shared.port) shared.port.close(); } catch (e) {}
        try { if (url) URL.revokeObjectURL(url); } catch (e) {}
        resolve(data ? { scope: scope, data: data } : null);
      }

      function startDedicated() {
        if (settled || dedicated) return;
        try {
          if (!window.Worker) { done(null, null); return; }
          dedicated = new Worker(url);
          dedicated.onmessage = function (ev) { if (ev && ev.data) done('dedicated', ev.data); else done(null, null); };
          dedicated.onerror = function () { done(null, null); };
          dedicated.postMessage('go');
        } catch (e) {
          // A CSP without blob: in worker-src/script-src refuses construction
          // outright. Settle immediately rather than burning the whole budget.
          done(null, null);
        }
      }

      try {
        if (!window.Worker && !window.SharedWorker) { resolve(null); return; }
        if (!window.Blob || !window.URL || !URL.createObjectURL) { resolve(null); return; }
        url = URL.createObjectURL(new Blob([workerSource()], { type: 'text/javascript' }));
      } catch (e) { resolve(null); return; }

      timer = setTimeout(function () { done(null, null); }, WORKER_TIMEOUT_MS);

      try {
        if (window.SharedWorker) {
          shared = new SharedWorker(url, 'fpg');
          shared.port.onmessage = function (ev) { if (ev && ev.data) done('shared', ev.data); };
          shared.onerror = function () { startDedicated(); };
          if (shared.port.start) shared.port.start();
          setTimeout(startDedicated, WORKER_SHARED_MS);
        } else {
          startDedicated();
        }
      } catch (e) { startDedicated(); }
    });
  }

  function workerCompare(data) {
    var mismatch = [];
    var norm = function (v) { return v == null ? '' : String(v); };
    var cmp = function (key, mainVal) {
      var w = data[key];
      // The worker writes an explicit null for anything it could not read, so a
      // null here is an absent answer rather than a disagreement — the same rule
      // the WebGL comparison below already applies.
      if (w == null) return;
      if (norm(w) !== norm(mainVal)) mismatch.push(key);
    };
    try {
      if (!data) return mismatch;
      var nav = navigator || {};
      cmp('platform', safe(function () { return nav.platform; }));
      cmp('userAgent', safe(function () { return nav.userAgent; }));
      cmp('hardwareConcurrency', safe(function () { return nav.hardwareConcurrency; }));
      cmp('deviceMemory', safe(function () { return nav.deviceMemory; }));
      cmp('language', safe(function () { return nav.language; }));
      cmp('timezone', safe(function () { return Intl.DateTimeFormat().resolvedOptions().timeZone; }));
      // WebGL only when the worker actually answered: OffscreenCanvas or the
      // debug-renderer extension being unavailable in a worker is normal and
      // must not read as a lie.
      if (data.webglVendor && MAIN_VENDOR && String(data.webglVendor) !== String(MAIN_VENDOR)) mismatch.push('webglVendor');
      if (data.webglRenderer && MAIN_RENDERER && String(data.webglRenderer) !== String(MAIN_RENDERER)) mismatch.push('webglRenderer');
    } catch (e) { /* whatever was collected so far stands */ }
    return mismatch;
  }

  /* Installed voice list. speechSynthesis.getVoices() is empty until the engine
   * has loaded them, so an empty first read is hooked and given a short budget
   * rather than reported as "no voices". */
  function speechVoices() {
    return new Promise(function (resolve) {
      var settled = false;
      var syn = null;
      try { syn = window.speechSynthesis; } catch (e) { syn = null; }
      if (!syn || !syn.getVoices) { resolve(null); return; }

      function shape(list) {
        var names = [];
        var joined = '';
        var def = null;
        for (var i = 0; i < list.length; i++) {
          var v = list[i];
          if (!v) continue;
          var n = String(v.name || v.voiceURI || '?');
          names.push(n);
          joined += n + '|' + String(v.lang || '') + '|' + (v.localService ? '1' : '0') + ';';
          if (v['default'] && !def) def = n;
        }
        return { count: names.length, names: names, defaultVoice: def, hash: 'sv_' + shortHash(joined) };
      }

      function finish() {
        if (settled) return;
        settled = true;
        try { syn.onvoiceschanged = null; } catch (e) {}
        var list = safe(function () { return syn.getVoices() || []; }) || [];
        resolve(list.length ? shape(list) : { count: 0, names: [], defaultVoice: null, hash: 'sv_0' });
      }

      var first = safe(function () { return syn.getVoices() || []; }) || [];
      if (first.length) { settled = true; resolve(shape(first)); return; }
      try { syn.onvoiceschanged = finish; } catch (e) {}
      setTimeout(finish, VOICES_TIMEOUT_MS);
    });
  }

  // The wording of the captured TypeErrors names the engine outright.
  function engineName(msgs) {
    try {
      if (!msgs) return null;
      var all = '';
      for (var k in msgs) { if (msgs[k]) all += String(msgs[k]) + ' '; }
      if (!all) return null;
      if (/Cannot read propert(y|ies)|is not a function|Assignment to constant|Converting circular structure/.test(all)) return 'V8';
      if (/is null|is undefined|can't access propert|cyclic object value/.test(all)) return 'SpiderMonkey';
      if (/null is not an object|undefined is not an object|is not a function\.|JSON\.stringify cannot serialize cyclic/.test(all)) return 'JavaScriptCore';
      return null;
    } catch (e) { return null; }
  }

  // Flattens the two engine probes into the one object the admin renderer
  // reads, with errors as a printable list rather than a map.
  function engineDigest(mq, ee) {
    var out = {};
    if (mq) { out.mathDigest = mq.hash; out.mathCount = mq.count; }
    if (ee) {
      out.errorsHash = ee.hash;
      var list = [];
      for (var k in ee.messages) { list.push(k + ': ' + ee.messages[k]); }
      out.errors = list;
      out.name = engineName(ee.messages);
    }
    return out;
  }

  /* -------------------------------------------------------------------- *
   *  Lie detection
   * -------------------------------------------------------------------- *
   *  Every other probe reads a value the page can rewrite. These read the
   *  *plumbing* instead: a spoofer has to replace a native accessor or method
   *  to change what the other probes see, and a replacement is detectable
   *  regardless of how convincing the value it returns is.
   *
   *  False positives matter more than misses here — this feeds an operator
   *  screen, not a block decision — so a property that is simply unsupported
   *  is never counted, and every check that cannot run is skipped rather than
   *  guessed.
   * -------------------------------------------------------------------- */

  function nativeSrc(fn) {
    // Whitespace differs between engines (V8 one line, SpiderMonkey three).
    return String(Function.prototype.toString.call(fn)).replace(/\s+/g, '');
  }

  function fnLie(fn, expectName) {
    try {
      if (typeof fn !== 'function') return 'notFunction';
      if (!/\[nativecode\]\}$/.test(nativeSrc(fn))) return 'notNative';
      // Function.prototype.bind returns something that still stringifies as
      // native, so the name is what gives a bound spoof away.
      if (expectName && fn.name && fn.name !== expectName && fn.name !== 'get ' + expectName) return 'renamed';
      // Native methods and accessors carry no .prototype; a plain function does.
      if (Object.getOwnPropertyDescriptor(fn, 'prototype')) return 'hasPrototype';
      var own = Object.getOwnPropertyNames(fn);
      for (var i = 0; i < own.length; i++) {
        if (own[i] !== 'length' && own[i] !== 'name' && own[i] !== 'prototype') return 'ownProp:' + own[i];
      }
      return null;
    } catch (e) { return 'threw'; }
  }
  function getterLie(protoFn, prop, instFn) {
    var proto, inst, d;
    try { proto = protoFn(); } catch (e) { return null; }
    if (!proto) return null;
    try { inst = instFn ? instFn() : null; } catch (e) { inst = null; }
    try { d = Object.getOwnPropertyDescriptor(proto, prop); } catch (e) { return null; }
    if (!d) {
      var reachable = false;
      try { reachable = prop in (inst || proto); } catch (e2) {}
      // Not on the prototype and not reachable at all: an API this browser
      // simply does not have. Only a value that IS reachable while the
      // prototype slot is gone means someone moved it.
      return reachable ? 'movedOffPrototype' : null;
    }
    if (inst) {
      try {
        if (Object.prototype.hasOwnProperty.call(inst, prop)) return 'instanceOwn';
      } catch (e3) {}
    }
    if (!d.get) return d.set ? 'setterOnly' : 'dataProperty';
    var bad = fnLie(d.get, prop);
    if (bad) return bad;
    // A real accessor rejects a foreign receiver ("Illegal invocation").
    try {
      d.get.call({});
      return 'noReceiverCheck';
    } catch (e4) { /* throwing is the correct behaviour */ }
    return null;
  }

  function g(path) { return function () { return hasPath(path) ? evalPath(path) : null; }; }

  function evalPath(path) {
    var parts = path.split('.');
    var cur = window;
    for (var i = 0; i < parts.length; i++) {
      if (parts[i] === 'window') continue;
      if (cur === null || cur === undefined) return null;
      cur = Object(cur)[parts[i]];
    }
    return cur;
  }

  // Methods a canvas/audio/geometry spoofer has to replace to change what the
  // other probes in this file see.
  var LIE_METHODS = [
    ['Function.prototype.toString', 'Function.prototype', 'toString'],
    ['HTMLCanvasElement.toDataURL', 'HTMLCanvasElement.prototype', 'toDataURL'],
    ['HTMLCanvasElement.toBlob', 'HTMLCanvasElement.prototype', 'toBlob'],
    ['HTMLCanvasElement.getContext', 'HTMLCanvasElement.prototype', 'getContext'],
    ['CanvasRenderingContext2D.getImageData', 'CanvasRenderingContext2D.prototype', 'getImageData'],
    ['CanvasRenderingContext2D.measureText', 'CanvasRenderingContext2D.prototype', 'measureText'],
    ['CanvasRenderingContext2D.fillText', 'CanvasRenderingContext2D.prototype', 'fillText'],
    ['WebGLRenderingContext.getParameter', 'WebGLRenderingContext.prototype', 'getParameter'],
    ['WebGLRenderingContext.getExtension', 'WebGLRenderingContext.prototype', 'getExtension'],
    ['WebGLRenderingContext.getSupportedExtensions', 'WebGLRenderingContext.prototype', 'getSupportedExtensions'],
    ['WebGLRenderingContext.readPixels', 'WebGLRenderingContext.prototype', 'readPixels'],
    ['WebGLRenderingContext.getShaderPrecisionFormat', 'WebGLRenderingContext.prototype', 'getShaderPrecisionFormat'],
    ['AudioBuffer.getChannelData', 'AudioBuffer.prototype', 'getChannelData'],
    ['AudioBuffer.copyFromChannel', 'AudioBuffer.prototype', 'copyFromChannel'],
    ['AnalyserNode.getFloatFrequencyData', 'AnalyserNode.prototype', 'getFloatFrequencyData'],
    ['Element.getBoundingClientRect', 'Element.prototype', 'getBoundingClientRect'],
    ['Element.getClientRects', 'Element.prototype', 'getClientRects'],
    ['Range.getBoundingClientRect', 'Range.prototype', 'getBoundingClientRect'],
    ['Date.getTimezoneOffset', 'Date.prototype', 'getTimezoneOffset'],
    ['Intl.DateTimeFormat.resolvedOptions', 'Intl.DateTimeFormat.prototype', 'resolvedOptions'],
    ['SVGTextContentElement.getComputedTextLength', 'SVGTextContentElement.prototype', 'getComputedTextLength'],
    ['SVGTextContentElement.getExtentOfChar', 'SVGTextContentElement.prototype', 'getExtentOfChar'],
    ['MediaDevices.enumerateDevices', 'MediaDevices.prototype', 'enumerateDevices'],
    ['Permissions.query', 'Permissions.prototype', 'query'],
    ['Performance.now', 'Performance.prototype', 'now'],
    ['CSSStyleDeclaration.getPropertyValue', 'CSSStyleDeclaration.prototype', 'getPropertyValue'],
    ['window.getComputedStyle', 'window', 'getComputedStyle'],
    ['Object.getOwnPropertyDescriptor', 'Object', 'getOwnPropertyDescriptor'],
    ['Object.defineProperty', 'Object', 'defineProperty'],
    ['Object.getOwnPropertyNames', 'Object', 'getOwnPropertyNames'],
    ['Reflect.get', 'Reflect', 'get'],
    ['SpeechSynthesis.getVoices', 'SpeechSynthesis.prototype', 'getVoices']
  ];

  // Accessors whose returned value the other probes report verbatim.
  var LIE_GETTERS = [
    ['navigator.platform', 'Navigator.prototype', 'platform', 'navigator'],
    ['navigator.userAgent', 'Navigator.prototype', 'userAgent', 'navigator'],
    ['navigator.appVersion', 'Navigator.prototype', 'appVersion', 'navigator'],
    ['navigator.language', 'Navigator.prototype', 'language', 'navigator'],
    ['navigator.languages', 'Navigator.prototype', 'languages', 'navigator'],
    ['navigator.hardwareConcurrency', 'Navigator.prototype', 'hardwareConcurrency', 'navigator'],
    ['navigator.deviceMemory', 'Navigator.prototype', 'deviceMemory', 'navigator'],
    ['navigator.plugins', 'Navigator.prototype', 'plugins', 'navigator'],
    ['navigator.mimeTypes', 'Navigator.prototype', 'mimeTypes', 'navigator'],
    ['navigator.webdriver', 'Navigator.prototype', 'webdriver', 'navigator'],
    ['navigator.vendor', 'Navigator.prototype', 'vendor', 'navigator'],
    ['navigator.maxTouchPoints', 'Navigator.prototype', 'maxTouchPoints', 'navigator'],
    ['navigator.pdfViewerEnabled', 'Navigator.prototype', 'pdfViewerEnabled', 'navigator'],
    ['navigator.cookieEnabled', 'Navigator.prototype', 'cookieEnabled', 'navigator'],
    ['navigator.doNotTrack', 'Navigator.prototype', 'doNotTrack', 'navigator'],
    ['navigator.userAgentData', 'Navigator.prototype', 'userAgentData', 'navigator'],
    ['navigator.connection', 'Navigator.prototype', 'connection', 'navigator'],
    ['screen.width', 'Screen.prototype', 'width', 'screen'],
    ['screen.height', 'Screen.prototype', 'height', 'screen'],
    ['screen.availWidth', 'Screen.prototype', 'availWidth', 'screen'],
    ['screen.availHeight', 'Screen.prototype', 'availHeight', 'screen'],
    ['screen.colorDepth', 'Screen.prototype', 'colorDepth', 'screen'],
    ['screen.pixelDepth', 'Screen.prototype', 'pixelDepth', 'screen'],
    ['TextMetrics.width', 'TextMetrics.prototype', 'width', null],
    ['PluginArray.length', 'PluginArray.prototype', 'length', null],
    ['Plugin.name', 'Plugin.prototype', 'name', null],
    ['Plugin.filename', 'Plugin.prototype', 'filename', null],
    ['MimeType.type', 'MimeType.prototype', 'type', null],
    ['MimeType.enabledPlugin', 'MimeType.prototype', 'enabledPlugin', null],
    ['DOMRectReadOnly.width', 'DOMRectReadOnly.prototype', 'width', null],
    ['DOMRectReadOnly.height', 'DOMRectReadOnly.prototype', 'height', null]
  ];

  function lieProbe() {
    try {
      var hits = [];
      var i, bad;
      for (i = 0; i < LIE_METHODS.length; i++) {
        var owner = evalPath(LIE_METHODS[i][1]);
        if (!owner) continue;
        var m = safe(function () { return owner[LIE_METHODS[i][2]]; });
        if (m === undefined || m === null) continue;
        bad = fnLie(m, LIE_METHODS[i][2]);
        if (bad) hits.push(LIE_METHODS[i][0] + ' (' + bad + ')');
      }
      for (i = 0; i < LIE_GETTERS.length; i++) {
        bad = getterLie(g(LIE_GETTERS[i][1]), LIE_GETTERS[i][2],
                        LIE_GETTERS[i][3] ? g(LIE_GETTERS[i][3]) : null);
        if (bad) hits.push(LIE_GETTERS[i][0] + ' (' + bad + ')');
      }
      // Structural checks: a spoofer that swaps the whole navigator object
      // leaves the prototype chain or the toString tag wrong.
      if (safe(function () { return Object.getPrototypeOf(navigator) !== Navigator.prototype; }) === true) hits.push('navigator.prototypeChain');
      if (safe(function () { return Object.prototype.toString.call(navigator); }) !== '[object Navigator]') hits.push('navigator.toStringTag');
      if (safe(function () { return Object.prototype.toString.call(screen); }) !== '[object Screen]') hits.push('screen.toStringTag');
      var ownNav = safe(function () { return Object.getOwnPropertyNames(navigator); });
      if (ownNav && ownNav.length) hits.push('navigator.ownProps:' + ownNav.slice(0, 4).join(','));
      if (hits.length > 40) hits = hits.slice(0, 40);
      return { count: hits.length, hits: hits, hash: 'li_' + shortHash(hits.join('|')) };
    } catch (e) { return null; }
  }
  /* Window-property diff against a pristine same-origin iframe.
   *
   * A raw diff is useless on a real page: every global our own templates
   * declare shows up as "extra". So the extra list is filtered down to names
   * that match known automation/injection markers, and only the raw counts are
   * reported for the rest. `missing` needs no filter — a property the pristine
   * iframe has and this window does not was deleted, and nothing legitimate
   * does that. */
  var AUTOMATION_GLOBAL_RE = /(^|_|\$)(webdriver|selenium|driver|puppeteer|playwright|phantom|nightmare|cdc_|domAutomation|fxdriver|awesomium|geb|watir|_Selenium|callSelenium|calledSelenium|spawn|emit|Buffer|__nightmare|__pw|__pwInitScripts|__playwright|__puppeteer)/i;

  function windowPropsProbe() {
    var frame = null;
    try {
      var mine = Object.getOwnPropertyNames(window);
      var flagged = [];
      var i;
      for (i = 0; i < mine.length; i++) {
        if (AUTOMATION_GLOBAL_RE.test(mine[i])) flagged.push(mine[i]);
      }
      var missing = [];
      var clean = null;
      if (document.body) {
        frame = document.createElement('iframe');
        frame.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;visibility:hidden';
        frame.setAttribute('aria-hidden', 'true');
        frame.src = 'about:blank';
        document.body.appendChild(frame);
        clean = safe(function () {
          return frame.contentWindow ? Object.getOwnPropertyNames(frame.contentWindow) : null;
        });
      }
      if (clean && clean.length) {
        var have = {};
        for (i = 0; i < mine.length; i++) have[mine[i]] = true;
        for (i = 0; i < clean.length; i++) {
          if (!have[clean[i]]) missing.push(clean[i]);
        }
      }
      if (missing.length > 30) missing = missing.slice(0, 30);
      if (flagged.length > 30) flagged = flagged.slice(0, 30);
      return {
        hash: 'wp_' + shortHash(mine.slice().sort().join(',')),
        count: mine.length,
        iframeCount: clean ? clean.length : null,
        extraCount: clean ? Math.max(0, mine.length - clean.length) : null,
        extra: flagged,
        missing: missing
      };
    } catch (e) {
      return null;
    } finally {
      try { if (frame && frame.parentNode) frame.parentNode.removeChild(frame); } catch (e2) {}
    }
  }
  /* Privacy-hardened browsers.
   *
   * Firefox's resistFingerprinting, the Tor Browser and Brave all deliberately
   * flatten the values every other probe reads. Recognising that is worth as
   * much as the entropy it costs: a hardened browser is a legitimate visitor
   * whose signals will look identical to thousands of others, so a low-entropy
   * match must not be read as the same person. This never contributes an
   * automation verdict. */
  function resistanceProbe() {
    try {
      var nav = navigator || {};
      var ua = safe(function () { return nav.userAgent || ''; }) || '';
      var engine = null;
      if (/Firefox\//.test(ua) || safe(function () { return 'mozInnerScreenX' in window; }) === true) engine = 'gecko';
      else if (/Chrom(e|ium)\/|Edg\//.test(ua) || safe(function () { return !!window.chrome; }) === true) engine = 'blink';
      else if (/Safari\//.test(ua)) engine = 'webkit';

      var hits = [];
      var mode = null;

      if (safe(function () { return typeof nav.brave === 'object' && typeof nav.brave.isBrave === 'function'; }) === true) {
        hits.push('navigator.brave');
        mode = 'brave';
      }
      if (safe(function () { return nav.globalPrivacyControl === true; }) === true) hits.push('globalPrivacyControl');

      // RFP tells, individually weak: a forced UTC clock, a spoofed core count,
      // no window chrome, no plugins, and a build ID Firefox normally exposes.
      var rfp = [];
      if (engine === 'gecko') {
        if (safe(function () { return Intl.DateTimeFormat().resolvedOptions().timeZone; }) === 'UTC'
            && safe(function () { return new Date().getTimezoneOffset(); }) === 0) rfp.push('utcClock');
        if (safe(function () { return nav.hardwareConcurrency; }) === 2) rfp.push('concurrency2');
        if (safe(function () { return 'buildID' in nav; }) === false) rfp.push('noBuildID');
        if (safe(function () { return 'oscpu' in nav ? nav.oscpu : null; }) === '') rfp.push('blankOscpu');
        if (safe(function () { return window.devicePixelRatio; }) === 1
            && safe(function () { return screen.width === window.innerWidth; }) === true) rfp.push('viewportAsScreen');
        if (safe(function () { return screen.availWidth === screen.width && screen.availHeight === screen.height; }) === true) rfp.push('noWindowChrome');
        if (safe(function () { return (nav.plugins && nav.plugins.length) || 0; }) === 0) rfp.push('noPlugins');
        // Tor rounds the content window to a multiple of 200x100.
        if (safe(function () { return window.innerWidth % 200 === 0 && window.innerHeight % 100 === 0; }) === true) rfp.push('letterboxed');
      }
      if (rfp.length >= 3) {
        mode = mode || (rfp.length >= 5 ? 'tor' : 'resistFingerprinting');
        for (var i = 0; i < rfp.length; i++) hits.push(rfp[i]);
      }
      if (safe(function () { return nav.doNotTrack === '1' || nav.doNotTrack === 'yes'; }) === true) hits.push('doNotTrack');
      return { engine: engine, mode: mode, hits: hits };
    } catch (e) { return null; }
  }

  // Deprecated APIs a browser still carries. Low entropy each, but the exact
  // set a build has not removed yet is a coarse version bucket.
  var TRASH_PATHS = ['document.all', 'document.layers', 'window.showModalDialog',
    'window.external', 'window.webkitStorageInfo', 'navigator.javaEnabled',
    'navigator.vibrate', 'navigator.getUserMedia', 'navigator.registerProtocolHandler',
    'window.orientation', 'document.caretRangeFromPoint', 'document.caretPositionFromPoint',
    'window.webkitRequestFileSystem', 'document.createEvent', 'window.escape',
    'window.captureEvents', 'window.releaseEvents', 'document.clear',
    'window.RTCIceGatherer', 'window.openDatabase'];

  function trashProbe() {
    try {
      var hits = [];
      for (var i = 0; i < TRASH_PATHS.length; i++) {
        if (hasPath(TRASH_PATHS[i])) hits.push(TRASH_PATHS[i]);
      }
      return { count: hits.length, hits: hits };
    } catch (e) { return null; }
  }
  // Locale plumbing. Every formatter carries ICU data and OS locale settings,
  // and the exact output strings differ per browser build and per platform.
  function intlProbe() {
    try {
      if (!window.Intl) return null;
      var D = new Date(1666666666666);
      var out = {};
      var ro = safe(function () { return Intl.DateTimeFormat().resolvedOptions(); }) || {};
      out.locale = ro.locale || null;
      out.calendar = ro.calendar || null;
      out.numberingSystem = ro.numberingSystem || null;
      out.timeZone = ro.timeZone || null;
      out.dateTimeFormat = safe(function () {
        return new Intl.DateTimeFormat(undefined, {
          weekday: 'long', year: 'numeric', month: 'long', day: 'numeric',
          hour: 'numeric', minute: 'numeric', second: 'numeric',
          timeZoneName: 'long', era: 'long'
        }).format(D);
      }) || null;
      out.numberFormat = safe(function () { return new Intl.NumberFormat().format(1234567.891); }) || null;
      out.currency = safe(function () {
        return new Intl.NumberFormat(undefined, { style: 'currency', currency: 'USD' }).format(1234.5)
          + ' / ' + new Intl.NumberFormat(undefined, { style: 'currency', currency: 'JPY' }).format(1234.5);
      }) || null;
      out.relativeTime = safe(function () {
        var f = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
        return f.format(-1, 'day') + ' / ' + f.format(3, 'month');
      }) || null;
      out.listFormat = safe(function () {
        return new Intl.ListFormat(undefined, { style: 'long', type: 'conjunction' }).format(['alpha', 'beta', 'gamma']);
      }) || null;
      out.pluralRules = safe(function () {
        var p = new Intl.PluralRules();
        return p.select(0) + ',' + p.select(1) + ',' + p.select(2) + ',' + p.select(1.5);
      }) || null;
      out.collator = safe(function () {
        return ['z', 'a', 'ä', 'A', 'Z', 'ö', 'b', '1', '_'].sort(new Intl.Collator().compare).join('');
      }) || null;
      out.displayNames = safe(function () {
        return new Intl.DisplayNames(undefined, { type: 'region' }).of('DE')
          + ' / ' + new Intl.DisplayNames(undefined, { type: 'language' }).of('fr');
      }) || null;
      out.segmenter = safe(function () {
        var s = new Intl.Segmenter(undefined, { granularity: 'grapheme' });
        var n = 0;
        var it = s.segment('👩‍💻é中x');
        it.forEach ? it.forEach(function () { n++; }) : (function () {
          for (var seg = it[Symbol.iterator](), r = seg.next(); !r.done; r = seg.next()) n++;
        })();
        return String(n);
      }) || null;
      var joined = '';
      for (var k in out) { joined += k + '=' + (out[k] == null ? '' : out[k]) + ';'; }
      out.hash = 'in_' + shortHash(joined);
      return out;
    } catch (e) { return null; }
  }

  // Offsets either side of the DST boundary across a century pin down the exact
  // zone rather than just the current offset, and the tzdata a build ships is
  // itself a version signal.
  function timezoneHistory() {
    try {
      var years = [1900, 1952, 1970, 1999, 2007, 2020, new Date().getFullYear()];
      var offsets = [];
      var i;
      for (i = 0; i < years.length; i++) {
        offsets.push(safe(function () { return new Date(years[i], 0, 1).getTimezoneOffset(); }));
        offsets.push(safe(function () { return new Date(years[i], 6, 1).getTimezoneOffset(); }));
      }
      var jan = offsets[offsets.length - 2];
      var jul = offsets[offsets.length - 1];
      return {
        hash: 'tz_' + shortHash(offsets.join(',')),
        offsets: offsets,
        dstShift: (typeof jan === 'number' && typeof jul === 'number') ? (jan - jul) : null,
        samples: offsets.length,
        dateString: safe(function () { return new Date(0).toString(); }) || null,
        isoString: safe(function () { return new Date(0).toISOString(); }) || null
      };
    } catch (e) { return null; }
  }
  // SVG text metrics come from a different measurement path than canvas
  // measureText, so a spoofer that patches only the canvas one disagrees here.
  function svgProbe() {
    var host = null;
    try {
      if (!document.body || !document.createElementNS) return null;
      var NS = 'http://www.w3.org/2000/svg';
      host = document.createElementNS(NS, 'svg');
      host.setAttribute('width', '400');
      host.setAttribute('height', '80');
      host.setAttribute('style', 'position:absolute;left:-9999px;top:-9999px;visibility:hidden');
      var text = document.createElementNS(NS, 'text');
      text.setAttribute('x', '0');
      text.setAttribute('y', '30');
      text.setAttribute('font-size', '17.5');
      text.setAttribute('font-family', 'Times New Roman, serif');
      text.textContent = 'mmMwWLlIi0Oo — fp-guard 123 é中';
      host.appendChild(text);
      document.body.appendChild(host);
      var r4 = function (v) { return typeof v === 'number' ? Math.round(v * 10000) / 10000 : null; };
      var bb = safe(function () { var b = text.getBBox(); return [r4(b.x), r4(b.y), r4(b.width), r4(b.height)].join(','); });
      var cl = safe(function () { return r4(text.getComputedTextLength()); });
      var sub = safe(function () {
        return [r4(text.getSubStringLength(0, 3)), r4(text.getSubStringLength(3, 8)),
                r4(text.getSubStringLength(0, text.textContent.length))].join(',');
      });
      var ext = safe(function () {
        var a = text.getExtentOfChar(0);
        var b = text.getExtentOfChar(text.textContent.length - 1);
        return [r4(a.width), r4(a.height), r4(b.width), r4(b.height)].join(',');
      });
      var nChars = safe(function () { return text.getNumberOfChars(); });
      return {
        hash: 'sg_' + shortHash([bb, cl, sub, ext].join('|')),
        bBox: bb || null,
        computedLength: cl == null ? null : String(cl),
        subStringLength: sub || null,
        extentOfChar: ext || null,
        count: nChars == null ? null : nChars
      };
    } catch (e) {
      return null;
    } finally {
      try { if (host && host.parentNode) host.parentNode.removeChild(host); } catch (e2) {}
    }
  }

  // matchMedia exposes OS accessibility and display settings that appear
  // nowhere else, and a query the engine does not understand reports false —
  // so the false/true pattern is itself a version signal.
  var CSS_MEDIA = ['(prefers-color-scheme: dark)', '(prefers-color-scheme: light)',
    '(prefers-reduced-motion: reduce)', '(prefers-reduced-transparency: reduce)',
    '(prefers-reduced-data: reduce)', '(prefers-contrast: more)', '(prefers-contrast: less)',
    '(prefers-contrast: custom)', '(forced-colors: active)', '(inverted-colors: inverted)',
    '(dynamic-range: high)', '(video-dynamic-range: high)', '(color-gamut: srgb)',
    '(color-gamut: p3)', '(color-gamut: rec2020)', '(monochrome)', '(grid: 1)',
    '(hover: hover)', '(any-hover: hover)', '(pointer: fine)', '(pointer: coarse)',
    '(any-pointer: fine)', '(any-pointer: coarse)', '(display-mode: browser)',
    '(display-mode: standalone)', '(display-mode: fullscreen)', '(orientation: portrait)',
    '(orientation: landscape)', '(scripting: enabled)', '(update: fast)', '(update: slow)',
    '(overflow-block: scroll)', '(overflow-inline: scroll)', '(scan: progressive)',
    '(color: 8)', '(color-index: 0)', '(resolution: 1dppx)', '(resolution: 2dppx)',
    '(-webkit-transform-3d)', '(-moz-touch-enabled)'];

  function cssMediaProbe() {
    try {
      if (!window.matchMedia) return null;
      var queries = {};
      var bits = '';
      for (var i = 0; i < CSS_MEDIA.length; i++) {
        var m = safe(function () { var q = window.matchMedia(CSS_MEDIA[i]); return q ? !!q.matches : null; });
        queries[CSS_MEDIA[i]] = m === null ? null : m;
        bits += m === null ? '?' : (m ? '1' : '0');
      }
      return { hash: 'cm_' + shortHash(bits), queries: queries };
    } catch (e) { return null; }
  }
  /* Separate canvas surfaces, one digest each. The identity hash's own canvas
   * input is untouched: these draw into their own elements so nothing here can
   * shift computeFingerprint(). Splitting the surfaces matters because
   * anti-fingerprint noise injection usually perturbs one path and not all of
   * them, and a digest that moves between two surfaces on the same visit is a
   * stronger tell than any single value. */
  function canvasVariants() {
    try {
      var out = {};
      out.twoD = safe(function () {
        var c = document.createElement('canvas');
        c.width = 220; c.height = 60;
        var x = c.getContext('2d');
        if (!x) return null;
        x.globalCompositeOperation = 'multiply';
        x.fillStyle = 'rgb(240,20,80)';
        x.fillRect(0, 0, 120, 40);
        x.fillStyle = 'rgba(20,120,240,0.6)';
        x.beginPath(); x.arc(70, 30, 26, 0, Math.PI * 2, true); x.fill();
        x.strokeStyle = 'rgb(10,200,120)';
        x.lineWidth = 2.7;
        x.beginPath(); x.moveTo(3.5, 55.5); x.bezierCurveTo(60, 2, 160, 58, 216, 6); x.stroke();
        x.font = 'italic 15.5px "Times New Roman", serif';
        x.fillStyle = 'rgba(0,0,0,0.75)';
        x.fillText('fp-guard — mmMwWLlIi0Oo é中', 4, 22);
        return 'c2_' + shortHash(c.toDataURL());
      }) || null;
      out.emoji = safe(function () {
        var c = document.createElement('canvas');
        c.width = 180; c.height = 44;
        var x = c.getContext('2d');
        if (!x) return null;
        x.font = '28px sans-serif';
        x.fillText('😀🦄❤️👩‍💻🏳️‍🌈', 0, 32);
        return 'ce_' + shortHash(c.toDataURL());
      }) || null;
      out.textBaseline = safe(function () {
        var c = document.createElement('canvas');
        var x = c.getContext('2d');
        if (!x || !x.measureText) return null;
        var bases = ['top', 'hanging', 'middle', 'alphabetic', 'ideographic', 'bottom'];
        var vals = [];
        for (var i = 0; i < bases.length; i++) {
          x.textBaseline = bases[i];
          x.font = '16px serif';
          var m = x.measureText('Hxg中');
          vals.push(m.width, m.actualBoundingBoxAscent, m.actualBoundingBoxDescent);
        }
        return 'cb_' + shortHash(vals.join(','));
      }) || null;
      out.webgl = safe(function () {
        var c = document.createElement('canvas');
        c.width = 24; c.height = 24;
        var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
        if (!gl) return null;
        gl.clearColor(0.3137255, 0.6039216, 0.9019608, 0.5019608);
        gl.clear(gl.COLOR_BUFFER_BIT);
        var px = new Uint8Array(24 * 24 * 4);
        gl.readPixels(0, 0, 24, 24, gl.RGBA, gl.UNSIGNED_BYTE, px);
        var acc = 0;
        var parts = [];
        for (var i = 0; i < px.length; i++) { acc = (acc + px[i] * (i % 7 + 1)) >>> 0; }
        parts.push(acc, px[0], px[1], px[2], px[3]);
        return 'cg_' + shortHash(parts.join(','));
      }) || null;
      out.webgl2 = safe(function () {
        var c = document.createElement('canvas');
        c.width = 24; c.height = 24;
        var gl = c.getContext('webgl2');
        if (!gl) return null;
        gl.clearColor(0.1254902, 0.7529412, 0.4392157, 0.2509804);
        gl.clear(gl.COLOR_BUFFER_BIT);
        var px = new Uint8Array(24 * 24 * 4);
        gl.readPixels(0, 0, 24, 24, gl.RGBA, gl.UNSIGNED_BYTE, px);
        var acc = 0;
        for (var i = 0; i < px.length; i++) { acc = (acc + px[i] * (i % 5 + 1)) >>> 0; }
        return 'c3_' + shortHash([acc, px[0], px[1], px[2], px[3]].join(','));
      }) || null;
      var joined = '';
      for (var k in out) { joined += out[k] || ''; }
      out.hash = 'cv_' + shortHash(joined);
      return out;
    } catch (e) { return null; }
  }
  var GL_PARAMS = ['ALIASED_LINE_WIDTH_RANGE', 'ALIASED_POINT_SIZE_RANGE',
    'ALPHA_BITS', 'BLUE_BITS', 'DEPTH_BITS', 'GREEN_BITS', 'RED_BITS',
    'STENCIL_BITS', 'SUBPIXEL_BITS', 'MAX_COMBINED_TEXTURE_IMAGE_UNITS',
    'MAX_CUBE_MAP_TEXTURE_SIZE', 'MAX_FRAGMENT_UNIFORM_VECTORS',
    'MAX_RENDERBUFFER_SIZE', 'MAX_TEXTURE_IMAGE_UNITS', 'MAX_TEXTURE_SIZE',
    'MAX_VARYING_VECTORS', 'MAX_VERTEX_ATTRIBS',
    'MAX_VERTEX_TEXTURE_IMAGE_UNITS', 'MAX_VERTEX_UNIFORM_VECTORS',
    'MAX_VIEWPORT_DIMS', 'SAMPLES', 'SAMPLE_BUFFERS', 'STENCIL_REF',
    'STENCIL_VALUE_MASK', 'STENCIL_WRITEMASK', 'DEPTH_FUNC',
    'IMPLEMENTATION_COLOR_READ_FORMAT', 'IMPLEMENTATION_COLOR_READ_TYPE',
    'VERSION', 'SHADING_LANGUAGE_VERSION', 'VENDOR', 'RENDERER'];

  var GL_PRECISION = ['LOW_FLOAT', 'MEDIUM_FLOAT', 'HIGH_FLOAT', 'LOW_INT',
    'MEDIUM_INT', 'HIGH_INT'];

  /* The full GL parameter table, read through a throwaway context so nothing
   * here can perturb webglSignal()'s own context. Driver-level values are hard
   * to spoof coherently: a faked RENDERER string usually keeps the real card's
   * limits, and that disagreement is the signal. */
  function webglParams() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return null;
      var params = {};
      var parts = [];
      var i, j, v;
      for (i = 0; i < GL_PARAMS.length; i++) {
        var name = GL_PARAMS[i];
        v = safe(function () {
          if (gl[name] === undefined) return undefined;
          var raw = gl.getParameter(gl[name]);
          // Typed arrays do not survive JSON.stringify as arrays.
          if (raw && typeof raw === 'object' && raw.length !== undefined) {
            return Array.prototype.slice.call(raw);
          }
          return raw;
        });
        if (v === undefined || v === null) continue;
        params[name] = v;
        parts.push(name + '=' + v);
      }
      for (i = 0; i < 2; i++) {
        var stage = i === 0 ? 'VERTEX_SHADER' : 'FRAGMENT_SHADER';
        for (j = 0; j < GL_PRECISION.length; j++) {
          var pk = GL_PRECISION[j];
          v = safe(function () {
            var f = gl.getShaderPrecisionFormat(gl[stage], gl[pk]);
            return f ? [f.rangeMin, f.rangeMax, f.precision] : null;
          });
          if (!v) continue;
          params[stage + '.' + pk] = v;
          parts.push(stage + '.' + pk + '=' + v);
        }
      }
      var exts = safe(function () {
        var e = gl.getSupportedExtensions() || [];
        return Array.prototype.slice.call(e).sort();
      }) || [];
      if (exts.length) {
        params.EXTENSIONS_COUNT = exts.length;
        parts.push('ext=' + exts.join(','));
      }
      safe(function () { var l = gl.getExtension('WEBGL_lose_context'); if (l) l.loseContext(); });
      var count = 0;
      for (var k in params) { count++; }
      return { hash: 'gp_' + shortHash(parts.join('|')), count: count, params: params };
    } catch (e) { return null; }
  }
  /* Document-level shape. elementCount and keysCount are weak on their own but
   * an extension or an automation harness that injects nodes or document
   * properties moves them, and they cost nothing to read. */
  function documentInfo() {
    try {
      var out = {};
      out.elementCount = safe(function () { return document.getElementsByTagName('*').length; });
      out.keysCount = safe(function () { return Object.keys(document).length; });
      out.referrer = safe(function () { return document.referrer || ''; });
      out.visibilityState = safe(function () { return document.visibilityState || null; });
      out.characterSet = safe(function () { return document.characterSet || document.charset || null; });
      out.compatMode = safe(function () { return document.compatMode || null; });
      out.doctype = safe(function () {
        var d = document.doctype;
        if (!d) return null;
        return d.name + '|' + (d.publicId || '') + '|' + (d.systemId || '');
      });
      var parts = [];
      for (var k in out) { parts.push(k + '=' + out[k]); }
      out.hash = 'dc_' + shortHash(parts.join('|'));
      return out;
    } catch (e) { return null; }
  }

  var RTC_TIMEOUT_MS = 2500;
  var RTC_STUN_URL = 'stun:stun.l.google.com:19302';

  /* A STUN server is contacted so ICE also produces server-reflexive
   * candidates, which carry the public address the packet actually left from.
   * That is the address worth having: it is what leaks when a visitor loads the
   * page through a proxy but lets WebRTC take the direct route, and comparing it
   * against the address the request arrived from is the whole point of the
   * probe. Host candidates alone cannot do that — Chrome replaces the local IP
   * with an .local mDNS name, which is reported as mdns:true rather than
   * dropped silently. publicIps holds srflx/prflx only, so a LAN address is
   * never mistaken for a routable one. Resolves as soon as a reflexive
   * candidate arrives so the extra round trip does not delay form submission,
   * and the timeout still resolves with whatever arrived. */
  function webrtcProbe() {
    return new Promise(function (resolve) {
      var RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection ||
        window.mozRTCPeerConnection;
      if (!RTC) { resolve({ error: 'unsupported' }); return; }
      var out = { candidateTypes: [], foundations: [], ips: [], publicIps: [], mdns: false };
      var pc = null;
      var done = false;

      function finish(err) {
        if (done) return;
        done = true;
        if (err) out.error = err;
        safe(function () { if (pc) pc.close(); });
        resolve(out);
      }

      function push(arr, v) {
        if (!v) return;
        for (var i = 0; i < arr.length; i++) { if (arr[i] === v) return; }
        if (arr.length < 12) arr.push(v);
      }

      function readCandidate(line) {
        // candidate:<foundation> <component> <proto> <pri> <ip> <port> typ <type>
        var m = /candidate:(\S+) \d+ (\S+) \d+ (\S+) (\d+) typ (\S+)/.exec(line);
        if (!m) return false;
        var type = m[5];
        push(out.foundations, m[1]);
        push(out.candidateTypes, type + '/' + m[2].toLowerCase());
        var addr = m[3];
        if (/\.local$/i.test(addr)) { out.mdns = true; return false; }
        push(out.ips, addr);
        if (type === 'srflx' || type === 'prflx') {
          push(out.publicIps, addr);
          return true;
        }
        return false;
      }

      try {
        pc = new RTC({ iceServers: [{ urls: RTC_STUN_URL }] });
        pc.onicecandidate = function (e) {
          if (!e || !e.candidate) { finish(null); return; }
          if (safe(function () { return readCandidate(e.candidate.candidate || ''); })) {
            finish(null);
          }
        };
        safe(function () { pc.createDataChannel('fpg'); });
        pc.createOffer().then(function (offer) {
          var sdp = (offer && offer.sdp) || '';
          out.sdpHash = 'rt_' + shortHash(sdp);
          var lines = sdp.split(/\r\n|\n/);
          for (var i = 0; i < lines.length; i++) {
            if (lines[i].indexOf('candidate:') !== -1) readCandidate(lines[i]);
          }
          return pc.setLocalDescription(offer);
        }).catch(function () { finish('offerFailed'); });
      } catch (e) { finish('threw'); return; }

      setTimeout(function () { finish(null); }, RTC_TIMEOUT_MS);
    });
  }
  /* -------------------------------------------------------------------- *
   * Assembly
   * -------------------------------------------------------------------- */

  function collectDetail() {
    var nav = navigator || {};

    var scr = safe(function () {
      return {
        width: screen.width,
        height: screen.height,
        colorDepth: screen.colorDepth,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        pixelRatio: window.devicePixelRatio || 1,
        orientation: screen.orientation ? screen.orientation.type + ' (' + screen.orientation.angle + ')' : null,
        hdr: screen.colorGamut ? (screen.colorGamut === 'p3' ? 'p3' : screen.colorGamut) : null
      };
    }) || {};
    var wgl = webglDetail();
    MAIN_VENDOR = wgl && wgl.vendor ? wgl.vendor : null;
    MAIN_RENDERER = wgl && wgl.renderer ? wgl.renderer : null;
    var dr = domRectProbe();
    var tm = textMetricsProbe();
    var ft = featureProbe();
    var css = cssProbe();
    var pm = pluginMimeProbe();
    var eng = engineDigest(mathQuirks(), engineErrors());
    var lies = lieProbe();
    var wp = windowPropsProbe();
    var res = resistanceProbe();
    return {
      userAgent: nav.userAgent || '',
      platform: nav.platform || '',
      language: nav.language || '',
      languages: nav.languages ? Array.prototype.slice.call(nav.languages) : [],
      hardwareConcurrency: nav.hardwareConcurrency || null,
      deviceMemory: nav.deviceMemory || null,
      maxTouchPoints: nav.maxTouchPoints != null ? nav.maxTouchPoints : null,
      screen: scr,
      timezoneOffset: new Date().getTimezoneOffset(),
      timezone: (function () { try { return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { return ''; } })(),
      canvas: (function () { try { return !!document.createElement('canvas').getContext('2d'); } catch (e) { return false; } })(),
      canvasHash: canvasHash(),
      webgl: !!wgl,
      webglDetail: wgl,
      cookiesEnabled: nav.cookieEnabled || false,
      doNotTrack: nav.doNotTrack || null,
      pluginsCount: safe(function () { return (nav.plugins && nav.plugins.length) || 0; }) || 0,
      userAgentData: uaDataSync(),
      network: networkInfo(),
      visual: visualPrefs(),
      storage: storageInfo(),
      domRect: dr,
      textMetrics: tm ? { hash: tm.hash, count: tm.stacks, hasBoundingBox: tm.hasBoundingBox } : null,
      jsEngine: eng,
      features: ft ? ft.map : null,
      featuresHash: ft ? ft.hash : null,
      systemColors: css ? css.systemColors : null,
      cssDefaults: css ? css.defaults : null,
      cssHash: css ? css.hash : null,
      pluginMime: pm,
      pluginMimeConsistent: pm ? pm.consistent : null,
      pdfViewerEnabled: safe(function () { return 'pdfViewerEnabled' in nav ? !!nav.pdfViewerEnabled : null; }),
      automation: automationInfo(),
      lies: lies,
      windowProps: wp,
      resistance: res,
      trash: trashProbe(),
      intl: intlProbe(),
      timezoneHistory: timezoneHistory(),
      svg: svgProbe(),
      cssMedia: cssMediaProbe(),
      canvasVariants: canvasVariants(),
      webglParams: webglParams(),
      documentInfo: documentInfo()
    };
  }

  function asyncDetail() {
    return Promise.all([
      function () { return probeFonts(); },
      function () { return Promise.resolve(audioSignal()); },
      function () { return batteryInfo(); },
      function () { return mediaInfo(); },
      function () { return highEntropyUa(); },
      function () { return workerProbe(); },
      function () { return speechVoices(); },
      function () { return webrtcProbe(); }
    ].map(function (fn) { return Promise.resolve().then(fn).catch(function () { return null; }); }))
      .then(function (r) {
        var extra = {};
        var fonts = r[0] || [];
        if (fonts.length) extra.fonts = fonts;
        if (r[1]) extra.audio = r[1];
        if (r[2]) extra.battery = r[2];
        if (r[3]) extra.mediaDevices = r[3];
        if (r[4]) extra.userAgentDataHighEntropy = r[4];
        // No worker answer at all leaves workerMismatch absent, which the admin
        // renderer shows as "no signal" rather than as agreement.
        if (r[5] && r[5].data) {
          extra.workerScope = r[5].scope;
          extra.workerMismatch = workerCompare(r[5].data);
          var re = automationWithWorker(r[5].data.userAgent);
          if (re) extra.automation = re;
        }
        if (r[6]) extra.speech = r[6];
        if (r[7]) extra.webrtc = r[7];
        return extra;
      });
  }

  function wireForms(fp) {
    var inputs = document.querySelectorAll('[data-fp-input]');
    for (var i = 0; i < inputs.length; i++) { inputs[i].value = fp; }

    var detail = JSON.stringify(collectDetail());
    var detailInputs = document.querySelectorAll('[data-fp-detail]');
    for (var i = 0; i < detailInputs.length; i++) { detailInputs[i].value = detail; }

    asyncDetail().then(function (extra) {
      var merged = {};
      try { merged = JSON.parse(detailInputs[0] && detailInputs[0].value ? detailInputs[0].value : detail); } catch (e) { merged = {}; }
      for (var k in extra) { merged[k] = extra[k]; }
      var enriched = JSON.stringify(merged);
      for (var i = 0; i < detailInputs.length; i++) { detailInputs[i].value = enriched; }
    });

    var forms = document.querySelectorAll('[data-fp-form]');
    for (var j = 0; j < forms.length; j++) {
      forms[j].addEventListener('submit', function (ev) {
        var form = ev.currentTarget;
        var fields = form.querySelectorAll('[data-fp-input]');
        for (var m = 0; m < fields.length; m++) {
          if (!fields[m].value) { fields[m].value = fp; }
        }
        var dfields = form.querySelectorAll('[data-fp-detail]');
        for (var m = 0; m < dfields.length; m++) {
          if (!dfields[m].value) { dfields[m].value = detail; }
        }
      });
    }
  }

  /* -------------------------------------------------------------------- *
   *  Ad-block detection
   * -------------------------------------------------------------------- *
   *  Modelled on Simple-Adblock-Detector (github.com/OddDevelopment): fire a
   *  spread of probes at hosts and element ids that filter lists target, and
   *  flag if ANY ONE of them trips. No per-signal controls, no vote threshold,
   *  no "unknown" votes — a refused bait is a blocker, full stop. Abstaining
   *  when a signal was merely inconclusive is what made real blockers slip
   *  through: uBlock and AdGuard let our same-origin /static/ads.js load while
   *  killing third-party ad hosts, so a signal that abstained on same-origin
   *  never voted at all.
   *
   *  One global control remains, and it is deliberately not blockable: a plain
   *  same-origin asset (/static/style.css, already loaded for the page). If
   *  that cannot be fetched the browser cannot reach our own server, which is
   *  offline/dead-network, not an ad blocker — so detection reports clean and
   *  the page opens. No filter list blocks a site's own stylesheet, so this
   *  cannot be used to suppress detection.
   *
   *  Timeouts do NOT count as blocked. A hung request is a slow network, and
   *  treating hangs as evidence flagged people on bad wifi.
   * -------------------------------------------------------------------- */

  var PROBE_TIMEOUT_MS = 2500;  // per-request budget
  var DETECT_TIMEOUT_MS = 5000; // whole-detection budget, then fail open
  var DEBUG = /[?&](guarddebug|adblockdebug)=1/.test(window.location.search);

  function debug(label, value) {
    if (!DEBUG) return;
    try { console.info('[fp-guard] ' + label, value); } catch (e) {}
  }

  // true  -> the request reached the network and something answered
  // false -> the request was cancelled/refused (blocker, CSP, DNS, offline)
  // null  -> timed out, verdict unknown
  function probe(url) {
    var busted = url + (url.indexOf('?') === -1 ? '?' : '&') + '_=' + Date.now();
    var timer = null;
    var request;
    try {
      request = fetch(busted, {
        method: 'GET',
        mode: 'no-cors',
        cache: 'no-store',
        credentials: 'omit',
        referrerPolicy: 'no-referrer'
      }).then(function () { return true; }, function () { return false; });
    } catch (e) {
      request = Promise.resolve(false);
    }
    var timeout = new Promise(function (resolve) {
      timer = setTimeout(function () { resolve(null); }, PROBE_TIMEOUT_MS);
    });
    return Promise.race([request, timeout]).then(function (r) {
      if (timer) clearTimeout(timer);
      return r;
    });
  }

  /* Bait 1: same-origin (/static/ads.js). ads.js sets __adsLoaded when it runs;
   * if it did not, either the script tag or the path is filtered. */

  var SAME_ORIGIN_BAIT = '/static/ads.js';
  var SAME_ORIGIN_CONTROL = '/static/style.css';

  function sameOriginBait() {
    if (window.__adsLoaded === true) return Promise.resolve(false);
    return probe(SAME_ORIGIN_BAIT).then(function (r) { return r === false; });
  }

  /* Bait 2: DOM cosmetic. Blockers hide elements whose id/class match filter
   * lists. Any one of them disappearing counts. */

  var BAIT_IDS = ['AdHeader', 'AdContainer', 'AD_Top', 'homead', 'ad-lead'];
  var BAIT_CLASSES = 'adsbox adsbygoogle ad-slot banner_ad ad-placement pub_300x250';

  function isHidden(el) {
    if (!el) return true;
    var cs = window.getComputedStyle(el);
    if (!cs) return false;
    return el.offsetHeight === 0 || el.clientHeight === 0 ||
      cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0';
  }

  function buildBait() {
    var host = document.createElement('div');
    host.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:300px;height:600px;';
    var cell = 'width:300px;height:40px;line-height:40px;';
    // Built node-by-node rather than via innerHTML: a style="" attribute in
    // parsed markup is refused by style-src, but the CSSOM .style is not.
    function makeCell() {
      var el = document.createElement('div');
      el.style.cssText = cell;
      el.textContent = ' ';
      return el;
    }
    var control = makeCell();
    control.setAttribute('data-guard-control', '');
    host.appendChild(control);
    for (var i = 0; i < BAIT_IDS.length; i++) {
      var bait = makeCell();
      bait.id = BAIT_IDS[i];
      bait.className = BAIT_CLASSES;
      host.appendChild(bait);
    }
    document.body.appendChild(host);
    return host;
  }

  function readBait(host) {
    // The neutral control must be laid out, otherwise we are measuring a
    // detached/zero-size container and every bait would read as hidden.
    if (isHidden(host.querySelector('[data-guard-control]'))) return false;
    var gone = 0;
    for (var i = 0; i < BAIT_IDS.length; i++) {
      if (isHidden(document.getElementById(BAIT_IDS[i]))) gone++;
    }
    debug('dom baits hidden', gone + '/' + BAIT_IDS.length);
    return gone >= 1;
  }

  function domBait() {
    if (!document.body) return Promise.resolve(false);
    var host;
    try { host = buildBait(); } catch (e) { return Promise.resolve(false); }
    return new Promise(function (resolve) {
      // Cosmetic filtering is applied asynchronously; give blockers a beat.
      setTimeout(function () {
        var verdict = false;
        try { verdict = readBait(host); } catch (e) { verdict = false; }
        try { if (host.parentNode) host.parentNode.removeChild(host); } catch (e) {}
        resolve(verdict);
      }, 350);
    });
  }

  /* Bait 3: third-party ad hosts (EasyList targets). Every host here must also
   * appear in the connect-src allowlist in frontend.py, or our own CSP cancels
   * the request and flags every visitor. */

  var NET_BAITS = [
    'https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js',
    'https://widgets.outbrain.com/outbrain.js',
    'https://secure.quantserve.com/quant.js',
    'https://static.doubleclick.net/instream/ad_status.js',
    'https://www.googletagservices.com/tag/js/gpt.js'
  ];

  function netBaits() {
    var jobs = [];
    for (var i = 0; i < NET_BAITS.length; i++) jobs.push(probe(NET_BAITS[i]));
    return Promise.all(jobs).then(function (results) {
      var refused = 0;
      for (var k = 0; k < results.length; k++) {
        if (results[k] === false) refused++;
      }
      debug('net baits refused', refused + '/' + results.length);
      return refused >= 1;
    });
  }

  function safeAsync(fn) {
    try { return Promise.resolve(fn()).catch(function () { return false; }); }
    catch (e) { return Promise.resolve(false); }
  }

  function detectAdblock() {
    // Global sanity control: can we reach our own origin at all? If not, the
    // network is broken (or we are offline) and nothing below is meaningful.
    var checks = safeAsync(function () { return probe(SAME_ORIGIN_CONTROL); })
      .then(function (reachable) {
        if (reachable !== true) {
          debug('origin unreachable, failing open', reachable);
          try {
            window.__adblockSignals = { reachable: false, verdict: false };
          } catch (e) {}
          return false;
        }
        return Promise.all([
          safeAsync(sameOriginBait),
          safeAsync(domBait),
          // Third-party host probes (netBaits) are always on since 2026-08-11:
          // the same-origin bait only trips on path-filter rules and the DOM
          // bait only trips on cosmetic filters that modern lists have largely
          // dropped, so neither reliably catches standard-mode blockers (Brave
          // Shields, uBlock with defaults). Net-bait refusals are the one
          // signal every mainstream blocker guarantees. The price: while a
          // blocker is active the browser logs each refused probe itself
          // (net::ERR_BLOCKED_BY_CLIENT) — no JS can suppress that.
          safeAsync(netBaits)
        ]).then(function (r) {
          var signals = {
            reachable: true, sameOrigin: r[0], dom: r[1], network: r[2]
          };
          // Any single tripped bait is enough.
          signals.verdict = (r[0] === true || r[1] === true || r[2] === true);
          try { window.__adblockSignals = signals; } catch (e) {}
          debug('signals', signals);
          return signals.verdict;
        });
      }, function () { return false; });

    // Never leave the page hanging on a slow probe: unknown means allowed.
    var watchdog = new Promise(function (resolve) {
      setTimeout(function () { resolve(false); }, DETECT_TIMEOUT_MS);
    });
    return Promise.race([checks, watchdog]);
  }

  window.detectAdblock = detectAdblock;

  /* -------------------------------------------------------------------- *
   *  Reveal / redirect
   * -------------------------------------------------------------------- *
   *  Guarded pages are hidden by default (CSS: body[data-guard]{visibility:
   *  hidden}). They are revealed by JS ONLY after the ad-block check passes.
   *  - Scripts blocked entirely  -> page never reveals (blank); <noscript>
   *    shows the "JavaScript required" message when JS is fully disabled.
   *  - Ad blocker detected        -> redirect to /blocked, which polls and
   *    forwards back here once the blocker is switched off.
   */

  var BLOCKED_URL = '/blocked';

  function hideScriptGate() {
    // JS is running, so the "enable scripts" gate is no longer true. Remove it
    // immediately (before the async ad-block check) so users don't stare at a
    // stale "Scripts Required" message while probes are in flight.
    var gate = document.getElementById('script-gate');
    if (gate && gate.parentNode) { gate.parentNode.removeChild(gate); }
  }

  function reveal() {
    hideScriptGate();
  }

  function showBanner() {
    // Deliberately empty. This used to build a red "Ad blocker detected — it may
    // break parts of this site" bar and insert it above the console's content,
    // which is what an operator saw on admin_embed.html once its bare <body> made
    // GUARD fall back to "warn". The console carries no advertising, so the banner
    // asked an operator to disable a blocker for ads that were never in the page.
    // The main site handles a real verdict server-side and renders blocked.html;
    // there is no equivalent here to route to, so the console shows nothing.
  }

  function redirectToBlocked() {
    var back = window.location.pathname + window.location.search;
    try { window.sessionStorage.setItem('fp_guard_return', back); } catch (e) {}
    window.location.replace(BLOCKED_URL + '?from=' + encodeURIComponent(back));
  }

  /* -------------------------------------------------------------------- *
   *  Deferred ad loading
   * -------------------------------------------------------------------- *
   *  Templates no longer emit ad <script src> tags directly. Every ad unit
   *  is a <script type="text/plain" data-ad-src="…"> placeholder (a plain
   *  script tag would be fetched by the browser and, when an ad blocker is
   *  on, every refused fetch is logged by the browser itself as
   *  net::ERR_BLOCKED_BY_CLIENT — unavoidable and un-silenceable).
   *  placeholders are only turned into real script elements after the
   *  ad-block check passes; a blocker therefore never even sees a refused
   *  request and the console stays clean.
   *
   *  Units that configure via the global atOptions object carry their config
   *  in data-ad-cfg; window.atOptions is set immediately before each unit's
   *  script runs (async=false preserves insertion order, so each invoke.js
   *  sees its own config — the ordering the old inline-atOptions markup gave
   *  us for free).
   *
   *  Two classes of unit, decided by markup:
   *   - display units sit inside <div class="ad-container"> and load as soon
   *     as the ad-block check passes;
   *   - click-fired units (popunder, social bar) are bare placeholders with
   *     no .ad-container wrapper. The popunder network's script opens a new
   *     tab on every qualifying click anywhere on the page, so these are
   *     never loaded on phones/tablets (display-only there), and on desktop
   *     they load only after the first click on an interactive element
   *     (button, [data-act], the settings modal). A window-capture listener
   *     then stops non-interactive events from ever reaching the network's
   *     own document listeners, so the popunder cannot fire on an arbitrary
   *     page click — only on a button-like click.
   */

  function isMobileDevice() {
    try {
      if (/(android|iphone|ipad|ipod|mobile|iemobile|opera mini)/i.test(navigator.userAgent)) return true;
      if (window.matchMedia && window.matchMedia('(pointer: coarse)').matches) return true;
    } catch (e) {}
    return false;
  }

  // What counts as an interactive target for the click-fired units. [data-act]
  // and the settings modal are the app's own delegated click handlers — they
  // must keep receiving events even though they are not <button>s.
  var INTERACTIVE_SELECTOR = 'button, [role="button"], input[type="button"], input[type="submit"], input[type="reset"], .btn, [data-act], [id$="-modal"]';

  function isInteractive(e) {
    var t = e && e.target;
    return !!(t && t.closest && t.closest(INTERACTIVE_SELECTOR));
  }

  // Some popunder placements run in "layer" mode: a 500 ms poll paints an
  // invisible full-viewport <a target="_blank"> over the page (z-index at the
  // 2147483647 ceiling), so EVERY click opens the ad — and swallows the click
  // the visitor actually aimed at the page. The popunder's own handler removes
  // it on qualifying clicks, but the click gate below keeps that handler from
  // running on non-interactive events, so without this the layer would stay up
  // and hijack the whole page. Remove anything near the z-index ceiling that
  // is not an iframe (the social bar's frame legitimately sits that high);
  // full-viewport + near-invisible fixed elements are caught as a fallback.
  // Our own UI never goes near that ceiling (modals cap at z-index 200).
  function watchAdOverlays() {
    function kill(elm) {
      if (!elm || elm.nodeType !== 1 || !elm.style || elm.tagName === 'IFRAME') return;
      var st = elm.style;
      var z = parseInt(st.zIndex || '', 10) || 0;
      var full = st.position === 'fixed' &&
                 elm.offsetWidth >= (window.innerWidth || 0) - 2 &&
                 elm.offsetHeight >= (window.innerHeight || 0) - 2;
      var faint = parseFloat(st.opacity || '1') < 0.1;
      if (!(z >= 2147480000 || (full && faint))) return;
      try { if (elm.parentNode) elm.parentNode.removeChild(elm); } catch (err) {}
    }
    function scan() {
      var all = document.getElementsByTagName('*');
      for (var i = all.length - 1; i >= 0; i--) kill(all[i]);
    }
    try {
      if (window.MutationObserver && document.body) {
        new MutationObserver(scan).observe(document.body, {childList: true, subtree: true});
      }
    } catch (e) {}
    if (document.body) scan();
    setInterval(scan, 2000);
  }

  function injectAds() {
    var placeholders = document.querySelectorAll('script[data-ad-src]');
    if (!placeholders.length) return;
    var display = [];
    var clickFired = [];
    for (var j = 0; j < placeholders.length; j++) {
      var ph = placeholders[j];
      var parent = ph.parentNode;
      if (parent && parent.classList && parent.classList.contains('ad-container')) {
        display.push(ph);
      } else {
        clickFired.push(ph);
      }
    }
    function loadUnits(units) {
      var i = 0;
      function next() {
        if (i >= units.length) return;
        var ph = units[i++];
        var src = ph.getAttribute('data-ad-src');
        if (!src) { next(); return; }
        var cfg = ph.getAttribute('data-ad-cfg');
        if (cfg) {
          try { window.atOptions = JSON.parse(cfg); } catch (e) {}
        }
        var s = document.createElement('script');
        s.src = src;
        s.async = false;
        s.onload = next;
        s.onerror = next;
        // Swap in place. Appending to document.body instead would run every unit
        // at the end of the page, leaving the styled .ad-container boxes empty
        // (and stuck on the ":empty" Advertisement label) while the iframes piled
        // up under the footer. These networks position relative to the script's
        // own parent, so the script has to sit where the slot is.
        if (ph.parentNode) {
          ph.parentNode.replaceChild(s, ph);
        } else {
          document.body.appendChild(s);
        }
      }
      next();
    }
    loadUnits(display);
    if (!clickFired.length) return;
    watchAdOverlays();
    // Phones/tablets are display-only: no popunder, no social bar, so no click
    // on the page can ever open an ad it was not meant to open.
    if (isMobileDevice()) return;
    // Desktop: gate + trigger for the click-fired units. The gate is a
    // window-capture listener, which always runs before the network script's
    // document listeners no matter who registered first; stopPropagation keeps
    // non-interactive events away from them (stopPropagation does not cancel
    // default actions, so links still navigate and buttons still submit — only
    // the ad script stays silent). The units load on the first interactive
    // event; a listener installed mid-dispatch is not called for the event in
    // flight, so that very first click behaves normally and the popunder only
    // ever fires on a later button-like click.
    var armed = false;
    function gate(e) {
      if (!isInteractive(e)) {
        if (armed) e.stopPropagation();
        return;
      }
      if (armed) return;
      armed = true;
      setTimeout(function () { loadUnits(clickFired); }, 0);
    }
    window.addEventListener('mousedown', gate, true);
    window.addEventListener('click', gate, true);
    window.addEventListener('touchstart', gate, true);
  }

  /* -------------------------------------------------------------------- *
   *  Boot
   * -------------------------------------------------------------------- */

  // The blocked page itself: stay visible, poll, and forward back once the
  // blocker is off.
  function bootBlockedPage() {
    reveal();
    // Re-arm after each check instead of setInterval: a probe round can take a
    // couple of seconds and overlapping rounds would pile up requests.
    var stopped = false;
    function returnHome() {
      var back;
      try { back = window.sessionStorage.getItem('fp_guard_return'); } catch (e) {}
      if (!back) {
        var m = /[?&]from=([^&]+)/.exec(window.location.search);
        back = m ? decodeURIComponent(m[1]) : '/';
      }
      window.location.replace(back || '/');
    }
    function tick() {
      if (stopped) return;
      detectAdblock().then(function (blocked) {
        if (!blocked) { stopped = true; returnHome(); return; }
        // 5 s instead of 2 s: each refused bait probe is logged by the browser
        // itself (net::ERR_BLOCKED_BY_CLIENT), so a faster poll just floods the
        // console while the blocker stays on.
        setTimeout(tick, 5000);
      }, function () { stopped = true; returnHome(); });
    }
    tick();
  }

  function boot() {
    // Scripts are clearly running now, so drop the "enable scripts" gate right
    // away. The body stays hidden (CSS) until the ad-block check passes.
    hideScriptGate();

    // Fingerprint is independent of the ad-block gate.
    computeFingerprint().then(function (fp) {
      wireForms(fp);
      try { window.__deviceFingerprint = fp; } catch (e) {}
    });

    if (GUARD === 'blocked') { bootBlockedPage(); return; }

    // No gate: page is not hidden by CSS, nothing to do beyond fingerprint.
    if (GUARD === 'off') { reveal(); injectAds(); return; }

    detectAdblock().then(function (blocked) {
      if (!blocked) { reveal(); injectAds(); return; }
      if (GUARD === 'gate') {
        // Keep the page hidden and route to the blocked screen.
        redirectToBlocked();
      } else {
        // warn: reveal the page and stand down. showBanner() is a no-op in this
        // copy, so nothing is painted. Ads stay unloaded either way: loading them
        // would log refused-request errors the blocker causes.
        reveal();
        showBanner();
      }
    }).catch(function () {
      // If detection itself errors, fail open so we don't trap real users.
      reveal();
      injectAds();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();

// A Monetag service worker was registered on this origin by an earlier build
// (this file used to call register('/sw.js')). It intercepted requests and
// broke page loads, and the tag script itself never registers it — the network
// only needs /sw.js to be reachable, not active. Unregister any stale one here
// so a visitor who already has it installed is healed on the next load.
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.getRegistrations().then(function (rs) {
    for (var i = 0; i < rs.length; i++) rs[i].unregister();
  }).catch(function () {});
}
