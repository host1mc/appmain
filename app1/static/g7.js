(function () {
  'use strict';

  var GUARD = (document.body && document.body.dataset.guard) || 'warn';

  var GUARD_BUILD = (function () {
    try {
      var s = document.currentScript;
      var m = /[?&]v=([^&]+)/.exec((s && s.src) || '');
      return m ? m[1] : 'x';
    } catch (e) { return 'x'; }
  })();

  function $(sel, root) {
    try { return (root || document).querySelector(sel); } catch (e) { return null; }
  }

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
      } catch (e) {  }
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

  var MAIN_VENDOR = null;
  var MAIN_RENDERER = null;

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

      if ((pc > 0) !== (mc > 0)) mismatches++;
      return { pluginsCount: pc, mimeTypesCount: mc, consistent: mismatches === 0, mismatches: mismatches };
    } catch (e) { return null; }
  }

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

    var chromeVer = safe(function () { var m = /Chrom(?:e|ium)\/(\d+)/.exec(ua); return m ? parseInt(m[1], 10) : 0; }) || 0;
    var ffVer = safe(function () { var m = /Firefox\/(\d+)/.exec(ua); return m ? parseInt(m[1], 10) : 0; }) || 0;
    if (safe(function () { return 'webdriver' in nav; }) === false && (chromeVer >= 63 || ffVer >= 56)) soft.push('webdriverMissing');
    if (MAIN_RENDERER && /SwiftShader|llvmpipe|Software Rasterizer|Mesa OffScreen/i.test(String(MAIN_RENDERER))) soft.push('softwareRenderer');
    if (safe(function () { return 'pdfViewerEnabled' in nav ? nav.pdfViewerEnabled : null; }) === false && isChromiumBuild()) soft.push('pdfViewerDisabled');
    if (safe(function () { return screen.height === screen.availHeight; }) === true) soft.push('noTaskbar');
    AUTOMATION_CACHE = { hard: hard, soft: soft };
    return { verdict: hard.length ? 'headless' : (soft.length ? 'suspect' : 'clean'), hits: hard.concat(soft) };
  }

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

      if (data.webglVendor && MAIN_VENDOR && String(data.webglVendor) !== String(MAIN_VENDOR)) mismatch.push('webglVendor');
      if (data.webglRenderer && MAIN_RENDERER && String(data.webglRenderer) !== String(MAIN_RENDERER)) mismatch.push('webglRenderer');
    } catch (e) {  }
    return mismatch;
  }

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

  function nativeSrc(fn) {

    return String(Function.prototype.toString.call(fn)).replace(/\s+/g, '');
  }

  function fnLie(fn, expectName) {
    try {
      if (typeof fn !== 'function') return 'notFunction';
      if (!/\[nativecode\]\}$/.test(nativeSrc(fn))) return 'notNative';

      if (expectName && fn.name && fn.name !== expectName && fn.name !== 'get ' + expectName) return 'renamed';

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

    try {
      d.get.call({});
      return 'noReceiverCheck';
    } catch (e4) {  }
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

      if (safe(function () { return Object.getPrototypeOf(navigator) !== Navigator.prototype; }) === true) hits.push('navigator.prototypeChain');
      if (safe(function () { return Object.prototype.toString.call(navigator); }) !== '[object Navigator]') hits.push('navigator.toStringTag');
      if (safe(function () { return Object.prototype.toString.call(screen); }) !== '[object Screen]') hits.push('screen.toStringTag');
      var ownNav = safe(function () { return Object.getOwnPropertyNames(navigator); });
      if (ownNav && ownNav.length) hits.push('navigator.ownProps:' + ownNav.slice(0, 4).join(','));
      if (hits.length > 40) hits = hits.slice(0, 40);
      return { count: hits.length, hits: hits, hash: 'li_' + shortHash(hits.join('|')) };
    } catch (e) { return null; }
  }

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

  var FPJS_URL = '/static/v2.js';
  var fpjsLibPromise = null;
  var fpjsAgentPromise = null;

  function fpjsLib() {
    if (fpjsLibPromise) return fpjsLibPromise;
    fpjsLibPromise = new Promise(function (resolve) {
      if (window.FingerprintJS) { resolve(window.FingerprintJS); return; }
      var s = document.createElement('script');
      s.src = FPJS_URL + '?_=' + Date.now();
      s.async = true;
      s.onload = function () { resolve(window.FingerprintJS || null); };
      s.onerror = function () { resolve(null); };
      document.head.appendChild(s);
    });

    fpjsLibPromise = Promise.race([
      fpjsLibPromise,
      new Promise(function (resolve) { setTimeout(function () { resolve(null); }, 5000); })
    ]);
    return fpjsLibPromise;
  }

  function fingerprintjsProbe() {
    return fpjsLib().then(function (FingerprintJS) {
      if (!FingerprintJS) return { version: 'v3.4.1', error: 'unavailable' };
      if (!fpjsAgentPromise) fpjsAgentPromise = FingerprintJS.load({ monitoring: false });
      return fpjsAgentPromise.then(function (agent) {
        return agent.get().then(function (result) {
          var out = { version: 'v3.4.1' };
          out.visitorId = result.visitorId || '';
          out.confidence = (typeof result.confidence === 'number') ? result.confidence : null;
          var c = result.components || {};

          var pick = ['userAgent', 'platform', 'screenResolution', 'colorDepth',
            'timezone', 'languages', 'hardwareConcurrency', 'deviceMemory',
            'cpuClass', 'vendor', 'cookiesEnabled', 'plugins', 'fonts',
            'fontPreferences', 'canvas', 'webgl', 'audio', 'touchSupport',
            'localStorage', 'sessionStorage', 'indexedDB', 'openDatabase',
            'adBlock'];
          var comps = {};
          for (var i = 0; i < pick.length; i++) {
            var k = pick[i];
            if (c[k] && c[k].value !== undefined) comps[k] = c[k].value;
          }
          if (c.error && c.error.value) out.error = c.error.value;
          out.componentCount = Object.keys(comps).length;
          out.components = comps;
          return out;
        }, function () { return { version: 'v3.4.1', error: 'get failed' }; });
      }, function () { return { version: 'v3.4.1', error: 'agent failed' }; });
    });
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
      function () { return webrtcProbe(); },
      function () { return fingerprintjsProbe(); }
    ].map(function (fn) { return Promise.resolve().then(fn).catch(function () { return null; }); }))
      .then(function (r) {
        var extra = {};
        var fonts = r[0] || [];
        if (fonts.length) extra.fonts = fonts;
        if (r[1]) extra.audio = r[1];
        if (r[2]) extra.battery = r[2];
        if (r[3]) extra.mediaDevices = r[3];
        if (r[4]) extra.userAgentDataHighEntropy = r[4];

        if (r[5] && r[5].data) {
          extra.workerScope = r[5].scope;
          extra.workerMismatch = workerCompare(r[5].data);
          var re = automationWithWorker(r[5].data.userAgent);
          if (re) extra.automation = re;
        }
        if (r[6]) extra.speech = r[6];
        if (r[7]) extra.webrtc = r[7];
        if (r[8]) extra.fingerprintjs = r[8];
        return extra;
      });
  }

  function wireForms(fp) {
    var inputs = document.querySelectorAll('[data-fp-input]');
    for (var i = 0; i < inputs.length; i++) { inputs[i].value = fp; }

    var detailInputs = document.querySelectorAll('[data-fp-detail]');

    var detail = detailInputs.length ? JSON.stringify(collectDetail()) : '';
    for (var i = 0; i < detailInputs.length; i++) { detailInputs[i].value = detail; }

    var enriched = (detailInputs.length ? asyncDetail() : Promise.resolve({})).then(function (extra) {
      var merged = {};
      try { merged = JSON.parse(detailInputs[0] && detailInputs[0].value ? detailInputs[0].value : detail); } catch (e) { merged = {}; }
      for (var k in extra) { merged[k] = extra[k]; }
      var out = JSON.stringify(merged);
      for (var i = 0; i < detailInputs.length; i++) { detailInputs[i].value = out; }
      return out;
    }, function () { return detail; });

    var forms = document.querySelectorAll('[data-fp-form]');
    for (var j = 0; j < forms.length; j++) {
      forms[j].addEventListener('submit', function (ev) {
        var form = ev.currentTarget;
        if (form.dataset.fpWaiting === '1') { ev.preventDefault(); return; }
        var fields = form.querySelectorAll('[data-fp-input]');
        for (var m = 0; m < fields.length; m++) {
          if (!fields[m].value) { fields[m].value = fp; }
        }
        var dfields = form.querySelectorAll('[data-fp-detail]');
        for (var m = 0; m < dfields.length; m++) {
          if (!dfields[m].value) { dfields[m].value = detail; }
        }

        ev.preventDefault();
        form.dataset.fpWaiting = '1';
        Promise.race([
          enriched,
          new Promise(function (resolve) { setTimeout(function () { resolve(''); }, 2500); })
        ]).then(function () {
          form.dataset.fpWaiting = '0';
          try { form.submit(); } catch (e) {}
        }, function () {
          form.dataset.fpWaiting = '0';
          try { form.submit(); } catch (e) {}
        });
      });
    }
  }

  var PROBE_TIMEOUT_MS = 2500;
  var DETECT_TIMEOUT_MS = 5000;
  var DEBUG = /[?&](guarddebug|adblockdebug)=1/.test(window.location.search);

  function debug(label, value) {
    if (!DEBUG) return;
    try { console.info('[fp-guard] ' + label, value); } catch (e) {}
  }

  function probe(url, method) {
    var busted = url + (url.indexOf('?') === -1 ? '?' : '&') + '_=' + Date.now();
    var timer = null;
    var request;
    try {
      request = fetch(busted, {
        method: method || 'GET',
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

  function probeNet(url) {
    return probe(url);
  }

  var SAME_ORIGIN_BAIT = '/static/ads.js';

  function sameOriginBait() {
    if (window.__adsLoaded === true) return Promise.resolve(false);
    return probeNet(SAME_ORIGIN_BAIT).then(function (r) { return r === false; });
  }

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

    if (isHidden(host.querySelector('[data-guard-control]'))) return false;
    var gone = 0;
    for (var i = 0; i < BAIT_IDS.length; i++) {

      if (isHidden(host.querySelector('#' + BAIT_IDS[i]))) gone++;
    }
    debug('dom baits hidden', gone + '/' + BAIT_IDS.length);
    return gone >= 1;
  }

  function domBait() {
    if (!document.body) return Promise.resolve(false);
    var host;
    try { host = buildBait(); } catch (e) { return Promise.resolve(false); }
    return new Promise(function (resolve) {

      setTimeout(function () {
        var verdict = false;
        try { verdict = readBait(host); } catch (e) { verdict = false; }
        try { if (host.parentNode) host.parentNode.removeChild(host); } catch (e) {}
        resolve(verdict);
      }, 350);
    });
  }

  function safeAsync(fn) {
    try { return Promise.resolve(fn()).catch(function () { return false; }); }
    catch (e) { return Promise.resolve(false); }
  }

  function detectAdblock() {
    return Promise.all([
      safeAsync(sameOriginBait),
      safeAsync(domBait)
    ]).then(function (cheap) {
      var verdict = cheap[0] === true || cheap[1] === true;
      try { window.__adblockSignals = { sameOrigin: cheap[0], dom: cheap[1], verdict: verdict }; } catch (e) {}
      debug('signals', window.__adblockSignals);
      return verdict;
    }, function () { return false; });
  }

  window.detectAdblock = detectAdblock;

  function watchDevTools() {
    if (!document.querySelector('meta[name="csrf-token"]')) return;
    var openedAt = 0, sent = false;
    function isOpen() {
      var threshold = 160;
      return (window.outerWidth - window.innerWidth > threshold) ||
        (window.outerHeight - window.innerHeight > threshold);
    }

    var poll = setInterval(function () {
      if (sent) return;
      if (!isOpen()) { openedAt = 0; return; }
      if (!openedAt) openedAt = Date.now();
      if (Date.now() - openedAt < 120000) return;
      var meta = document.querySelector('meta[name="csrf-token"]');
      var token = meta ? meta.content : '';
      if (!token) return;
      sent = true;
      fetch('/api/user/devtools-flag', {
        method: 'POST', credentials: 'same-origin',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': token},
        body: JSON.stringify({open_seconds: Math.floor((Date.now() - openedAt) / 1000)})
      }).then(function () { clearInterval(poll); }, function () { sent = false; });
    }, 1000);
  }

  var BLOCKED_URL = '/blocked';

  var GATE_REVEAL_MS = DETECT_TIMEOUT_MS + 1500;

  var gateTimer = 0;

  function hideScriptGate() {

    var gate = document.getElementById('script-gate');
    if (gate && gate.parentNode) { gate.parentNode.removeChild(gate); }
  }

  function holdScriptGate() {
    var gate = document.getElementById('script-gate');
    if (gate) {
      try {
        gate.setAttribute('role', 'status');
        gate.setAttribute('aria-live', 'polite');
        var head = gate.querySelector('h1');
        var body = gate.querySelector('p');
        if (head) head.textContent = 'Checking…';
        if (body) body.textContent = 'Verifying that no content blocker is active. This only takes a moment.';
      } catch (e) {}
    }
    gateTimer = setTimeout(reveal, GATE_REVEAL_MS);
  }

  function reveal() {
    if (gateTimer) { clearTimeout(gateTimer); gateTimer = 0; }
    hideScriptGate();
  }

  var stoodDown = false;

  function standDown() {
    if (stoodDown) return;
    stoodDown = true;
    reveal();
    injectAds();
  }

  var BANNER_DISMISSED_KEY = 'fp_guard_banner_dismissed';

  function showBanner(force) {
    redirectToBlocked();
    return;
  }

  var BOUNCE_KEY = 'fp_guard_bounces';
  var BOUNCE_LIMIT = 2;
  var BOUNCE_WINDOW_MS = 60000;

  var FAILED_UNIT_KEY = 'fp_guard_failed_unit';

  function bounceCount() {
    try {
      var raw = window.sessionStorage.getItem(BOUNCE_KEY);
      if (!raw) return 0;
      var parts = String(raw).split(':');
      var n = parseInt(parts[0], 10) || 0;
      var at = parseInt(parts[1], 10) || 0;

      if (!at || Date.now() - at > BOUNCE_WINDOW_MS) return 0;
      return n;
    } catch (e) { return 0; }
  }

  function noteBounce() {
    try {
      var n = bounceCount() + 1;
      window.sessionStorage.setItem(BOUNCE_KEY, n + ':' + Date.now());
      return n;
    } catch (e) { return 0; }
  }

  var LOOP_GAVEUP_KEY = 'fp_guard_gaveup';

  function loopGaveUp() {
    try { return window.sessionStorage.getItem(LOOP_GAVEUP_KEY) === GUARD_BUILD; }
    catch (e) { return false; }
  }

  var RELEASED_KEY = 'fp_guard_released';
  var RELEASE_TTL_MS = BOUNCE_WINDOW_MS;

  function noteRelease() {
    try { window.sessionStorage.setItem(RELEASED_KEY, String(Date.now())); } catch (e) {}
  }

  function cameFromRelease() {
    var at = 0;
    try {
      at = parseInt(window.sessionStorage.getItem(RELEASED_KEY) || '', 10) || 0;
      window.sessionStorage.removeItem(RELEASED_KEY);
    } catch (e) { return false; }
    return !!at && (Date.now() - at) <= RELEASE_TTL_MS;
  }

  function redirectToBlocked() {

    var here = window.location.pathname;
    if (here === BLOCKED_URL || here === BLOCKED_URL + '/') { reveal(); return; }

    if (loopGaveUp()) {
      try { window.__adblockBounceLimit = true; } catch (e) {}
      standDown();
      return;
    }
    if (cameFromRelease() && noteBounce() > BOUNCE_LIMIT) {
      debug('bounce limit reached, staying blocked', BOUNCE_LIMIT);
      try { window.sessionStorage.setItem(LOOP_GAVEUP_KEY, GUARD_BUILD); } catch (e) {}
      try { window.__adblockBounceLimit = true; } catch (e) {}
      standDown();
      return;
    }
    var back = window.location.pathname + window.location.search;
    var saved = false;
    try { window.sessionStorage.setItem('fp_guard_return', back); saved = true; } catch (e) {}

    if (saved) { window.location.replace(BLOCKED_URL + '?from=1'); return; }
    window.location.replace(BLOCKED_URL + '?from=' + encodeURIComponent(back));
  }

  function isMobileDevice() {
    try {
      if (/(android|iphone|ipad|ipod|mobile|iemobile|opera mini)/i.test(navigator.userAgent)) return true;
      if (window.matchMedia && window.matchMedia('(pointer: coarse)').matches) return true;
    } catch (e) {}
    return false;
  }

  var INTERACTIVE_SELECTOR = 'button, [role="button"], input[type="button"], input[type="submit"], input[type="reset"], .btn, [data-act], [id$="-modal"], a[href]';

  function isInteractive(e) {
    var t = e && e.target;
    return !!(t && t.closest && t.closest(INTERACTIVE_SELECTOR));
  }

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

    var queued = false;
    function scanSoon() {
      if (queued) return;
      queued = true;
      setTimeout(function () { queued = false; scan(); }, 50);
    }
    try {
      if (window.MutationObserver && document.body) {
        new MutationObserver(scanSoon).observe(document.body, {childList: true, subtree: true});
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
      if (ph.getAttribute('data-ad-kind') === 'popunder' && window.matchMedia && window.matchMedia('(max-width: 768px)').matches) continue;
      var parent = ph.parentNode;
      if (parent && parent.classList && parent.classList.contains('ad-container')) {
        display.push(ph);
      } else {
        clickFired.push(ph);
      }
    }
    var adFailureHandled = false;
    function handleAdFailure(src) {
      if (adFailureHandled) return;
      adFailureHandled = true;
      try { window.__adblockSignals = {reachable:true, actualAdScript:true, verdict:true}; } catch (e) {}
      try { if (src) window.sessionStorage.setItem(FAILED_UNIT_KEY, src); } catch (e) {}
      if (GUARD === 'gate') redirectToBlocked();
      else if (GUARD === 'warn') redirectToBlocked();
    }
    function loadUnits(units, detectFailure) {
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
        s.onerror = function () {
          if (detectFailure) handleAdFailure(src);
          next();
        };

        if (ph.parentNode) {
          ph.parentNode.replaceChild(s, ph);
        } else {
          document.body.appendChild(s);
        }
      }
      next();
    }
    loadUnits(display, true);
    if (!clickFired.length) return;
    watchAdOverlays();

    if (isMobileDevice()) return;

    var armed = false;
    function gate(e) {
      if (!isInteractive(e)) {
        if (armed) e.stopPropagation();
        return;
      }
      if (armed) return;
      armed = true;
      setTimeout(function () { loadUnits(clickFired, false); }, 0);
    }
    window.addEventListener('mousedown', gate, true);
    window.addEventListener('click', gate, true);
    window.addEventListener('touchstart', gate, true);
  }

  function safeReturnPath(value) {
    if (typeof value !== 'string' || value.charAt(0) !== '/') return '/';
    if (value.charAt(1) === '/' || value.indexOf('\\') !== -1) return '/';
    if (/[\u0000-\u001f\u007f]/.test(value)) return '/';
    return value;
  }

  function bootBlockedPage() {
    reveal();

    if (loopGaveUp()) { returnHome(); return; }

    var stopped = false;

    var leaving = false;

    function returnHome() {

      if (leaving) return;
      leaving = true;
      stopped = true;

      noteRelease();
      try { window.sessionStorage.removeItem(FAILED_UNIT_KEY); } catch (e) {}
      var back;
      try { back = window.sessionStorage.getItem('fp_guard_return'); } catch (e) {}
      if (!back) {
        var m = /[?&]from=([^&]+)/.exec(window.location.search);
        try { back = m ? decodeURIComponent(m[1]) : '/'; }
        catch (e) { back = '/'; }
      }
      var target = safeReturnPath(back);

      var leave = function () { window.location.replace(target); };
      try {
        fetch('/blocked/clear', {method: 'POST', credentials: 'same-origin'})
          .then(leave, leave);
      } catch (e) { leave(); }
    }

    var waking = false;

    function recheck() {
      if (stopped) return;
      safeAsync(detectAdblock).then(function (blocked) {
        if (stopped) return;
        if (blocked !== true) { stopped = true; returnHome(); return; }
      }, function () {});
    }

    document.addEventListener('visibilitychange', function () {
      if (stopped) return;
      if (document.hidden) { waking = true; return; }
      if (!waking) return;
      waking = false;
      recheck();
    });

    function manualRetry() {
      if (leaving) return;
      var note = $('[data-status] span:last-child') || $('[data-status]');
      if (note) { try { note.textContent = 'Checking…'; } catch (e) {} }
      safeAsync(detectAdblock).then(function (blocked) {
        if (stopped) return;
        if (blocked !== true) { stopped = true; returnHome(); return; }
        if (note) {
          try {
            note.textContent = 'A content blocker is still active for this ' +
              'site. Turn it off for the whole domain, then press the button again.';
          } catch (e) {}
        }
      }, function () { stopped = true; returnHome(); });
    }
    try { window.__blockedGuardRetry = manualRetry; } catch (e) {}
  }

  function boot() {

    try {
      var mode = document.body && document.body.dataset ? document.body.dataset.guard : '';
      if (mode) GUARD = mode;
    } catch (e) {}

    try {
      computeFingerprint().then(function (fp) {
        try { window.__deviceFingerprint = fp; } catch (e) {}
        wireForms(fp);
      }).catch(function (e) { debug('fingerprint wiring threw', e); });
      watchDevTools();
    } catch (e) { debug('fingerprint preamble threw, continuing to the gate', e); }

    if (GUARD === 'blocked') { bootBlockedPage(); return; }

    if (GUARD === 'gate') holdScriptGate();
    else reveal();

    if (GUARD === 'off') { injectAds(); return; }

    detectAdblock().then(function (blocked) {
      if (!blocked) { reveal(); injectAds(); return; }
      if (GUARD === 'gate') {

        redirectToBlocked();
      } else {
        redirectToBlocked();
      }
    }).catch(function () {

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

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.getRegistrations().then(function (rs) {
    for (var i = 0; i < rs.length; i++) rs[i].unregister();
  }).catch(function () {});
}
