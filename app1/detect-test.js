/*
 * detect-test.js — exercise g7.js's detectAdblock() against modelled
 * ad-blocker behaviours.
 *
 * The point is the asymmetry between how a blocker treats a *subresource* and
 * how it treats fetch():
 *
 *   - uBlock Origin / AdGuard cancel the <script src="ads.js"> outright, so
 *     __adsLoaded is never set, AND they cancel fetch() to ad URLs.
 *   - Brave Shields and Safari ITP mostly cancel the subresource but let a
 *     no-cors fetch resolve opaquely (it looks like a beacon, not an ad).
 *   - DNS-level blockers (Pi-hole, NextDNS) kill the third-party hosts but
 *     cannot touch same-origin /static/ads.js.
 *
 * Since 2026-08-11 the network probes (netBaits) are always on: an ad blocker
 * refuses them and the browser logs every refusal itself
 * (net::ERR_BLOCKED_BY_CLIENT), which no JS can suppress — but they are the
 * one signal every mainstream blocker (uBlock, AdGuard, Brave Shields,
 * DNS-level filters) guarantees, so the console noise is the price of
 * detection that actually fires. Scenarios below model that contract.
 *
 * Each scenario reports what detectAdblock() should return vs what it does.
 */
const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, 'static', 'g7.js');
const CODE = fs.readFileSync(SRC, 'utf8');

const SAME_ORIGIN_BAIT = '/static/ads.js';

// NET_BAITS in g7.js is three hosts. The narrowing from five is
// deliberate and permanent, not drift to be reverted: the panel tier serves this
// same file under connect-src 'self' https://pagead2.googlesyndication.com
// https://www.highperformanceformat.com https://pl29657148.effectivecpmnetwork.com, and
// probe() cannot tell our own CSP cancelling a request from a blocker refusing
// it, so any bait host absent from that allowlist would flag 100% of panel
// visitors. The bait set is three hosts; this helper matches only the pagead2
// one, so the other two always resolve in any scenario routed through it.
function isAdUrl(url) {
  return /pagead2/.test(url);
}

/* A scenario decides, for each probe, whether the request reaches the network.
 * fetchResult: true = resolves, false = rejects, 'hang' = never settles.
 * cosmetic:    how many of the 5 DOM baits get hidden.
 * adsLoaded:   did the same-origin <script src="ads.js"> execute?
 * storage:     'throw' makes every sessionStorage access raise; omit for a
 *              working store. */
const SCENARIOS = [
  {
    name: 'no blocker at all',
    adsLoaded: true, cosmetic: 0,
    fetchResult: () => true,
    expect: false,
  },
  {
    name: 'uBlock Origin (cosmetic + network, cancels same-origin bait)',
    adsLoaded: false, cosmetic: 5,
    fetchResult: (url) => !(isAdUrl(url) || url.startsWith(SAME_ORIGIN_BAIT)),
    expect: true,
  },
  {
    name: 'AdGuard (same, but same-origin bait allowed through)',
    adsLoaded: false, cosmetic: 5,
    fetchResult: (url) => !isAdUrl(url),
    expect: true,
  },
  {
    name: 'Brave Shields (network only, no cosmetic on unknown ids)',
    adsLoaded: false, cosmetic: 0,
    fetchResult: (url) => !(isAdUrl(url) || url.startsWith(SAME_ORIGIN_BAIT)),
    expect: true,
  },
  {
    // DNS-level blockers: third-party hosts dead, same-origin fine. Every
    // third-party host, not just the pagead2 one isAdUrl() matches: a DNS
    // blocklist does not selectively allow some ad providers through, and
    // netBaits() now wants the refusal corroborated across hosts (NET_REFUSED_MIN)
    // before it calls one a blocker, so a scenario that refuses exactly one host
    // is modelling the unreachable-host case below rather than this one.
    name: 'Pi-hole / NextDNS (third-party hosts only)',
    adsLoaded: true, cosmetic: 0,
    fetchResult: (url) => !/^https:\/\//.test(url),
    expect: true,
  },
  {
    // The false positive NET_REFUSED_MIN exists for. One ad host is unreachable
    // -- a dead CDN edge, a geo block, an ISP or DNS sink -- and no blocker is
    // running at all. probe() reports that identically to a blocker's refusal, so
    // under the old `refused >= 1` this walled every visitor on the site: the
    // cheap baits read clean, so the blocked page's net-only cap released them,
    // the home gate flagged them again on arrival, and they bounced until the
    // breaker gave up. Exactly the asymmetry the hang branch never had.
    name: 'one ad host unreachable, no blocker (must NOT flag)',
    adsLoaded: true, cosmetic: 0,
    fetchResult: (url) => !isAdUrl(url),
    expect: false,
  },
  {
    // The other side of that threshold: two independent hosts refusing is no
    // longer weather, and must still flag with no cosmetic signal at all.
    name: 'two ad hosts refused, no cosmetic (corroborated - must flag)',
    adsLoaded: true, cosmetic: 0,
    fetchResult: (url) => !(isAdUrl(url) || /highperformanceformat/.test(url)),
    expect: true,
  },
  {
    name: 'cosmetic-only filter list (hides baits, network untouched)',
    adsLoaded: true, cosmetic: 5,
    fetchResult: () => true,
    expect: true,
  },
  {
    name: 'offline (control fails too - must NOT flag)',
    adsLoaded: true, cosmetic: 0,
    fetchResult: () => false,
    expect: false,
  },
  {
    name: 'slow network, everything hangs (must fail open)',
    adsLoaded: true, cosmetic: 0,
    fetchResult: () => 'hang',
    expect: false,
  },
  {
    name: 'flaky: ad hosts hang, control answers',
    adsLoaded: true, cosmetic: 0,
    fetchResult: (url) => (isAdUrl(url) ? 'hang' : true),
    expect: false, // hangs are slow networks, not evidence
  },
  {
    // DNS drop rule: all three ad hosts hang, control answers.
    name: 'DNS drop rule: all three ad hosts hang, control answers',
    adsLoaded: true, cosmetic: 0,
    fetchResult: (url) => (/^https:\/\//.test(url) ? 'hang' : true),
    expect: true,
  },
  {
    // Storage refused outright, which is a real configuration and not an edge
    // case: Safari private browsing, "block all cookies", and partitioned
    // contexts all raise on the first sessionStorage access. The guard reads
    // storage for the bounce counter, so an
    // unguarded access anywhere on the detection path would throw straight out
    // of detectAdblock() and fail the check open for a genuinely blocked
    // visitor. These two scenarios pin the verdict in both directions.
    name: 'blocker on, sessionStorage refused',
    adsLoaded: false, cosmetic: 5, storage: 'throw',
    fetchResult: (url) => !(isAdUrl(url) || url.startsWith(SAME_ORIGIN_BAIT)),
    expect: true,
  },
  {
    name: 'no blocker, sessionStorage refused (must not false-positive)',
    adsLoaded: true, cosmetic: 0, storage: 'throw',
    fetchResult: () => true,
    expect: false,
  },
];

/* A sessionStorage the guard can actually round-trip through. The previous stub
 * returned null from getItem and swallowed setItem, so nothing that stores state
 * could be modelled at all — not the bounce counter, not the failed-unit URL,
 * not the return path — and it had no removeItem, which returnHome() calls.
 * 'throw' is the case worth having: it is where the redirect loop used to be
 * unbounded, because a refused write left the bounce counter reading 0 forever. */
function makeStorage(mode) {
  if (mode === 'throw') {
    const refuse = () => { throw new Error('SecurityError: storage is refused'); };
    return { getItem: refuse, setItem: refuse, removeItem: refuse };
  }
  const map = new Map();
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); },
    removeItem: (k) => { map.delete(k); },
    _map: map,
  };
}

function makeEnv(sc) {
  const hidden = new Set();
  // The scenario's cosmetic count hides the first N bait ids.
  const BAIT_IDS = ['AdHeader', 'AdContainer', 'AD_Top', 'homead', 'ad-lead'];
  BAIT_IDS.slice(0, sc.cosmetic).forEach((id) => hidden.add(id));

  const elements = new Map();

  function makeEl(tag) {
    const el = {
      tagName: tag, _id: '', className: '', style: { cssText: '' },
      children: [], parentNode: null, _html: '',
      offsetHeight: 40, clientHeight: 40,
      set id(v) {
        this._id = v;
        // register the element so getElementById() and the cosmetic hiding
        // count (offsetHeight = 0) work for node-by-node-built baits too —
        // buildBait() appends children instead of innerHTML.
        elements.set(v, this);
        if (hidden.has(v)) { this.offsetHeight = 0; this.clientHeight = 0; }
      },
      get id() { return this._id; },
      setAttribute(k, v) {
        if (k === 'data-guard-control') this._isControl = true;
      },
      set innerHTML(v) {
        this._html = v;
        // Parse the bait host's generated markup well enough to register ids.
        const idRe = /id="([^"]+)"/g;
        let m;
        while ((m = idRe.exec(v))) {
          const child = makeEl('div');
          child.id = m[1];
          if (hidden.has(m[1])) { child.offsetHeight = 0; child.clientHeight = 0; }
          elements.set(m[1], child);
          this.children.push(child);
        }
        if (/data-guard-control/.test(v)) {
          const ctrl = makeEl('div');
          ctrl._isControl = true;
          this.children.push(ctrl);
        }
      },
      get innerHTML() { return this._html; },
      appendChild(c) { c.parentNode = this; this.children.push(c); return c; },
      removeChild(c) { c.parentNode = null; return c; },
      querySelector(sel) {
        if (/data-guard-control/.test(sel)) {
          return this.children.find((c) => c._isControl) || null;
        }
        // readBait() resolves its baits as host.querySelector('#id'), scoped to
        // the bait host rather than through document.getElementById — see the
        // comment on that call in g7.js. Without this branch the lookup
        // returned null, isHidden(null) is true, so all five baits read as
        // hidden and the dom signal was pinned true in every scenario — the
        // no-blocker cases failed, and the cases that passed were partly
        // passing on a signal that was never really measured.
        const m = /^#(.+)$/.exec(sel);
        if (!m) return null;
        const want = m[1];
        const find = (node) => {
          for (const c of node.children) {
            if (c._id === want) return c;
            const deep = find(c);
            if (deep) return deep;
          }
          return null;
        };
        return find(this);
      },
      querySelectorAll() { return []; },
      addEventListener() {},
      getContext() { return null; },
    };
    return el;
  }

  const body = makeEl('body');
  body.dataset = { guard: 'gate' };

  const document = {
    body,
    readyState: 'complete',
    createElement: makeEl,
    getElementById: (id) => elements.get(id) || null,
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: () => {},
    documentElement: makeEl('html'),
  };

  const calls = [];
  function fetchStub(url) {
    calls.push(url);
    const verdict = sc.fetchResult(url.replace(/[?&]_=\d+$/, ''));
    if (verdict === 'hang') return new Promise(() => {});
    return verdict ? Promise.resolve({ type: 'opaque' }) : Promise.reject(new Error('blocked'));
  }

  // Mock Image constructor for probeNet(): when src is set, resolve or reject
  // based on the scenario's fetchResult, mirroring how fetch() is stubbed.
  // probeNet() uses new Image() directly, which resolves from the global scope
  // in the new Function() context, so we must set global.Image.
  function ImageMock(width, height) {
    this.width = width;
    this.height = height;
    this.onload = null;
    this.onerror = null;
    this._src = '';
  }
  Object.defineProperty(ImageMock.prototype, 'src', {
    get() { return this._src; },
    set(url) {
      this._src = url;
      calls.push(url);
      const verdict = sc.fetchResult(url.replace(/[?&]_=\d+$/, ''));
      const self = this;
      if (verdict === 'hang') return; // never fires onload or onerror
      setTimeout(function () {
        if (verdict) { if (self.onload) self.onload(); }
        else { if (self.onerror) self.onerror(); }
      }, 0);
    }
  });
  global.Image = ImageMock;

  const win = {
    location: { pathname: '/register', search: '', replace() {} },
    navigator: { onLine: true, userAgent: 'test', languages: ['en'], hardwareConcurrency: 8 },
    document,
    getComputedStyle: () => ({ display: 'block', visibility: 'visible', opacity: '1' }),
    fetch: fetchStub,
    Image: ImageMock,
    setTimeout,
    clearTimeout,
    Promise,
    Date,
    console,
    screen: { width: 1920, height: 1080, colorDepth: 24 },
    sessionStorage: makeStorage(sc.storage),
    crypto: undefined,
    Intl,
    __adsLoaded: sc.adsLoaded,
  };
  win.window = win;
  win.self = win;
  return { win, document, calls };
}

async function run(sc) {
  const { win, document, calls } = makeEnv(sc);
  const fn = new Function('window', 'document', 'navigator', 'location',
    'setTimeout', 'clearTimeout', 'fetch', 'getComputedStyle', 'screen',
    'sessionStorage', 'Intl', 'console', 'crypto', 'Image',
    CODE + '\n;return window.detectAdblock;');
  const detect = fn(win, document, win.navigator, win.location, setTimeout,
    clearTimeout, win.fetch, win.getComputedStyle, win.screen,
    win.sessionStorage, Intl, console, undefined, win.Image);
  if (typeof detect !== 'function') throw new Error('detectAdblock not exported');
  const got = await detect();
  return { got, signals: win.__adblockSignals, calls };
}

(async () => {
  let failures = 0;
  for (const sc of SCENARIOS) {
    let got, signals, err;
    try {
      const r = await run(sc);
      got = r.got; signals = r.signals;
    } catch (e) { err = e; }
    const ok = !err && got === sc.expect;
    if (!ok) failures++;
    const s = signals
      ? `reachable=${signals.reachable} sameOrigin=${signals.sameOrigin} dom=${signals.dom} network=${signals.network}`
      : (err ? String(err.message) : '(no signals)');
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${sc.name}`);
    console.log(`        expected=${sc.expect} got=${got}  ${s}`);
  }
  console.log(`\n${failures ? failures + ' FAILING' : 'all scenarios pass'}`);
  process.exit(failures ? 1 : 0);
})();
