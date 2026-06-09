#!/usr/bin/env node
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

function btoaCompat(value) { return Buffer.from(String(value), 'binary').toString('base64'); }
function atobCompat(value) { return Buffer.from(String(value), 'base64').toString('binary'); }
function camelCase(value) { return String(value || '').replace(/-([a-z])/g, (_, c) => c.toUpperCase()); }

class MiniEvent {
  constructor(type, init = {}) {
    this.type = String(type || '');
    this.bubbles = !!init.bubbles;
    this.cancelable = !!init.cancelable;
    this.composed = !!init.composed;
    this.defaultPrevented = false;
    this.timeStamp = Date.now();
    this.target = init.target || null;
    this.currentTarget = init.currentTarget || null;
    Object.assign(this, init || {});
  }
  preventDefault() { if (this.cancelable) this.defaultPrevented = true; }
  stopPropagation() {}
  stopImmediatePropagation() {}
  composedPath() { return this.target ? [this.target] : []; }
}

class MiniStorage {
  constructor(init = {}) { this.map = new Map(Object.entries(init || {}).map(([k, v]) => [String(k), String(v)])); }
  get length() { return this.map.size; }
  key(index) { return Array.from(this.map.keys())[Number(index)] ?? null; }
  getItem(key) { return this.map.has(String(key)) ? this.map.get(String(key)) : null; }
  setItem(key, value) { this.map.set(String(key), String(value)); }
  removeItem(key) { this.map.delete(String(key)); }
  clear() { this.map.clear(); }
  toJSON() { return Object.fromEntries(this.map.entries()); }
}

class MiniHeaders {
  constructor(init = {}) {
    this.map = new Map();
    if (init instanceof MiniHeaders) {
      for (const [k, v] of init.entries()) this.set(k, v);
    } else if (Array.isArray(init)) {
      for (const item of init) this.set(item[0], item[1]);
    } else if (init && typeof init[Symbol.iterator] === 'function' && typeof init !== 'string') {
      try { for (const item of init) this.set(item[0], item[1]); } catch (_) {}
    } else if (init && typeof init === 'object') {
      for (const [k, v] of Object.entries(init)) this.set(k, v);
    }
  }
  set(key, value) { this.map.set(String(key).toLowerCase(), String(value)); }
  get(key) { return this.map.get(String(key).toLowerCase()) ?? null; }
  has(key) { return this.map.has(String(key).toLowerCase()); }
  append(key, value) {
    const lowered = String(key).toLowerCase();
    const prior = this.map.get(lowered);
    this.map.set(lowered, prior ? `${prior}, ${value}` : String(value));
  }
  delete(key) { this.map.delete(String(key).toLowerCase()); }
  entries() { return this.map.entries(); }
  keys() { return this.map.keys(); }
  values() { return this.map.values(); }
  forEach(cb, thisArg = undefined) { for (const [k, v] of this.map.entries()) cb.call(thisArg, v, k, this); }
  [Symbol.iterator]() { return this.entries(); }
  toJSON() { return Object.fromEntries(this.map.entries()); }
}

function headersToObject(input = {}) {
  if (input instanceof MiniHeaders) return input.toJSON();
  if (input && input.headers instanceof MiniHeaders) return input.headers.toJSON();
  if (Array.isArray(input)) return Object.fromEntries(input.map(([k, v]) => [String(k).toLowerCase(), String(v)]));
  if (input && typeof input[Symbol.iterator] === 'function' && typeof input !== 'string') {
    const out = {};
    try {
      for (const item of input) out[String(item[0]).toLowerCase()] = String(item[1]);
      return out;
    } catch (_) {}
  }
  if (input && typeof input === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(input)) out[String(k).toLowerCase()] = String(v);
    return out;
  }
  return {};
}

function normalize(input) {
  const pageUrl = input.page_url || input.pageUrl || input.url || 'https://example.test/';
  const scriptUrl = input.script_url || input.scriptUrl || new URL('/px.js', pageUrl).href;
  return {
    script: String(input.script || ''),
    scriptUrl,
    pageUrl,
    collectorUrl: input.collector_url || input.collectorUrl || input.collector_url || input.collectorUrl || '',
    profile: input.profile && typeof input.profile === 'object' ? input.profile : {},
    config: input.config && typeof input.config === 'object' ? input.config : {},
    cookie: String(input.cookie || ''),
    settleMs: Number(input.settle_ms || input.settleMs || 100),
    vmTimeoutMs: Number(input.vm_timeout_ms || input.vmTimeoutMs || 10000),
  };
}

function makeCookieJar(initialCookie) {
  const jar = new Map();
  for (const part of String(initialCookie || '').split(';')) {
    const trimmed = part.trim();
    if (!trimmed || !trimmed.includes('=')) continue;
    const [name, ...rest] = trimmed.split('=');
    jar.set(name.trim(), rest.join('=').trim());
  }
  return {
    set(value) {
      const first = String(value || '').split(';', 1)[0];
      if (!first || !first.includes('=')) return;
      const [name, ...rest] = first.split('=');
      jar.set(name.trim(), rest.join('=').trim());
    },
    get() { return Array.from(jar.entries()).map(([k, v]) => `${k}=${v}`).join('; '); },
    toJSON() { return Object.fromEntries(jar.entries()); },
  };
}

function makeSandbox(opts) {
  const listeners = new Map();
  const requests = [];
  const events = [];
  const messages = [];
  const errors = [];
  const performanceObservers = new Set();
  const objectUrls = new Map();
  const profile = opts.profile || {};
  const config = opts.config || {};
  const page = new URL(opts.pageUrl);
  const cookieJar = makeCookieJar(opts.cookie || profile.cookie || '');
  const hrOrigin = process.hrtime.bigint();
  const timeOrigin = Date.now();
  const rafTimers = new Map();
  let rafSeq = 1;
  let blobSeq = 1;
  let workerSeq = 1;
  let sandbox;

  function nowMs() { return Number((process.hrtime.bigint() - hrOrigin) / 1000000n); }
  function safeCall(cb, thisArg, args = [], source = 'callback') {
    if (typeof cb !== 'function') return undefined;
    try { return cb.apply(thisArg, args); } catch (e) { errors.push({ type: 'callback-error', source, message: e && e.message }); return undefined; }
  }
  function toBuffer(value) {
    if (value == null) return Buffer.alloc(0);
    if (Buffer.isBuffer(value)) return value;
    if (value instanceof ArrayBuffer) return Buffer.from(new Uint8Array(value));
    if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    if (value instanceof MiniBlob) return Buffer.from(value.textSync());
    return Buffer.from(String(value));
  }

  class MiniBlob {
    constructor(parts = [], opts = {}) {
      this.parts = Array.isArray(parts) ? parts.slice() : [parts];
      this.type = String(opts.type || '').toLowerCase();
      this.size = this.parts.reduce((n, p) => n + toBuffer(p).length, 0);
    }
    textSync() { return Buffer.concat(this.parts.map(p => toBuffer(p))).toString('utf8'); }
    async text() { return this.textSync(); }
    async arrayBuffer() {
      const buf = Buffer.concat(this.parts.map(p => toBuffer(p)));
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    }
    slice(start = 0, end = this.size, type = this.type) {
      const buf = Buffer.concat(this.parts.map(p => toBuffer(p))).subarray(Number(start) || 0, Number(end) || this.size);
      return new MiniBlob([buf], { type });
    }
    toString() { return this.textSync(); }
    get [Symbol.toStringTag]() { return 'Blob'; }
  }

  class MiniFormData {
    constructor(init = undefined) {
      this.items = [];
      if (init && typeof init[Symbol.iterator] === 'function') {
        try { for (const [k, v] of init) this.append(k, v); } catch (_) {}
      }
    }
    append(key, value, filename = undefined) { this.items.push([String(key), value, filename == null ? undefined : String(filename)]); }
    set(key, value, filename = undefined) { this.delete(key); this.append(key, value, filename); }
    get(key) { const hit = this.items.find(([k]) => k === String(key)); return hit ? hit[1] : null; }
    getAll(key) { return this.items.filter(([k]) => k === String(key)).map(([, v]) => v); }
    has(key) { return this.items.some(([k]) => k === String(key)); }
    delete(key) { this.items = this.items.filter(([k]) => k !== String(key)); }
    entries() { return this.items.map(([k, v]) => [k, v])[Symbol.iterator](); }
    keys() { return this.items.map(([k]) => k)[Symbol.iterator](); }
    values() { return this.items.map(([, v]) => v)[Symbol.iterator](); }
    forEach(cb, thisArg = undefined) { for (const [k, v] of this.entries()) cb.call(thisArg, v, k, this); }
    [Symbol.iterator]() { return this.entries(); }
    get [Symbol.toStringTag]() { return 'FormData'; }
  }

  function serializeBody(body, depth = 0) {
    if (body == null) return null;
    if (depth > 2) return String(body);
    if (typeof body === 'string') return body;
    if (typeof body === 'number' || typeof body === 'boolean' || typeof body === 'bigint') return String(body);
    if (body instanceof URLSearchParams) return body.toString();
    if (body instanceof MiniBlob) return body.textSync();
    if (body instanceof MiniFormData || (body && Object.prototype.toString.call(body) === '[object FormData]' && typeof body.entries === 'function')) {
      const params = [];
      try {
        for (const [k, v] of body.entries()) params.push(`${encodeURIComponent(String(k))}=${encodeURIComponent(serializeBody(v, depth + 1) ?? '')}`);
        return params.join('&');
      } catch (_) { return String(body); }
    }
    if (body instanceof ArrayBuffer || ArrayBuffer.isView(body) || Buffer.isBuffer(body)) return toBuffer(body).toString('utf8');
    if (typeof body.textSync === 'function') return String(body.textSync());
    if (typeof body.toString === 'function' && body.toString !== Object.prototype.toString) {
      const out = body.toString();
      if (out !== '[object Object]') return String(out);
    }
    try { return JSON.stringify(body); } catch (_) { return String(body); }
  }

  const performanceEntries = [
    { name: opts.pageUrl, entryType: 'navigation', initiatorType: 'navigation', startTime: 0, duration: 0, type: 'navigate', domComplete: 0, loadEventEnd: 0 },
    { name: opts.scriptUrl, entryType: 'resource', initiatorType: 'script', startTime: 0, duration: 0, transferSize: 0, encodedBodySize: 0, decodedBodySize: 0 },
  ];

  function makePerformanceList(entries) {
    return {
      getEntries: () => entries.slice(),
      getEntriesByType: type => entries.filter(e => e.entryType === String(type)),
      getEntriesByName: name => entries.filter(e => e.name === String(name)),
    };
  }
  function notifyPerformance(entry) {
    for (const observer of performanceObservers) {
      const accepts = observer.entryTypes.includes(entry.entryType) || observer.entryTypes.includes('*');
      if (!accepts) continue;
      observer.records.push(entry);
      queueMicrotaskCompat(() => safeCall(observer.cb, observer, [makePerformanceList([entry]), observer], 'PerformanceObserver'));
    }
  }
  function recordPerformanceResource(url, initiatorType = 'fetch') {
    const entry = {
      name: String(url || ''),
      entryType: 'resource',
      initiatorType,
      startTime: nowMs(),
      duration: 0,
      transferSize: 0,
      encodedBodySize: 0,
      decodedBodySize: 0,
    };
    performanceEntries.push(entry);
    notifyPerformance(entry);
    return entry;
  }

  class MiniPerformanceObserver {
    constructor(cb) { this.cb = cb; this.entryTypes = []; this.records = []; }
    observe(options = {}) {
      const types = [];
      if (Array.isArray(options.entryTypes)) types.push(...options.entryTypes.map(String));
      if (options.type) types.push(String(options.type));
      this.entryTypes = types.length ? types : ['*'];
      performanceObservers.add(this);
      if (options.buffered) {
        const buffered = performanceEntries.filter(e => this.entryTypes.includes('*') || this.entryTypes.includes(e.entryType));
        if (buffered.length) queueMicrotaskCompat(() => safeCall(this.cb, this, [makePerformanceList(buffered), this], 'PerformanceObserver.buffered'));
      }
    }
    disconnect() { performanceObservers.delete(this); }
    takeRecords() { const out = this.records.slice(); this.records.length = 0; return out; }
  }
  MiniPerformanceObserver.supportedEntryTypes = ['navigation', 'resource', 'mark', 'measure', 'paint'];

  function capture(kind, url, options = {}) {
    const isRequest = url && typeof url === 'object' && typeof url.url === 'string';
    const rawUrl = isRequest ? url.url : String(url);
    const finalUrl = opts.collectorUrl && rawUrl.includes('__PX_COLLECTOR__') ? opts.collectorUrl + rawUrl.split('__PX_COLLECTOR__').slice(1).join('__PX_COLLECTOR__') : rawUrl;
    const requestHeaders = isRequest ? headersToObject(url.headers || {}) : {};
    const optionHeaders = headersToObject(options.headers || {});
    const rawBody = options.body ?? (isRequest ? url.body : null);
    const body = serializeBody(rawBody);
    const method = String(options.method || (isRequest ? url.method : '') || (body == null ? 'GET' : 'POST')).toUpperCase();
    const item = {
      kind,
      url: finalUrl,
      method,
      headers: { ...requestHeaders, ...optionHeaders },
      body,
      at: Date.now(),
    };
    requests.push(item);
    if (finalUrl) recordPerformanceResource(finalUrl, kind === 'element' ? 'other' : kind);
    return item;
  }

  function addEventListener(type, cb) {
    if (typeof cb !== 'function') return;
    const key = String(type || '');
    if (!listeners.has(key)) listeners.set(key, []);
    listeners.get(key).push(cb);
  }
  function removeEventListener(type, cb) {
    const arr = listeners.get(String(type || '')) || [];
    const idx = arr.indexOf(cb);
    if (idx >= 0) arr.splice(idx, 1);
  }
  function dispatchEvent(event) {
    const ev = typeof event === 'string' ? new MiniEvent(event) : event;
    if (!ev || !ev.type) return false;
    ev.target = ev.target || sandbox.window;
    ev.currentTarget = sandbox.window;
    events.push({ type: ev.type, data: ev.data ?? null, at: Date.now() });
    for (const cb of listeners.get(ev.type) || []) safeCall(cb, sandbox.window, [ev], `window.${ev.type}`);
    const handler = sandbox[`on${ev.type}`];
    if (typeof handler === 'function') safeCall(handler, sandbox.window, [ev], `window.on${ev.type}`);
    return true;
  }
  function postMessage(data, origin = '*') {
    messages.push({ data, origin, at: Date.now() });
    dispatchEvent(new MiniEvent('message', { data, origin, source: sandbox.window }));
  }
  function setTimeoutCompat(cb, delay = 0, ...args) {
    if (typeof cb !== 'function') return setTimeout(cb, delay, ...args);
    return setTimeout(() => safeCall(cb, sandbox.window, args, 'setTimeout'), delay);
  }
  function setIntervalCompat(cb, delay = 0, ...args) {
    if (typeof cb !== 'function') return setInterval(cb, delay, ...args);
    return setInterval(() => safeCall(cb, sandbox.window, args, 'setInterval'), delay);
  }
  function queueMicrotaskCompat(cb) {
    if (typeof cb !== 'function') return;
    Promise.resolve().then(() => safeCall(cb, sandbox ? sandbox.window : undefined, [], 'queueMicrotask'));
  }
  function requestAnimationFrameCompat(cb) {
    const id = rafSeq++;
    const timer = setTimeout(() => {
      rafTimers.delete(id);
      safeCall(cb, sandbox.window, [sandbox.performance.now()], 'requestAnimationFrame');
    }, 16);
    rafTimers.set(id, timer);
    return id;
  }
  function cancelAnimationFrameCompat(id) {
    const timer = rafTimers.get(Number(id));
    if (timer) clearTimeout(timer);
    rafTimers.delete(Number(id));
  }

  function makeEventTarget(target) {
    const targetListeners = new Map();
    target.addEventListener = function addTargetEventListener(type, cb) {
      if (typeof cb !== 'function') return;
      const key = String(type || '');
      if (!targetListeners.has(key)) targetListeners.set(key, []);
      targetListeners.get(key).push(cb);
    };
    target.removeEventListener = function removeTargetEventListener(type, cb) {
      const arr = targetListeners.get(String(type || '')) || [];
      const idx = arr.indexOf(cb);
      if (idx >= 0) arr.splice(idx, 1);
    };
    target.dispatchEvent = function dispatchTargetEvent(event) {
      const ev = typeof event === 'string' ? new MiniEvent(event) : event;
      if (!ev || !ev.type) return false;
      ev.target = ev.target || target;
      ev.currentTarget = target;
      for (const cb of targetListeners.get(ev.type) || []) safeCall(cb, target, [ev], `${target.tagName || 'target'}.${ev.type}`);
      const handler = target[`on${ev.type}`];
      if (typeof handler === 'function') safeCall(handler, target, [ev], `${target.tagName || 'target'}.on${ev.type}`);
      return true;
    };
    return target;
  }

  function triggerElementLoad(child, source = 'element') {
    if (!child || typeof child !== 'object') return;
    child.readyState = 'complete';
    setTimeout(() => {
      if (typeof child.onreadystatechange === 'function') safeCall(child.onreadystatechange, child, [new MiniEvent('readystatechange', { target: child })], `${source}.onreadystatechange`);
      if (typeof child.dispatchEvent === 'function') child.dispatchEvent(new MiniEvent('load', { target: child }));
      else if (typeof child.onload === 'function') safeCall(child.onload, child, [new MiniEvent('load', { target: child })], `${source}.onload`);
    }, 0);
  }

  function appendDocumentChild(parent, child) {
    if (!child || typeof child !== 'object') return child;
    parent.children = parent.children || [];
    parent.children.push(child);
    child.parentNode = parent;
    if (child.src) {
      const tag = String(child.tagName || '').toLowerCase();
      capture(tag === 'script' ? 'script' : tag === 'img' || tag === 'image' ? 'image' : 'element', child.src, { method: 'GET' });
    }
    if (String(child.tagName || '').toLowerCase() === 'script' || typeof child.onload === 'function' || typeof child.onreadystatechange === 'function') triggerElementLoad(child, 'appendChild');
    return child;
  }

  function makeElement(tag) {
    const lowered = String(tag || '').toLowerCase();
    const attrs = new Map();
    const style = {};
    const el = makeEventTarget({
      tagName: lowered.toUpperCase(),
      nodeName: lowered.toUpperCase(),
      nodeType: 1,
      style,
      children: [],
      childNodes: [],
      parentNode: null,
      ownerDocument: null,
      className: '',
      id: '',
      hidden: false,
      async: false,
      defer: false,
      readyState: 'loading',
      onload: null,
      onerror: null,
      onreadystatechange: null,
      setAttribute(k, v) {
        const key = String(k);
        const value = String(v);
        attrs.set(key.toLowerCase(), value);
        if (key.toLowerCase() === 'src') this.src = value;
        else if (key.toLowerCase() === 'class') this.className = value;
        else this[key] = value;
      },
      getAttribute(k) { return attrs.get(String(k).toLowerCase()) ?? null; },
      hasAttribute(k) { return attrs.has(String(k).toLowerCase()); },
      removeAttribute(k) { attrs.delete(String(k).toLowerCase()); },
      appendChild(child) { this.childNodes.push(child); return appendDocumentChild(this, child); },
      removeChild(child) { this.children = this.children.filter(x => x !== child); this.childNodes = this.childNodes.filter(x => x !== child); if (child) child.parentNode = null; return child; },
      insertBefore(child) { return this.appendChild(child); },
      remove() { if (this.parentNode && this.parentNode.removeChild) this.parentNode.removeChild(this); },
      querySelector() { return null; },
      querySelectorAll() { return []; },
      getBoundingClientRect() { return { x: 0, y: 0, width: Number(this.width || 0), height: Number(this.height || 0), top: 0, left: 0, right: Number(this.width || 0), bottom: Number(this.height || 0) }; },
      get clientWidth() { return Number(this.width || sandbox.innerWidth || 0); },
      get clientHeight() { return Number(this.height || sandbox.innerHeight || 0); },
      get offsetWidth() { return this.clientWidth; },
      get offsetHeight() { return this.clientHeight; },
      toString() { return `[object HTML${lowered ? lowered[0].toUpperCase() + lowered.slice(1) : ''}Element]`; },
    });
    Object.defineProperty(el, 'src', { get() { return this._src || ''; }, set(value) { this._src = String(value); attrs.set('src', this._src); } });
    if (lowered === 'iframe') { el.contentWindow = sandbox; el.contentDocument = null; }
    if (lowered === 'canvas') {
      el.width = Number(profile.canvasWidth || 300);
      el.height = Number(profile.canvasHeight || 150);
      el.getContext = () => ({ getParameter: () => null, getExtension: () => null, toDataURL: () => 'data:,', fillRect() {}, drawImage() {}, measureText: text => ({ width: String(text || '').length * 6 }) });
      el.toDataURL = () => 'data:,';
    }
    if (lowered === 'img' || lowered === 'image') {
      Object.defineProperty(el, 'src', {
        get() { return this._src || ''; },
        set(value) {
          this._src = String(value);
          attrs.set('src', this._src);
          capture('image', this._src, { method: 'GET' });
          triggerElementLoad(this, 'image');
        },
      });
    }
    return el;
  }

  function mediaQueryMatches(query) {
    const text = String(query || '').toLowerCase();
    if (!text || text.includes('not all')) return false;
    let matches = true;
    const width = Number(profile.innerWidth || profile.screen_width || 1920);
    const height = Number(profile.innerHeight || profile.screen_height || 1080);
    const colorScheme = String(profile.colorScheme || 'light').toLowerCase();
    for (const [, op, raw] of text.matchAll(/\((min|max)-width:\s*(\d+)px\)/g)) matches = matches && (op === 'min' ? width >= Number(raw) : width <= Number(raw));
    for (const [, op, raw] of text.matchAll(/\((min|max)-height:\s*(\d+)px\)/g)) matches = matches && (op === 'min' ? height >= Number(raw) : height <= Number(raw));
    if (text.includes('prefers-color-scheme: dark')) matches = matches && colorScheme === 'dark';
    if (text.includes('prefers-color-scheme: light')) matches = matches && colorScheme === 'light';
    if (text.includes('hover: none')) matches = matches && false;
    if (text.includes('hover: hover')) matches = matches && true;
    if (text.includes('pointer: coarse')) matches = matches && Number(profile.maxTouchPoints || 0) > 0;
    if (text.includes('pointer: fine')) matches = matches && Number(profile.maxTouchPoints || 0) === 0;
    return !!matches;
  }
  function matchMediaCompat(query) {
    const mql = makeEventTarget({ matches: mediaQueryMatches(query), media: String(query || ''), onchange: null });
    mql.addListener = cb => mql.addEventListener('change', cb);
    mql.removeListener = cb => mql.removeEventListener('change', cb);
    return mql;
  }
  function getComputedStyleCompat(el = {}) {
    const style = el.style || {};
    const defaults = { display: 'block', visibility: 'visible', opacity: '1', position: 'static', pointerEvents: 'auto', color: 'rgb(0, 0, 0)', backgroundColor: 'rgba(0, 0, 0, 0)' };
    const merged = { ...defaults, ...style };
    return new Proxy({
      length: Object.keys(merged).length,
      getPropertyValue(prop) { return String(merged[camelCase(prop)] ?? merged[String(prop)] ?? ''); },
      item(index) { return Object.keys(merged)[Number(index)] || ''; },
      [Symbol.iterator]: function* iterator() { yield* Object.keys(merged); },
    }, {
      get(target, prop) {
        if (prop in target) return target[prop];
        return merged[prop] ?? merged[camelCase(prop)] ?? '';
      },
    });
  }

  async function nativeFetch(url, options = {}) {
    const item = capture('fetch', url, options);
    return {
      ok: true,
      status: 204,
      statusText: 'No Content',
      url: item.url,
      headers: new MiniHeaders(),
      bodyUsed: false,
      text: async () => '',
      json: async () => ({}),
      arrayBuffer: async () => new ArrayBuffer(0),
      blob: async () => new MiniBlob([]),
      clone() { return this; },
    };
  }

  class MiniRequest {
    constructor(url, init = {}) {
      const isRequest = url && typeof url === 'object' && typeof url.url === 'string';
      const body = init.body ?? (isRequest ? url.body : undefined);
      this.url = isRequest ? url.url : String(url);
      this.method = String(init.method || (isRequest ? url.method : '') || (body == null ? 'GET' : 'POST')).toUpperCase();
      this.headers = new MiniHeaders(init.headers || (isRequest ? url.headers : {}) || {});
      this.body = body;
      this.credentials = init.credentials || (isRequest ? url.credentials : 'same-origin');
      this.mode = init.mode || (isRequest ? url.mode : 'cors');
    }
    clone() { return new MiniRequest(this.url, this); }
  }

  class MiniResponse {
    constructor(body = '', init = {}) {
      this._body = body;
      this.status = Number(init.status || 200);
      this.statusText = init.statusText || 'OK';
      this.ok = this.status >= 200 && this.status < 300;
      this.headers = new MiniHeaders(init.headers || {});
      this.url = init.url || '';
    }
    async text() { return serializeBody(this._body) || ''; }
    async json() { return JSON.parse(await this.text()); }
    async arrayBuffer() { return toBuffer(await this.text()).buffer; }
    clone() { return new MiniResponse(this._body, this); }
  }

  class MiniXMLHttpRequest {
    constructor() {
      this.headers = {};
      this.readyState = 0;
      this.status = 204;
      this.statusText = 'No Content';
      this.responseText = '';
      this.response = '';
      this.onreadystatechange = null;
      this.onload = null;
      this.onerror = null;
      this.timeout = 0;
      makeEventTarget(this);
    }
    open(method, url, async = true) { this.method = String(method || 'GET').toUpperCase(); this.url = String(url); this.async = async !== false; this.readyState = 1; }
    setRequestHeader(key, value) { this.headers[String(key).toLowerCase()] = String(value); }
    getAllResponseHeaders() { return ''; }
    getResponseHeader() { return null; }
    abort() { this.readyState = 0; }
    send(body = null) {
      capture('xhr', this.url || '', { method: this.method || 'GET', headers: this.headers, body });
      this.readyState = 4;
      const ev = new MiniEvent('load', { target: this });
      if (typeof this.onreadystatechange === 'function') safeCall(this.onreadystatechange, this, [ev], 'xhr.onreadystatechange');
      this.dispatchEvent(new MiniEvent('readystatechange', { target: this }));
      this.dispatchEvent(ev);
    }
  }
  MiniXMLHttpRequest.DONE = 4;

  class MiniImage {
    constructor(width = 0, height = 0) { this.onload = null; this.onerror = null; this.width = Number(width) || 0; this.height = Number(height) || 0; makeEventTarget(this); }
    set src(value) { this._src = String(value); capture('image', this._src, { method: 'GET' }); triggerElementLoad(this, 'Image'); }
    get src() { return this._src || ''; }
  }

  class MiniWorker {
    constructor(url) {
      this.url = String(url || '');
      this.onmessage = null;
      this.onerror = null;
      this.id = workerSeq++;
      makeEventTarget(this);
      capture('worker', this.url, { method: 'GET' });
    }
    postMessage(data) { messages.push({ data, origin: `worker:${this.id}`, at: Date.now() }); }
    terminate() { this.terminated = true; }
  }

  class URLShim extends URL {}
  URLShim.createObjectURL = function createObjectURL(obj) {
    const url = `blob:${page.origin}/px-${blobSeq++}`;
    objectUrls.set(url, obj);
    return url;
  };
  URLShim.revokeObjectURL = function revokeObjectURL(url) { objectUrls.delete(String(url)); };

  const performance = {
    timeOrigin,
    now: nowMs,
    timing: { navigationStart: timeOrigin, fetchStart: timeOrigin, domComplete: timeOrigin, loadEventEnd: timeOrigin },
    navigation: { type: 0, redirectCount: 0 },
    getEntries: () => performanceEntries.slice(),
    getEntriesByType: type => performanceEntries.filter(e => e.entryType === String(type)),
    getEntriesByName: name => performanceEntries.filter(e => e.name === String(name)),
    clearResourceTimings: () => { for (let i = performanceEntries.length - 1; i >= 0; i -= 1) if (performanceEntries[i].entryType === 'resource') performanceEntries.splice(i, 1); },
    mark: name => { const entry = { name: String(name), entryType: 'mark', startTime: nowMs(), duration: 0 }; performanceEntries.push(entry); notifyPerformance(entry); },
    measure: name => { const entry = { name: String(name), entryType: 'measure', startTime: nowMs(), duration: 0 }; performanceEntries.push(entry); notifyPerformance(entry); },
  };

  const screen = {
    width: Number(profile.screen_width || 1920),
    height: Number(profile.screen_height || 1080),
    availWidth: Number(profile.availWidth || profile.screen_width || 1920),
    availHeight: Number(profile.availHeight || profile.screen_height || 1040),
    colorDepth: Number(profile.colorDepth || 24),
    pixelDepth: Number(profile.pixelDepth || 24),
    orientation: { type: profile.orientation || 'landscape-primary', angle: 0 },
  };

  sandbox = {
    console: { log() {}, error() {}, warn() {}, info() {}, debug() {} },
    Date, Math, JSON, URL: URLShim, URLSearchParams, Error, TypeError, Promise,
    Array, Object, String, Number, Boolean, RegExp, Function, Symbol, Map, Set, WeakMap, WeakSet,
    Uint8Array, Uint16Array, Uint32Array, Int8Array, Int16Array, Int32Array, Float32Array, Float64Array, ArrayBuffer, DataView,
    TextEncoder, TextDecoder,
    Event: MiniEvent,
    CustomEvent: MiniEvent,
    MessageEvent: MiniEvent,
    MouseEvent: MiniEvent,
    KeyboardEvent: MiniEvent,
    PointerEvent: MiniEvent,
    TouchEvent: MiniEvent,
    Headers: MiniHeaders,
    Request: MiniRequest,
    Response: MiniResponse,
    FormData: MiniFormData,
    Blob: MiniBlob,
    Worker: MiniWorker,
    crypto: webcrypto,
    btoa: btoaCompat,
    atob: atobCompat,
    setTimeout: setTimeoutCompat,
    clearTimeout,
    setInterval: setIntervalCompat,
    clearInterval,
    setImmediate: typeof setImmediate === 'function' ? (cb, ...args) => setImmediate(() => safeCall(cb, sandbox.window, args, 'setImmediate')) : (cb, ...args) => setTimeoutCompat(cb, 0, ...args),
    clearImmediate: typeof clearImmediate === 'function' ? clearImmediate : clearTimeout,
    queueMicrotask: queueMicrotaskCompat,
    requestAnimationFrame: requestAnimationFrameCompat,
    cancelAnimationFrame: cancelAnimationFrameCompat,
    performance,
    PerformanceObserver: MiniPerformanceObserver,
    getComputedStyle: getComputedStyleCompat,
    matchMedia: matchMediaCompat,
    devicePixelRatio: Number(profile.devicePixelRatio || 1),
    innerWidth: Number(profile.innerWidth || profile.screen_width || 1920),
    innerHeight: Number(profile.innerHeight || profile.screen_height || 1080),
    outerWidth: Number(profile.outerWidth || profile.screen_width || 1920),
    outerHeight: Number(profile.outerHeight || profile.screen_height || 1080),
    screenX: Number(profile.screenX || 0),
    screenY: Number(profile.screenY || 0),
    pageXOffset: Number(profile.pageXOffset || 0),
    pageYOffset: Number(profile.pageYOffset || 0),
    scrollX: Number(profile.pageXOffset || 0),
    scrollY: Number(profile.pageYOffset || 0),
    location: {
      href: opts.pageUrl,
      origin: page.origin,
      protocol: page.protocol,
      host: page.host,
      hostname: page.hostname,
      port: page.port,
      pathname: page.pathname,
      search: page.search,
      hash: page.hash,
      assign(value) { this.href = String(value); },
      replace(value) { this.href = String(value); },
      reload() {},
      toString() { return this.href; },
    },
    navigator: {
      userAgent: profile.user_agent || profile.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      webdriver: false,
      platform: profile.platform || 'Win32',
      language: profile.language || 'en-US',
      languages: profile.languages || ['en-US', 'en'],
      hardwareConcurrency: Number(profile.hardwareConcurrency || 8),
      deviceMemory: Number(profile.deviceMemory || 8),
      cookieEnabled: true,
      onLine: true,
      maxTouchPoints: Number(profile.maxTouchPoints || 0),
      plugins: profile.plugins || [],
      mimeTypes: profile.mimeTypes || [],
      javaEnabled: () => false,
      permissions: { query: async descriptor => makeEventTarget({ name: descriptor && descriptor.name ? String(descriptor.name) : '', state: profile.permissionState || 'prompt', onchange: null }) },
      mediaDevices: {
        enumerateDevices: async () => profile.mediaDevices || [],
        getUserMedia: async () => ({ active: false, id: 'mock-stream', getTracks: () => [], getAudioTracks: () => [], getVideoTracks: () => [] }),
        getDisplayMedia: async () => ({ active: false, id: 'mock-display-stream', getTracks: () => [] }),
      },
      connection: makeEventTarget({ effectiveType: profile.effectiveType || '4g', rtt: Number(profile.rtt || 50), downlink: Number(profile.downlink || 10), saveData: !!profile.saveData, type: profile.connectionType || 'wifi', onchange: null }),
      sendBeacon(url, data = null) { capture('beacon', url, { method: 'POST', body: data }); return true; },
      userAgentData: profile.userAgentData || {
        brands: [{ brand: 'Chromium', version: '120' }, { brand: 'Google Chrome', version: '120' }, { brand: 'Not=A?Brand', version: '99' }],
        mobile: false,
        platform: profile.platform || 'Windows',
        getHighEntropyValues: async () => ({ architecture: 'x86', bitness: '64', mobile: false, model: '', platform: profile.platform || 'Windows', platformVersion: '10.0.0', uaFullVersion: '120.0.0.0', wow64: false }),
      },
    },
    screen,
    addEventListener, removeEventListener, dispatchEvent, postMessage,
    fetch: nativeFetch,
    __nativeFetch: nativeFetch,
    __pxRequests: requests,
    __pxEvents: events,
    __pxMessages: messages,
    __pxErrors: errors,
    __pxCookieJar: cookieJar,
    __pxObjectUrls: objectUrls,
    _pxAppId: config.px_app_id || config.appId || config._pxAppId || '',
    _pxParam1: config.px_param1 || config.param1 || config._pxParam1 || '',
    _pxVid: config.pxvid || config.vid || config._pxVid || '',
    _pxUuid: config.px_uuid || config.uuid || config._pxUuid || '',
    PX: {},
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.parent = sandbox;
  sandbox.top = sandbox;

  const documentElement = makeElement('html');
  const head = makeElement('head');
  const body = makeElement('body');
  const currentScript = makeElement('script');
  currentScript.src = opts.scriptUrl;
  const document = {
    location: sandbox.location,
    URL: opts.pageUrl,
    documentURI: opts.pageUrl,
    referrer: profile.referrer || '',
    readyState: 'complete',
    hidden: false,
    visibilityState: 'visible',
    currentScript,
    title: profile.title || '',
    compatMode: 'CSS1Compat',
    defaultView: sandbox,
    documentElement,
    body,
    head,
    activeElement: body,
    scripts: [currentScript],
    forms: [],
    images: [],
    hasFocus() { return true; },
    addEventListener, removeEventListener, dispatchEvent,
    createElement: makeElement,
    createEvent(type) { return new MiniEvent(type); },
    getElementById() { return null; },
    getElementsByTagName(tag) {
      const lowered = String(tag || '').toLowerCase();
      if (lowered === 'script') return [currentScript];
      if (lowered === 'head') return [head];
      if (lowered === 'body') return [body];
      if (lowered === 'html') return [documentElement];
      return [];
    },
    getElementsByClassName() { return []; },
    querySelector(selector) {
      const lowered = String(selector || '').toLowerCase();
      if (lowered === 'head') return head;
      if (lowered === 'body') return body;
      if (lowered === 'html' || lowered === ':root') return documentElement;
      if (lowered === 'script') return currentScript;
      return null;
    },
    querySelectorAll(selector) { const hit = this.querySelector(selector); return hit ? [hit] : []; },
  };
  documentElement.ownerDocument = document;
  head.ownerDocument = document;
  body.ownerDocument = document;
  currentScript.ownerDocument = document;
  documentElement.children.push(head, body);
  documentElement.childNodes.push(head, body);
  head.parentNode = documentElement;
  body.parentNode = documentElement;
  Object.defineProperty(document, 'cookie', { get() { return cookieJar.get(); }, set(value) { cookieJar.set(value); } });
  sandbox.document = document;

  sandbox.localStorage = new MiniStorage(profile.localStorage || {});
  sandbox.sessionStorage = new MiniStorage(profile.sessionStorage || {});
  sandbox.chrome = profile.chrome || { runtime: {}, app: {}, csi() { return {}; }, loadTimes() { return {}; } };
  sandbox.history = { length: Number(profile.historyLength || 2), scrollRestoration: 'auto', pushState() {}, replaceState() {}, back() {}, forward() {}, go() {} };
  sandbox.Image = MiniImage;
  sandbox.XMLHttpRequest = MiniXMLHttpRequest;
  sandbox.MutationObserver = class MutationObserver { constructor(cb) { this.cb = cb; } observe() {} disconnect() {} takeRecords() { return []; } };
  sandbox.IntersectionObserver = class IntersectionObserver { constructor(cb) { this.cb = cb; } observe() {} unobserve() {} disconnect() {} takeRecords() { return []; } };
  sandbox.ResizeObserver = class ResizeObserver { constructor(cb) { this.cb = cb; } observe() {} unobserve() {} disconnect() {} };
  return sandbox;
}

async function solve(input) {
  const opts = normalize(input || {});
  if (!opts.script.trim()) throw new Error('PerimeterX PX VM requires non-empty script');
  const sandbox = makeSandbox(opts);
  const context = vm.createContext(sandbox);
  vm.runInContext(opts.script, context, { timeout: opts.vmTimeoutMs, filename: opts.scriptUrl });

  for (const ev of ['DOMContentLoaded', 'load', 'visibilitychange']) {
    try { context.dispatchEvent(new MiniEvent(ev)); } catch (e) { context.__pxErrors.push({ type: 'dispatch-error', event: ev, message: e && e.message }); }
  }
  await new Promise(resolve => setTimeout(resolve, Math.max(0, opts.settleMs)));

  return {
    requests: context.__pxRequests,
    events: context.__pxEvents,
    messages: context.__pxMessages,
    errors: context.__pxErrors,
    cookies: context.__pxCookieJar.toJSON(),
    cookie: context.document.cookie,
    diagnostics: {
      scriptUrl: opts.scriptUrl,
      pageUrl: opts.pageUrl,
      collectorUrl: opts.collectorUrl,
      requestCount: context.__pxRequests.length,
      eventCount: context.__pxEvents.length,
      messageCount: context.__pxMessages.length,
      errorCount: context.__pxErrors.length,
      hasPxCookie: Object.keys(context.__pxCookieJar.toJSON()).some(k => k.startsWith('_px')),
      pxConfigKeys: opts.config && typeof opts.config === 'object' ? Object.keys(opts.config).slice(0, 60) : [],
    },
  };
}

try {
  const raw = await readStdin();
  const output = await solve(raw.trim() ? JSON.parse(raw) : {});
  process.stdout.write(JSON.stringify(output));
} catch (error) {
  process.stderr.write((error && error.message ? error.message : String(error)) + '\n');
  process.exit(1);
}
