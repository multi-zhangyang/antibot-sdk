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

function bytesToText(value) {
  if (value == null) return '';
  if (typeof value === 'string') return value;
  if (value instanceof ArrayBuffer) return Buffer.from(value).toString('utf8');
  if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('utf8');
  return String(value);
}

function encodeFormValue(value) {
  if (value && typeof value === 'object' && typeof value.textSync === 'function') return value.textSync();
  return bytesToText(value);
}

class MiniBlob {
  constructor(parts = [], opts = {}) {
    this._parts = Array.isArray(parts) ? parts : [parts];
    this.type = String((opts && opts.type) || '').toLowerCase();
    this.size = Buffer.byteLength(this.textSync());
  }
  textSync() { return this._parts.map(part => bytesToText(part)).join(''); }
  async text() { return this.textSync(); }
  async arrayBuffer() {
    const buf = Buffer.from(this.textSync(), 'utf8');
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  slice(start = 0, end = this.size, type = this.type) {
    return new MiniBlob([this.textSync().slice(Number(start) || 0, end == null ? undefined : Number(end))], { type });
  }
  stream() {
    const payload = new TextEncoder().encode(this.textSync());
    let done = false;
    return {
      getReader() {
        return {
          async read() {
            if (done) return { done: true, value: undefined };
            done = true;
            return { done: false, value: payload };
          },
          releaseLock() {},
        };
      },
    };
  }
  get [Symbol.toStringTag]() { return 'Blob'; }
}

class MiniFile extends MiniBlob {
  constructor(parts = [], name = 'file', opts = {}) {
    super(parts, opts);
    this.name = String(name);
    this.lastModified = Number(opts.lastModified || Date.now());
  }
  get [Symbol.toStringTag]() { return 'File'; }
}

class MiniFormData {
  constructor(init = null) {
    this.items = [];
    if (init && typeof init[Symbol.iterator] === 'function') {
      for (const item of init) {
        if (Array.isArray(item) && item.length >= 2) this.append(item[0], item[1], item[2]);
      }
    }
  }
  append(key, value, filename = undefined) { this.items.push([String(key), value, filename == null ? undefined : String(filename)]); }
  set(key, value, filename = undefined) {
    this.delete(key);
    this.append(key, value, filename);
  }
  delete(key) { this.items = this.items.filter(item => item[0] !== String(key)); }
  get(key) {
    const item = this.items.find(entry => entry[0] === String(key));
    return item ? item[1] : null;
  }
  getAll(key) { return this.items.filter(entry => entry[0] === String(key)).map(entry => entry[1]); }
  has(key) { return this.items.some(entry => entry[0] === String(key)); }
  entries() { return this.items.map(([key, value]) => [key, value])[Symbol.iterator](); }
  keys() { return this.items.map(([key]) => key)[Symbol.iterator](); }
  values() { return this.items.map(([, value]) => value)[Symbol.iterator](); }
  forEach(cb, thisArg = undefined) {
    for (const [key, value] of this.items) cb.call(thisArg, value, key, this);
  }
  toString() {
    return this.items
      .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(encodeFormValue(value))}`)
      .join('&');
  }
  [Symbol.iterator]() { return this.entries(); }
  get [Symbol.toStringTag]() { return 'FormData'; }
}

function serializeBody(body) {
  if (body == null) return null;
  if (typeof body === 'string') return body;
  if (body instanceof URLSearchParams) return body.toString();
  if (body instanceof MiniFormData) return body.toString();
  if (body instanceof MiniBlob) return body.textSync();
  if (body instanceof ArrayBuffer) return bytesToText(body);
  if (ArrayBuffer.isView(body)) return bytesToText(body);
  if (body && typeof body === 'object') {
    if (typeof body.textSync === 'function') return body.textSync();
    if (typeof body.toString === 'function' && body.toString !== Object.prototype.toString) return String(body);
    try { return JSON.stringify(body); } catch {}
  }
  return String(body);
}

class MiniEvent {
  constructor(type, init = {}) {
    this.type = String(type || '');
    this.bubbles = !!init.bubbles;
    this.cancelable = !!init.cancelable;
    this.defaultPrevented = false;
    Object.assign(this, init || {});
  }
  preventDefault() { if (this.cancelable) this.defaultPrevented = true; }
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
  forEach(cb, thisArg = undefined) {
    for (const [k, v] of this.map.entries()) cb.call(thisArg, v, k, this);
  }
  [Symbol.iterator]() { return this.entries(); }
  toJSON() { return Object.fromEntries(this.map.entries()); }
}

function headersToObject(input = {}) {
  if (input instanceof MiniHeaders) return input.toJSON();
  if (input && input.headers instanceof MiniHeaders) return input.headers.toJSON();
  if (Array.isArray(input)) return Object.fromEntries(input.map(([k, v]) => [String(k).toLowerCase(), String(v)]));
  if (input && typeof input === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(input)) out[String(k).toLowerCase()] = String(v);
    return out;
  }
  return {};
}

function normalize(input) {
  const pageUrl = input.page_url || input.pageUrl || input.url || 'https://example.test/';
  const scriptUrl = input.script_url || input.scriptUrl || new URL('/tags.js', pageUrl).href;
  return {
    script: String(input.script || ''),
    scriptUrl,
    pageUrl,
    endpointUrl: input.endpoint_url || input.endpointUrl || '',
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
  const performanceEntries = [];
  const performanceObservers = new Set();
  const objectUrls = new Map();
  let objectUrlCounter = 0;
  let rafCounter = 0;
  const rafTimers = new Map();
  const profile = opts.profile || {};
  const config = opts.config || {};
  const NativeURL = globalThis.URL;
  const page = new NativeURL(opts.pageUrl);
  const cookieJar = makeCookieJar(opts.cookie || profile.cookie || '');
  const timeOrigin = Date.now();
  const hrOrigin = process.hrtime.bigint();

  function perfNow() { return Number(process.hrtime.bigint() - hrOrigin) / 1000000; }
  function safeCall(cb, thisArg, args = [], source = 'callback') {
    if (typeof cb !== 'function') return undefined;
    try { return cb.apply(thisArg, args); } catch (e) { errors.push({ type: 'callback-error', source, message: e && e.message ? e.message : String(e) }); return undefined; }
  }
  function setTimeoutCompat(cb, delay = 0, ...args) {
    if (typeof cb !== 'function') return setTimeout(cb, delay, ...args);
    return setTimeout(() => safeCall(cb, sandbox.window, args, 'setTimeout'), delay);
  }
  function setIntervalCompat(cb, delay = 0, ...args) {
    if (typeof cb !== 'function') return setInterval(cb, delay, ...args);
    return setInterval(() => safeCall(cb, sandbox.window, args, 'setInterval'), delay);
  }
  const nativeSetImmediate = typeof setImmediate === 'function' ? setImmediate : (cb, ...args) => setTimeout(cb, 0, ...args);
  function setImmediateCompat(cb, ...args) {
    if (typeof cb !== 'function') return nativeSetImmediate(cb, ...args);
    return nativeSetImmediate(() => safeCall(cb, sandbox.window, args, 'setImmediate'));
  }
  const clearImmediateCompat = typeof clearImmediate === 'function' ? clearImmediate : clearTimeout;

  class SandboxURL extends NativeURL {
    static createObjectURL(obj) {
      const href = `blob:${page.origin}/${++objectUrlCounter}-${Math.random().toString(36).slice(2)}`;
      objectUrls.set(href, obj);
      return href;
    }
    static revokeObjectURL(value) { objectUrls.delete(String(value)); }
    static canParse(value, base = undefined) {
      if (typeof NativeURL.canParse === 'function') return NativeURL.canParse(value, base);
      try { new NativeURL(value, base); return true; } catch { return false; }
    }
  }

  function clonePerformanceEntry(entry) {
    return {
      ...entry,
      toJSON() {
        const { toJSON: _ignored, ...plain } = this;
        return plain;
      },
    };
  }

  function notifyPerformanceObservers(entry) {
    for (const observer of performanceObservers) {
      if (!observer.entryTypes.has(entry.entryType)) continue;
      const cloned = clonePerformanceEntry(entry);
      observer.records.push(cloned);
      queueMicrotaskCompat(() => {
        if (!performanceObservers.has(observer) || observer.records.length === 0) return;
        const batch = observer.takeRecords();
        try {
          observer.cb(
            {
              getEntries: () => batch.slice(),
              getEntriesByType: type => batch.filter(item => item.entryType === String(type)),
              getEntriesByName: name => batch.filter(item => item.name === String(name)),
            },
            observer,
          );
        } catch (e) {
          errors.push({ type: 'performance-observer-error', message: e && e.message ? e.message : String(e) });
        }
      });
    }
  }

  function addPerformanceEntry(kind, url) {
    if (!url) return null;
    const startTime = perfNow();
    const entry = {
      name: String(url),
      entryType: kind === 'navigation' ? 'navigation' : 'resource',
      initiatorType: kind === 'navigation' ? 'navigation' : String(kind || 'other'),
      startTime,
      duration: 0,
      fetchStart: startTime,
      requestStart: startTime,
      responseStart: startTime,
      responseEnd: startTime,
      transferSize: 0,
      encodedBodySize: 0,
      decodedBodySize: 0,
    };
    performanceEntries.push(entry);
    notifyPerformanceObservers(entry);
    return entry;
  }
  addPerformanceEntry('navigation', opts.pageUrl);

  function queueMicrotaskCompat(cb) {
    Promise.resolve().then(() => {
      try { if (typeof cb === 'function') cb(); } catch (e) { errors.push({ type: 'microtask-error', message: e && e.message ? e.message : String(e) }); }
    });
  }

  function requestAnimationFrameCompat(cb) {
    const id = ++rafCounter;
    const timer = setTimeout(() => {
      rafTimers.delete(id);
      try { if (typeof cb === 'function') cb(perfNow()); } catch (e) { errors.push({ type: 'raf-error', message: e && e.message ? e.message : String(e) }); }
    }, 16);
    rafTimers.set(id, timer);
    return id;
  }

  function cancelAnimationFrameCompat(id) {
    const timer = rafTimers.get(Number(id));
    if (timer) clearTimeout(timer);
    rafTimers.delete(Number(id));
  }

  class MiniPerformanceObserver {
    constructor(cb) {
      this.cb = typeof cb === 'function' ? cb : () => {};
      this.entryTypes = new Set();
      this.records = [];
    }
    observe(options = {}) {
      const entryTypes = Array.isArray(options.entryTypes) ? options.entryTypes : (options.type ? [options.type] : []);
      this.entryTypes = new Set(entryTypes.map(String));
      performanceObservers.add(this);
      if (options.buffered) {
        for (const entry of performanceEntries) {
          if (this.entryTypes.has(entry.entryType)) this.records.push(clonePerformanceEntry(entry));
        }
      }
    }
    disconnect() {
      performanceObservers.delete(this);
      this.records = [];
    }
    takeRecords() {
      const out = this.records.slice();
      this.records = [];
      return out;
    }
    static get supportedEntryTypes() { return ['navigation', 'resource', 'mark', 'measure', 'paint']; }
  }

  function capture(kind, url, options = {}) {
    const isRequest = url && typeof url === 'object' && typeof url.url === 'string';
    const rawUrl = isRequest ? url.url : String(url);
    const finalUrl = opts.endpointUrl && rawUrl.includes('__DATADOME_ENDPOINT__') ? rawUrl.split('__DATADOME_ENDPOINT__').join(opts.endpointUrl) : rawUrl;
    const requestHeaders = isRequest ? headersToObject(url.headers || {}) : {};
    const optionHeaders = headersToObject(options.headers || {});
    const body = options.body ?? (isRequest ? url.body : null);
    const method = String(options.method || (isRequest ? url.method : '') || (body == null ? 'GET' : 'POST')).toUpperCase();
    const serializedBody = serializeBody(body);
    const item = {
      kind,
      url: finalUrl,
      method,
      headers: { ...requestHeaders, ...optionHeaders },
      body: serializedBody,
      at: Date.now(),
    };
    requests.push(item);
    addPerformanceEntry(kind, finalUrl);
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
    events.push({ type: ev.type, data: ev.data ?? null, at: Date.now() });
    for (const target of [sandbox.window, sandbox.document]) {
      const handler = target && target[`on${ev.type}`];
      if (typeof handler === 'function') {
        try { handler.call(target, ev); } catch (e) { errors.push({ type: 'handler-error', source: ev.type, message: e && e.message }); }
      }
    }
    for (const cb of listeners.get(ev.type) || []) {
      try { cb.call(sandbox.window, ev); } catch (e) { errors.push({ type: 'listener-error', source: ev.type, message: e && e.message }); }
    }
    return true;
  }
  function postMessage(data, origin = '*') {
    messages.push({ data, origin, at: Date.now() });
    dispatchEvent(new MiniEvent('message', { data, origin, source: sandbox.window }));
  }
  async function nativeFetch(url, options = {}) {
    const item = capture('fetch', url, options);
    return {
      ok: true,
      status: 204,
      url: item.url,
      headers: new MiniHeaders(),
      text: async () => '',
      json: async () => ({}),
      arrayBuffer: async () => new ArrayBuffer(0),
      clone() { return this; },
    };
  }

  function attachEventTarget(target, source = 'target') {
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
      const handler = target[`on${ev.type}`];
      if (typeof handler === 'function') {
        try { handler.call(target, ev); } catch (e) { errors.push({ type: `${source}-handler-error`, source: ev.type, message: e && e.message }); }
      }
      for (const cb of targetListeners.get(ev.type) || []) {
        try { cb.call(target, ev); } catch (e) { errors.push({ type: `${source}-listener-error`, source: ev.type, message: e && e.message }); }
      }
      return !ev.defaultPrevented;
    };
    return target;
  }

  function fireElementLoad(el) {
    setTimeout(() => {
      try { if (el && typeof el.dispatchEvent === 'function') el.dispatchEvent(new MiniEvent('load')); } catch (e) { errors.push({ type: 'element-load-error', message: e && e.message }); }
    }, 0);
  }

  function appendChildTo(parent, child) {
    if (!child) return child;
    if (!parent.children) parent.children = [];
    if (!parent.children.includes(child)) parent.children.push(child);
    child.parentNode = parent;
    const tag = String(child.tagName || child.nodeName || '').toUpperCase();
    const childUrl = child.src || child.href || '';
    if (childUrl && tag === 'SCRIPT') {
      capture('script', childUrl, { method: 'GET' });
      fireElementLoad(child);
    } else if (childUrl && !['IMG', 'IMAGE'].includes(tag)) {
      capture('element', childUrl, { method: 'GET' });
      fireElementLoad(child);
    }
    return child;
  }

  function removeChildFrom(parent, child) {
    if (parent && Array.isArray(parent.children)) {
      const idx = parent.children.indexOf(child);
      if (idx >= 0) parent.children.splice(idx, 1);
    }
    if (child) child.parentNode = null;
    return child;
  }

  function makeElement(tag = 'div') {
    const lowered = String(tag || 'div').toLowerCase();
    const upper = lowered.toUpperCase();
    const el = attachEventTarget({
      nodeType: 1,
      nodeName: upper,
      tagName: upper,
      localName: lowered,
      style: {},
      children: [],
      attributes: {},
      parentNode: null,
      ownerDocument: null,
      className: '',
      id: '',
      hidden: false,
      clientWidth: 0,
      clientHeight: 0,
      setAttribute(k, v) {
        const key = String(k).toLowerCase();
        this.attributes[key] = String(v);
        if (key === 'class') this.className = String(v);
        else if (key in this || ['src', 'href', 'type', 'id', 'name', 'value'].includes(key)) this[key] = String(v);
      },
      getAttribute(k) {
        const key = String(k).toLowerCase();
        return Object.prototype.hasOwnProperty.call(this.attributes, key) ? this.attributes[key] : null;
      },
      removeAttribute(k) { delete this.attributes[String(k).toLowerCase()]; },
      appendChild(child) { return appendChildTo(this, child); },
      removeChild(child) { return removeChildFrom(this, child); },
      insertBefore(child) { return appendChildTo(this, child); },
      remove() { if (this.parentNode) removeChildFrom(this.parentNode, this); },
      contains(child) { return this.children.includes(child); },
      getBoundingClientRect() {
        const width = Number(this.clientWidth || 0);
        const height = Number(this.clientHeight || 0);
        return { x: 0, y: 0, left: 0, top: 0, width, height, right: width, bottom: height, toJSON() { return { x: 0, y: 0, width, height }; } };
      },
      click() { this.dispatchEvent(new MiniEvent('click', { bubbles: true })); },
    }, `element-${lowered}`);
    if (lowered === 'script') {
      el.async = false;
      el.defer = false;
      el.onload = null;
      el.onerror = null;
      Object.defineProperty(el, 'src', { get() { return this._src || ''; }, set(value) { this._src = String(value); this.attributes.src = this._src; } });
    }
    if (lowered === 'iframe') { el.contentWindow = sandbox; el.contentDocument = null; }
    if (lowered === 'canvas') {
      el.width = Number(profile.canvasWidth || 300);
      el.height = Number(profile.canvasHeight || 150);
      el.toDataURL = () => 'data:image/png;base64,';
      el.getContext = () => ({
        canvas: el,
        getParameter: () => null,
        getExtension: () => null,
        measureText: text => ({ width: String(text || '').length * 6 }),
        fillText() {},
        strokeText() {},
        drawImage() {},
        getImageData: (x, y, width, height) => ({ data: new Uint8ClampedArray(Math.max(0, Number(width) * Number(height) * 4)), width, height }),
        putImageData() {},
        createImageData: (width, height) => ({ data: new Uint8ClampedArray(Math.max(0, Number(width) * Number(height) * 4)), width, height }),
      });
    }
    if (lowered === 'img' || lowered === 'image') {
      el.complete = false;
      el.width = 0;
      el.height = 0;
      Object.defineProperty(el, 'src', {
        get() { return this._src || ''; },
        set(value) {
          this._src = String(value);
          this.attributes.src = this._src;
          capture('image', this._src, { method: 'GET' });
          this.complete = true;
          fireElementLoad(this);
        },
      });
    }
    return el;
  }

  function makeContainer(tag) {
    const el = makeElement(tag);
    el.clientWidth = Number(profile.innerWidth || profile.screen_width || 1920);
    el.clientHeight = Number(profile.innerHeight || profile.screen_height || 1080);
    return el;
  }

  function mediaQueryMatches(query) {
    const q = String(query || '').toLowerCase();
    const width = Number(profile.innerWidth || profile.screen_width || 1920);
    const height = Number(profile.innerHeight || profile.screen_height || 1080);
    let matches = true;
    for (const [, op, value] of q.matchAll(/\(\s*(min|max)-width\s*:\s*(\d+)px\s*\)/g)) {
      matches = matches && (op === 'min' ? width >= Number(value) : width <= Number(value));
    }
    for (const [, op, value] of q.matchAll(/\(\s*(min|max)-height\s*:\s*(\d+)px\s*\)/g)) {
      matches = matches && (op === 'min' ? height >= Number(value) : height <= Number(value));
    }
    if (q.includes('orientation: portrait')) matches = matches && height >= width;
    if (q.includes('orientation: landscape')) matches = matches && width >= height;
    if (q.includes('prefers-color-scheme: dark')) matches = false;
    if (q.includes('prefers-reduced-motion: reduce')) matches = false;
    return matches;
  }

  const sandbox = {
    console: { log() {}, error() {}, warn() {}, info() {}, debug() {} },
    Date, Math, JSON, URL: SandboxURL, URLSearchParams, Error, TypeError, Promise,
    Array, Object, String, Number, Boolean, RegExp, Function, Symbol, Map, Set, WeakMap, WeakSet,
    Uint8Array, Uint8ClampedArray, Uint16Array, Uint32Array, Int8Array, Int16Array, Int32Array, Float32Array, Float64Array, ArrayBuffer, DataView,
    TextEncoder, TextDecoder,
    Event: MiniEvent,
    CustomEvent: MiniEvent,
    MessageEvent: MiniEvent,
    MouseEvent: MiniEvent,
    KeyboardEvent: MiniEvent,
    PointerEvent: MiniEvent,
    Headers: MiniHeaders,
    Request: class Request {
      constructor(url, init = {}) {
        const isRequest = url && typeof url === 'object' && typeof url.url === 'string';
        this.url = isRequest ? url.url : String(url);
        this.method = String(init.method || (isRequest ? url.method : '') || 'GET').toUpperCase();
        this.headers = new MiniHeaders(init.headers || (isRequest ? url.headers : {}) || {});
        this.body = init.body ?? (isRequest ? url.body : undefined);
      }
    },
    Response: class Response {},
    crypto: webcrypto,
    btoa: btoaCompat,
    atob: atobCompat,
    setTimeout: setTimeoutCompat,
    clearTimeout,
    setInterval: setIntervalCompat,
    clearInterval,
    setImmediate: setImmediateCompat,
    clearImmediate: clearImmediateCompat,
    queueMicrotask: queueMicrotaskCompat,
    requestAnimationFrame: requestAnimationFrameCompat,
    cancelAnimationFrame: cancelAnimationFrameCompat,
    performance: {
      now: perfNow,
      timeOrigin,
      getEntries: () => performanceEntries.map(clonePerformanceEntry),
      getEntriesByType: type => performanceEntries.filter(entry => entry.entryType === String(type)).map(clonePerformanceEntry),
      getEntriesByName: name => performanceEntries.filter(entry => entry.name === String(name)).map(clonePerformanceEntry),
      mark(name) {
        const entry = { name: String(name), entryType: 'mark', startTime: perfNow(), duration: 0 };
        performanceEntries.push(entry);
        notifyPerformanceObservers(entry);
      },
      measure(name) {
        const entry = { name: String(name), entryType: 'measure', startTime: perfNow(), duration: 0 };
        performanceEntries.push(entry);
        notifyPerformanceObservers(entry);
      },
      clearMarks(name = undefined) {
        for (let i = performanceEntries.length - 1; i >= 0; i--) {
          if (performanceEntries[i].entryType === 'mark' && (name == null || performanceEntries[i].name === String(name))) performanceEntries.splice(i, 1);
        }
      },
      clearMeasures(name = undefined) {
        for (let i = performanceEntries.length - 1; i >= 0; i--) {
          if (performanceEntries[i].entryType === 'measure' && (name == null || performanceEntries[i].name === String(name))) performanceEntries.splice(i, 1);
        }
      },
    },
    PerformanceObserver: MiniPerformanceObserver,
    devicePixelRatio: Number(profile.devicePixelRatio || 1),
    innerWidth: Number(profile.innerWidth || profile.screen_width || 1920),
    innerHeight: Number(profile.innerHeight || profile.screen_height || 1080),
    outerWidth: Number(profile.outerWidth || profile.screen_width || 1920),
    outerHeight: Number(profile.outerHeight || profile.screen_height || 1080),
    screenX: Number(profile.screenX || 0),
    screenY: Number(profile.screenY || 0),
    pageXOffset: Number(profile.pageXOffset || 0),
    pageYOffset: Number(profile.pageYOffset || 0),
    scrollX: Number(profile.scrollX || profile.pageXOffset || 0),
    scrollY: Number(profile.scrollY || profile.pageYOffset || 0),
    location: {
      href: opts.pageUrl,
      origin: page.origin,
      protocol: page.protocol,
      host: page.host,
      hostname: page.hostname,
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
      maxTouchPoints: Number(profile.maxTouchPoints || 0),
      plugins: profile.plugins || [],
      mimeTypes: profile.mimeTypes || [],
      connection: profile.connection || { effectiveType: '4g', rtt: 50, downlink: 10, saveData: false, type: 'wifi' },
      permissions: {
        query: async descriptor => attachEventTarget({ name: descriptor && descriptor.name ? String(descriptor.name) : '', state: 'prompt', onchange: null }, 'permission-status'),
      },
      mediaDevices: {
        enumerateDevices: async () => [],
        getSupportedConstraints: () => ({ audio: true, video: true, width: true, height: true, frameRate: true }),
        getUserMedia: async () => ({ active: false, id: 'mock-stream', getTracks: () => [], getAudioTracks: () => [], getVideoTracks: () => [] }),
        getDisplayMedia: async () => ({ active: false, id: 'mock-display-stream', getTracks: () => [] }),
      },
      sendBeacon(url, data = null) { capture('beacon', url, { method: 'POST', body: data }); return true; },
      userAgentData: profile.userAgentData || {
        brands: [{ brand: 'Chromium', version: '120' }, { brand: 'Google Chrome', version: '120' }, { brand: 'Not=A?Brand', version: '99' }],
        mobile: false,
        platform: profile.platform || 'Windows',
        getHighEntropyValues: async () => ({ architecture: 'x86', bitness: '64', mobile: false, model: '', platform: profile.platform || 'Windows', platformVersion: '10.0.0', uaFullVersion: '120.0.0.0', wow64: false }),
      },
    },
    screen: { width: Number(profile.screen_width || 1920), height: Number(profile.screen_height || 1080), availWidth: Number(profile.availWidth || profile.screen_width || 1920), availHeight: Number(profile.availHeight || profile.screen_height || 1040), colorDepth: 24, pixelDepth: 24, orientation: { type: 'landscape-primary', angle: 0 } },
    addEventListener, removeEventListener, dispatchEvent, postMessage,
    fetch: nativeFetch,
    __nativeFetch: nativeFetch,
    __ddRequests: requests,
    __ddEvents: events,
    __ddMessages: messages,
    __ddErrors: errors,
    __ddCookieJar: cookieJar,
    ddoptions: config.ddoptions || config,
    DD_RUM: {},
    getComputedStyle(element = {}) {
      const style = element && element.style ? element.style : {};
      const defaults = { display: 'block', visibility: 'visible', opacity: '1', position: 'static', width: '0px', height: '0px' };
      return new Proxy({ ...defaults, ...style }, {
        get(target, prop) {
          if (prop === 'getPropertyValue') return key => target[String(key)] || target[String(key).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] || '';
          if (prop === 'setProperty') return (key, value) => { target[String(key)] = String(value); };
          if (prop === 'removeProperty') return key => { const prior = target[String(key)] || ''; delete target[String(key)]; return prior; };
          return target[prop] ?? '';
        },
      });
    },
    matchMedia(query) {
      return attachEventTarget({ media: String(query || ''), matches: mediaQueryMatches(query), onchange: null, addListener(cb) { this.addEventListener('change', cb); }, removeListener(cb) { this.removeEventListener('change', cb); } }, 'media-query-list');
    },
    FormData: MiniFormData,
    Blob: MiniBlob,
    File: MiniFile,
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.parent = sandbox;
  sandbox.top = sandbox;
  sandbox.navigator.connection = attachEventTarget({ onchange: null, ...(sandbox.navigator.connection || {}) }, 'network-information');
  sandbox.Node = function Node() {};
  sandbox.Node.ELEMENT_NODE = 1;
  sandbox.Node.TEXT_NODE = 3;
  sandbox.Node.DOCUMENT_NODE = 9;
  sandbox.Element = function Element() {};
  sandbox.HTMLElement = function HTMLElement() {};
  sandbox.HTMLScriptElement = function HTMLScriptElement() {};

  const documentElement = makeContainer('html');
  const documentHead = makeContainer('head');
  const documentBody = makeContainer('body');
  sandbox.document = {
    nodeType: 9,
    nodeName: '#document',
    location: sandbox.location,
    URL: opts.pageUrl,
    documentURI: opts.pageUrl,
    referrer: profile.referrer || '',
    readyState: 'complete',
    hidden: false,
    visibilityState: 'visible',
    currentScript: { src: opts.scriptUrl },
    title: profile.title || '',
    defaultView: sandbox,
    body: documentBody,
    head: documentHead,
    documentElement,
    addEventListener, removeEventListener, dispatchEvent,
    hasFocus() { return true; },
    createElement: makeElement,
    createElementNS(_ns, tag) { return makeElement(tag); },
    createTextNode(text = '') { return { nodeType: 3, nodeName: '#text', textContent: String(text), data: String(text), parentNode: null }; },
    createDocumentFragment() { return makeContainer('fragment'); },
    appendChild(child) { return appendChildTo(documentElement, child); },
    removeChild(child) { return removeChildFrom(documentElement, child); },
    getElementById() { return null; },
    getElementsByTagName(tag) {
      const lowered = String(tag || '').toLowerCase();
      if (lowered === 'head') return [documentHead];
      if (lowered === 'body') return [documentBody];
      if (lowered === 'html') return [documentElement];
      return [];
    },
    getElementsByClassName() { return []; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
  };
  documentElement.ownerDocument = sandbox.document;
  documentHead.ownerDocument = sandbox.document;
  documentBody.ownerDocument = sandbox.document;
  documentElement.appendChild(documentHead);
  documentElement.appendChild(documentBody);
  Object.defineProperty(sandbox.document, 'cookie', { get() { return cookieJar.get(); }, set(value) { cookieJar.set(value); } });

  sandbox.localStorage = new MiniStorage(profile.localStorage || {});
  sandbox.sessionStorage = new MiniStorage(profile.sessionStorage || {});
  sandbox.chrome = profile.chrome || { runtime: {}, app: {}, csi() { return {}; }, loadTimes() { return {}; } };
  sandbox.history = { length: Number(profile.historyLength || 2), pushState() {}, replaceState() {} };
  sandbox.Image = class Image {
    constructor() { this.onload = null; this.onerror = null; this.width = 0; this.height = 0; attachEventTarget(this, 'image'); }
    set src(value) {
      this._src = String(value);
      capture('image', this._src, { method: 'GET' });
      setTimeout(() => {
        const ev = new MiniEvent('load', { target: this });
        if (typeof this.dispatchEvent === 'function') this.dispatchEvent(ev);
        else if (typeof this.onload === 'function') safeCall(this.onload, this, [ev], 'image.onload');
      }, 0);
    }
    get src() { return this._src || ''; }
  };
  sandbox.XMLHttpRequest = class XMLHttpRequest {
    constructor() { this.headers = {}; this.readyState = 0; this.status = 204; this.responseText = ''; this.onreadystatechange = null; this.onload = null; attachEventTarget(this, 'xhr'); }
    open(method, url) { this.method = String(method || 'GET').toUpperCase(); this.url = String(url); this.readyState = 1; }
    setRequestHeader(key, value) { this.headers[String(key).toLowerCase()] = String(value); }
    getAllResponseHeaders() { return ''; }
    send(body = null) {
      capture('xhr', this.url || '', { method: this.method || 'GET', headers: this.headers, body });
      this.readyState = 4;
      const readyEvent = new MiniEvent('readystatechange', { target: this });
      const loadEvent = new MiniEvent('load', { target: this });
      if (typeof this.onreadystatechange === 'function') safeCall(this.onreadystatechange, this, [readyEvent], 'xhr.onreadystatechange');
      if (typeof this.dispatchEvent === 'function') this.dispatchEvent(readyEvent);
      if (typeof this.dispatchEvent === 'function') this.dispatchEvent(loadEvent);
      else if (typeof this.onload === 'function') safeCall(this.onload, this, [loadEvent], 'xhr.onload');
    }
  };
  sandbox.Worker = class Worker {
    constructor(url, options = {}) {
      this.url = String(url);
      this.name = String(options.name || '');
      this.type = String(options.type || 'classic');
      this.onmessage = null;
      this.onerror = null;
      this._closed = false;
      attachEventTarget(this, 'worker');
      capture('worker', this.url, { method: 'GET' });
      const source = objectUrls.get(this.url);
      if (source && typeof source.textSync === 'function') {
        const worker = this;
        const workerSandbox = {
          console: sandbox.console,
          Date, Math, JSON, URL: SandboxURL, URLSearchParams, Error, TypeError, Promise,
          Array, Object, String, Number, Boolean, RegExp, Function, Symbol, Map, Set, WeakMap, WeakSet,
          Uint8Array, Uint8ClampedArray, Uint16Array, Uint32Array, Int8Array, Int16Array, Int32Array, Float32Array, Float64Array, ArrayBuffer, DataView,
          TextEncoder, TextDecoder,
          Blob: MiniBlob,
          File: MiniFile,
          crypto: webcrypto,
          setTimeout, clearTimeout, setInterval, clearInterval, setImmediate: setImmediateCompat, clearImmediate: clearImmediateCompat,
          queueMicrotask: queueMicrotaskCompat,
          postMessage(data) {
            if (worker._closed) return;
            setTimeout(() => {
              const ev = new MiniEvent('message', { data, source: worker });
              if (typeof worker.onmessage === 'function') {
                try { worker.onmessage.call(worker, ev); } catch (e) { errors.push({ type: 'worker-onmessage-error', message: e && e.message }); }
              }
              try { worker.dispatchEvent(ev); } catch (e) { errors.push({ type: 'worker-dispatch-error', message: e && e.message }); }
            }, 0);
          },
          close() { worker._closed = true; },
          onmessage: null,
          self: null,
        };
        workerSandbox.self = workerSandbox;
        workerSandbox.globalThis = workerSandbox;
        this._workerContext = vm.createContext(workerSandbox);
        try { vm.runInContext(source.textSync(), this._workerContext, { timeout: Math.min(1000, opts.vmTimeoutMs), filename: this.url }); } catch (e) { errors.push({ type: 'worker-eval-error', message: e && e.message ? e.message : String(e) }); }
      }
    }
    postMessage(data) {
      if (this._closed) return;
      if (this._workerContext && typeof this._workerContext.onmessage === 'function') {
        try { this._workerContext.onmessage.call(this._workerContext, new MiniEvent('message', { data, source: sandbox.window })); } catch (e) { errors.push({ type: 'worker-message-error', message: e && e.message ? e.message : String(e) }); }
      }
    }
    terminate() { this._closed = true; }
  };
  sandbox.SharedWorker = class SharedWorker {
    constructor(url, options = {}) {
      this.port = attachEventTarget({ postMessage(data) { messages.push({ data, origin: 'shared-worker', at: Date.now() }); }, start() {}, close() {} }, 'shared-worker-port');
      this.url = String(url);
      this.name = String(options.name || '');
      capture('shared-worker', this.url, { method: 'GET' });
    }
  };
  sandbox.MutationObserver = class MutationObserver { constructor(cb) { this.cb = cb; } observe() {} disconnect() {} takeRecords() { return []; } };
  sandbox.IntersectionObserver = class IntersectionObserver { constructor(cb) { this.cb = cb; } observe() {} unobserve() {} disconnect() {} };
  return sandbox;
}

async function solve(input) {
  const opts = normalize(input || {});
  if (!opts.script.trim()) throw new Error('DataDome tag VM requires non-empty script');
  const sandbox = makeSandbox(opts);
  const context = vm.createContext(sandbox);
  vm.runInContext(opts.script, context, { timeout: opts.vmTimeoutMs, filename: opts.scriptUrl });

  for (const ev of ['DOMContentLoaded', 'load', 'visibilitychange']) {
    try { context.dispatchEvent(new MiniEvent(ev)); } catch (e) { context.__ddErrors.push({ type: 'dispatch-error', event: ev, message: e && e.message }); }
  }
  await new Promise(resolve => setTimeout(resolve, Math.max(0, opts.settleMs)));

  return {
    requests: context.__ddRequests,
    events: context.__ddEvents,
    messages: context.__ddMessages,
    errors: context.__ddErrors,
    cookies: context.__ddCookieJar.toJSON(),
    cookie: context.document.cookie,
    diagnostics: {
      scriptUrl: opts.scriptUrl,
      pageUrl: opts.pageUrl,
      endpointUrl: opts.endpointUrl,
      requestCount: context.__ddRequests.length,
      eventCount: context.__ddEvents.length,
      messageCount: context.__ddMessages.length,
      errorCount: context.__ddErrors.length,
      hasDatadomeCookie: Object.prototype.hasOwnProperty.call(context.__ddCookieJar.toJSON(), 'datadome'),
      ddOptionsKeys: context.ddoptions && typeof context.ddoptions === 'object' ? Object.keys(context.ddoptions).slice(0, 60) : [],
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
