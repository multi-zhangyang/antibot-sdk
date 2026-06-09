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

function normalize(input) {
  const pageUrl = input.page_url || input.pageUrl || input.url || 'https://target.example/';
  const scriptUrl = input.script_url || input.scriptUrl || new URL('/challenge.js', pageUrl).href;
  return {
    script: String(input.script || ''),
    scriptUrl,
    pageUrl,
    cookie: String(input.cookie || ''),
    profile: input.profile && typeof input.profile === 'object' ? input.profile : {},
    config: input.config && typeof input.config === 'object' ? input.config : {},
    resources: input.resources && typeof input.resources === 'object' ? input.resources : {},
    settleMs: Number(input.settle_ms || input.settleMs || 120),
    vmTimeoutMs: Number(input.vm_timeout_ms || input.vmTimeoutMs || 10000),
  };
}

function toBuffer(value) {
  if (value == null) return Buffer.alloc(0);
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof ArrayBuffer) return Buffer.from(new Uint8Array(value));
  if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  if (value && typeof value.textSync === 'function') return Buffer.from(value.textSync(), 'utf8');
  return Buffer.from(String(value), 'utf8');
}

function bytesToText(value) { return toBuffer(value).toString('utf8'); }

function encodeFormValue(value) {
  if (value && typeof value === 'object' && typeof value.textSync === 'function') return value.textSync();
  if (value == null) return '';
  return bytesToText(value);
}

class MiniBlob {
  constructor(parts = [], opts = {}) {
    this.parts = Array.isArray(parts) ? parts.slice() : [parts];
    this.type = String(opts.type || '').toLowerCase();
    this.size = this.parts.reduce((n, part) => n + toBuffer(part).length, 0);
  }
  textSync() { return Buffer.concat(this.parts.map(part => toBuffer(part))).toString('utf8'); }
  async text() { return this.textSync(); }
  async arrayBuffer() {
    const buf = Buffer.concat(this.parts.map(part => toBuffer(part)));
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  slice(start = 0, end = this.size, type = this.type) {
    const buf = Buffer.concat(this.parts.map(part => toBuffer(part))).subarray(Number(start) || 0, end == null ? this.size : Number(end));
    return new MiniBlob([buf], { type });
  }
  stream() {
    const payload = new Uint8Array(toBuffer(this.textSync()));
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
      try {
        for (const item of init) {
          if (Array.isArray(item) && item.length >= 2) this.append(item[0], item[1], item[2]);
        }
      } catch (_) {}
    }
  }
  append(key, value, filename = undefined) { this.items.push([String(key), value, filename == null ? undefined : String(filename)]); }
  set(key, value, filename = undefined) { this.delete(key); this.append(key, value, filename); }
  delete(key) { this.items = this.items.filter(item => item[0] !== String(key)); }
  get(key) { const hit = this.items.find(item => item[0] === String(key)); return hit ? hit[1] : null; }
  getAll(key) { return this.items.filter(item => item[0] === String(key)).map(item => item[1]); }
  has(key) { return this.items.some(item => item[0] === String(key)); }
  entries() { return this.items.map(([key, value]) => [key, value])[Symbol.iterator](); }
  keys() { return this.items.map(([key]) => key)[Symbol.iterator](); }
  values() { return this.items.map(([, value]) => value)[Symbol.iterator](); }
  forEach(cb, thisArg = undefined) { for (const [key, value] of this.items) cb.call(thisArg, value, key, this); }
  toString() {
    return this.items
      .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(encodeFormValue(value))}`)
      .join('&');
  }
  [Symbol.iterator]() { return this.entries(); }
  get [Symbol.toStringTag]() { return 'FormData'; }
}

class MiniHeaders {
  constructor(init = {}) {
    this.map = new Map();
    if (init instanceof MiniHeaders) {
      for (const [key, value] of init.entries()) this.set(key, value);
    } else if (Array.isArray(init)) {
      for (const item of init) this.set(item[0], item[1]);
    } else if (init && typeof init[Symbol.iterator] === 'function' && typeof init !== 'string') {
      try { for (const item of init) this.set(item[0], item[1]); } catch (_) {}
    } else if (init && typeof init === 'object') {
      for (const [key, value] of Object.entries(init)) this.set(key, value);
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
  forEach(cb, thisArg = undefined) { for (const [key, value] of this.map.entries()) cb.call(thisArg, value, key, this); }
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
    for (const [key, value] of Object.entries(input)) out[String(key).toLowerCase()] = String(value);
    return out;
  }
  return {};
}

function serializeBody(body) {
  if (body == null) return null;
  if (typeof body === 'string') return body;
  if (body instanceof URLSearchParams) return body.toString();
  if (body instanceof MiniFormData) return body.toString();
  if (body instanceof MiniBlob) return body.textSync();
  if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return bytesToText(body);
  if (body && typeof body === 'object') {
    if (typeof body.textSync === 'function') return body.textSync();
    if (typeof body.toString === 'function' && body.toString !== Object.prototype.toString) return String(body);
    try { return JSON.stringify(body); } catch (_) {}
  }
  return String(body);
}

class MiniRequest {
  constructor(input, init = {}) {
    if (input instanceof MiniRequest) {
      this.url = input.url;
      this.method = String(init.method || input.method || 'GET').toUpperCase();
      this.headers = new MiniHeaders(init.headers || input.headers || {});
      this.body = init.body !== undefined ? init.body : input.body;
    } else {
      this.url = String(input || '');
      this.method = String(init.method || 'GET').toUpperCase();
      this.headers = new MiniHeaders(init.headers || {});
      this.body = init.body ?? null;
    }
  }
  clone() { return new MiniRequest(this); }
  async text() { return serializeBody(this.body) || ''; }
  async json() { return JSON.parse(await this.text()); }
}

class MiniResponse {
  constructor(body = '', init = {}) {
    this.status = Number(init.status || 200);
    this.statusText = String(init.statusText || 'OK');
    this.ok = this.status >= 200 && this.status < 300;
    this.headers = new MiniHeaders(init.headers || { 'content-type': 'application/json' });
    this._body = body;
  }
  async text() { return serializeBody(this._body) || ''; }
  async json() { const text = await this.text(); return text ? JSON.parse(text) : {}; }
  async arrayBuffer() {
    const buf = toBuffer(await this.text());
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }
  clone() { return new MiniResponse(this._body, { status: this.status, statusText: this.statusText, headers: this.headers }); }
}

class MiniEvent {
  constructor(type, init = {}) {
    this.type = String(type || '');
    this.bubbles = !!init.bubbles;
    this.cancelable = !!init.cancelable;
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

function createLocation(url) {
  const current = new URL(url);
  const loc = {
    assign(next) { current.href = new URL(String(next), current.href).href; },
    replace(next) { current.href = new URL(String(next), current.href).href; },
    reload() {},
    toString() { return current.href; },
  };
  for (const prop of ['href', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash', 'origin']) {
    Object.defineProperty(loc, prop, {
      enumerable: true,
      get() { return current[prop]; },
      set(value) {
        if (prop === 'origin') return;
        current[prop] = String(value);
      },
    });
  }
  return loc;
}

function makeSandbox(opts) {
  const requests = [];
  const messages = [];
  const events = [];
  const errors = [];
  const performanceEntries = [];
  const performanceObservers = new Set();
  const objectUrls = new Map();
  const timers = new Map();
  const documentScripts = [];
  const cookieJar = makeCookieJar(opts.cookie || opts.profile.cookie || '');
  const page = new URL(opts.pageUrl);
  const scriptUrl = new URL(opts.scriptUrl, page.href).href;
  const hrOrigin = process.hrtime.bigint();
  const timeOrigin = Date.now();
  let rafSeq = 1;
  let blobSeq = 1;
  let sandbox;

  function nowMs() { return Number((process.hrtime.bigint() - hrOrigin) / 1000000n); }
  function safeCall(cb, thisArg, args = [], source = 'callback') {
    if (typeof cb !== 'function') return undefined;
    try { return cb.apply(thisArg, args); } catch (error) {
      errors.push({ type: 'callback-error', source, message: error && error.message ? error.message : String(error) });
      return undefined;
    }
  }
  function resolveUrl(url) {
    try { return new URL(String(url), page.href).href; } catch (_) { return String(url); }
  }
  function notifyPerformance(kind, url) {
    const entry = {
      name: url,
      entryType: kind === 'navigation' ? 'navigation' : 'resource',
      startTime: nowMs(),
      duration: 1,
      initiatorType: kind,
      nextHopProtocol: 'h2',
      transferSize: 0,
      encodedBodySize: 0,
      decodedBodySize: 0,
    };
    performanceEntries.push(entry);
    for (const observer of performanceObservers) {
      if (!observer.options || !observer.options.entryTypes || observer.options.entryTypes.includes(entry.entryType)) {
        setTimeout(() => safeCall(observer.callback, observer.instance, [{ getEntries: () => [entry], getEntriesByType: type => entry.entryType === type ? [entry] : [] }, observer.instance], 'PerformanceObserver'), 0);
      }
    }
  }
  function capture(kind, url, init = {}) {
    const requestUrl = resolveUrl(url && url.url ? url.url : url);
    const method = String(init.method || (url && url.method) || 'GET').toUpperCase();
    const headers = headersToObject(init.headers || (url && url.headers) || {});
    const body = serializeBody(init.body !== undefined ? init.body : (url && url.body));
    const item = { kind, url: requestUrl, method, headers, body, at: Date.now() };
    requests.push(item);
    notifyPerformance(kind, requestUrl);
    return item;
  }
  function setImmediateCompat(cb, ...args) {
    const id = setTimeout(() => safeCall(cb, sandbox, args, 'setImmediate'), 0);
    timers.set(id, true);
    return id;
  }
  function clearImmediateCompat(id) { clearTimeout(id); timers.delete(id); }
  function queueMicrotaskCompat(cb) { Promise.resolve().then(() => safeCall(cb, sandbox, [], 'queueMicrotask')); }
  function requestAnimationFrameCompat(cb) {
    const id = rafSeq++;
    const timer = setTimeout(() => {
      timers.delete(id);
      safeCall(cb, sandbox, [nowMs()], 'requestAnimationFrame');
    }, 16);
    timers.set(id, timer);
    return id;
  }
  function cancelAnimationFrameCompat(id) {
    const timer = timers.get(id);
    if (timer) clearTimeout(timer);
    timers.delete(id);
  }
  function attachEventTarget(target, label = 'target') {
    const listeners = new Map();
    Object.defineProperty(target, '__listeners', { value: listeners, enumerable: false, configurable: true });
    target.addEventListener = function addEventListener(type, cb) {
      const key = String(type || '');
      if (!listeners.has(key)) listeners.set(key, []);
      listeners.get(key).push(cb);
      events.push({ type: 'listen', label, event: key, at: Date.now() });
    };
    target.removeEventListener = function removeEventListener(type, cb) {
      const key = String(type || '');
      if (!listeners.has(key)) return;
      listeners.set(key, listeners.get(key).filter(item => item !== cb));
    };
    target.dispatchEvent = function dispatchEvent(event) {
      const ev = typeof event === 'string' ? new MiniEvent(event) : event;
      ev.target = ev.target || target;
      ev.currentTarget = target;
      events.push({ type: 'dispatch', label, event: ev.type, at: Date.now() });
      for (const cb of listeners.get(ev.type) || []) safeCall(cb, target, [ev], `${label}.${ev.type}`);
      const handler = target[`on${ev.type}`];
      if (typeof handler === 'function') safeCall(handler, target, [ev], `${label}.on${ev.type}`);
      return !ev.defaultPrevented;
    };
    return target;
  }

  class MiniElement {
    constructor(tagName = 'div') {
      this.tagName = String(tagName || 'div').toUpperCase();
      this.nodeName = this.tagName;
      this.nodeType = 1;
      this.children = [];
      this.childNodes = this.children;
      this.attributes = {};
      this.style = {};
      this.parentNode = null;
      this.ownerDocument = null;
      this.textContent = '';
      this.innerHTML = '';
      this.onload = null;
      this.onerror = null;
      attachEventTarget(this, `element:${this.tagName.toLowerCase()}`);
    }
    get src() { return this._src || this.attributes.src || ''; }
    set src(value) {
      this._src = String(value || '');
      this.attributes.src = this._src;
      if (this.parentNode && String(this.tagName || '').toLowerCase() === 'script') {
        if (!documentScripts.includes(this)) documentScripts.push(this);
        if (this._src) this._loadScript();
      }
    }
    setAttribute(key, value) { this.attributes[String(key)] = String(value); if (String(key).toLowerCase() === 'src') this.src = String(value); }
    getAttribute(key) { return this.attributes[String(key)] ?? null; }
    removeAttribute(key) { delete this.attributes[String(key)]; }
    _normalizeChild(child) {
      if (typeof child === 'string' || typeof child === 'number' || typeof child === 'boolean') {
        return { nodeType: 3, textContent: String(child), ownerDocument: this.ownerDocument, parentNode: null };
      }
      return child;
    }
    _loadScript() {
      const url = this.src;
      if (!url) return;
      const resolved = resolveUrl(url);
      capture('script', resolved, { method: 'GET' });
      const source = opts.resources[url] || opts.resources[resolved] || '';
      if (source) {
        try { vm.runInContext(String(source), sandbox.__context, { timeout: Math.min(1000, opts.vmTimeoutMs), filename: resolved }); }
        catch (error) { errors.push({ type: 'script-resource-error', url: resolved, message: error && error.message ? error.message : String(error) }); }
      }
      setTimeout(() => this.dispatchEvent(new MiniEvent('load', { target: this })), 0);
    }
    _insertChild(child, index = this.children.length) {
      child = this._normalizeChild(child);
      if (child && typeof child === 'object') {
        child.parentNode = this;
        if (child.ownerDocument == null) child.ownerDocument = this.ownerDocument;
        const pos = Math.max(0, Math.min(Number(index), this.children.length));
        this.children.splice(pos, 0, child);
        if (String(child.tagName || '').toLowerCase() === 'script' && child.src) {
          if (!documentScripts.includes(child)) documentScripts.push(child);
          child._loadScript();
        }
      }
      return child;
    }
    appendChild(child) { return this._insertChild(child); }
    append(...nodes) { for (const node of nodes) this.appendChild(node); }
    prepend(...nodes) {
      let index = 0;
      for (const node of nodes) this._insertChild(node, index++);
    }
    insertBefore(child, reference = null) {
      const index = reference ? this.children.indexOf(reference) : -1;
      return this._insertChild(child, index >= 0 ? index : this.children.length);
    }
    replaceChild(child, oldChild) {
      const index = this.children.indexOf(oldChild);
      if (index < 0) throw new Error('replaceChild target is not a child');
      this.removeChild(oldChild);
      this._insertChild(child, index);
      return oldChild;
    }
    removeChild(child) {
      this.children = this.children.filter(item => item !== child);
      const scriptIndex = documentScripts.indexOf(child);
      if (scriptIndex >= 0) documentScripts.splice(scriptIndex, 1);
      if (child && typeof child === 'object') child.parentNode = null;
      return child;
    }
    remove() { if (this.parentNode && this.parentNode.removeChild) this.parentNode.removeChild(this); }
    querySelector() { return null; }
    querySelectorAll() { return []; }
    getBoundingClientRect() { return { x: 0, y: 0, top: 0, left: 0, right: 1, bottom: 1, width: 1, height: 1 }; }
  }

  const documentElement = new MiniElement('html');
  const head = new MiniElement('head');
  const body = new MiniElement('body');
  const currentScript = new MiniElement('script');
  currentScript.src = scriptUrl;
  const document = attachEventTarget({
    nodeType: 9,
    readyState: 'complete',
    visibilityState: 'visible',
    hidden: false,
    referrer: '',
    title: '',
    characterSet: 'UTF-8',
    compatMode: 'CSS1Compat',
    documentElement,
    head,
    body,
    currentScript,
    scripts: documentScripts,
    location: null,
    hasFocus() { return true; },
    createElement(tagName) { const el = new MiniElement(tagName); el.ownerDocument = document; return el; },
    createTextNode(text) { return { nodeType: 3, textContent: String(text), ownerDocument: document }; },
    getElementById() { return null; },
    getElementsByTagName(tagName) {
      const lowered = String(tagName || '').toLowerCase();
      if (lowered === 'script') return documentScripts.slice();
      if (lowered === 'head') return [head];
      if (lowered === 'body') return [body];
      if (lowered === 'html') return [documentElement];
      return [];
    },
    querySelector(selector) {
      const lowered = String(selector || '').toLowerCase();
      if (lowered === 'script') return documentScripts[0] || currentScript;
      if (lowered === 'head') return head;
      if (lowered === 'body') return body;
      if (lowered === 'html' || lowered === ':root') return documentElement;
      return null;
    },
    querySelectorAll(selector) {
      if (String(selector || '').toLowerCase() === 'script') return documentScripts.slice();
      const hit = this.querySelector(selector);
      return hit ? [hit] : [];
    },
  }, 'document');
  documentElement.ownerDocument = document;
  head.ownerDocument = document;
  body.ownerDocument = document;
  currentScript.ownerDocument = document;
  documentScripts.push(currentScript);
  documentElement.appendChild(head);
  documentElement.appendChild(body);
  Object.defineProperty(document, 'cookie', { enumerable: true, get() { return cookieJar.get(); }, set(value) { cookieJar.set(value); } });

  const location = createLocation(opts.pageUrl);
  document.location = location;

  const performance = {
    timeOrigin,
    now: nowMs,
    timing: { navigationStart: timeOrigin, domLoading: timeOrigin + 1, domComplete: timeOrigin + 10, loadEventEnd: timeOrigin + 20 },
    navigation: { type: 0, redirectCount: 0 },
    mark(name) { performanceEntries.push({ name: String(name), entryType: 'mark', startTime: nowMs(), duration: 0 }); },
    measure(name) { performanceEntries.push({ name: String(name), entryType: 'measure', startTime: nowMs(), duration: 0 }); },
    getEntries() { return performanceEntries.slice(); },
    getEntriesByType(type) { return performanceEntries.filter(entry => entry.entryType === String(type)); },
    getEntriesByName(name) { return performanceEntries.filter(entry => entry.name === String(name)); },
    clearMarks() {},
    clearMeasures() {},
  };
  performanceEntries.push({ name: opts.pageUrl, entryType: 'navigation', startTime: 0, duration: 1, initiatorType: 'navigation' });

  class MiniPerformanceObserver {
    constructor(callback) { this.callback = callback; this.options = null; this.instance = this; }
    observe(options = {}) {
      this.options = options;
      performanceObservers.add(this);
      const buffered = options.buffered ? performanceEntries.filter(entry => !options.entryTypes || options.entryTypes.includes(entry.entryType)) : [];
      if (buffered.length) setTimeout(() => safeCall(this.callback, this, [{ getEntries: () => buffered, getEntriesByType: type => buffered.filter(entry => entry.entryType === type) }, this], 'PerformanceObserver.buffered'), 0);
    }
    disconnect() { performanceObservers.delete(this); }
    takeRecords() { return []; }
    static supportedEntryTypes = ['navigation', 'resource', 'mark', 'measure'];
  }

  class MiniXMLHttpRequest {
    constructor() {
      this.method = 'GET';
      this.url = '';
      this.headers = {};
      this.readyState = 0;
      this.status = 200;
      this.statusText = 'OK';
      this.responseText = '{}';
      this.response = this.responseText;
      this.onreadystatechange = null;
      this.onload = null;
      attachEventTarget(this, 'xhr');
    }
    open(method, url) { this.method = String(method || 'GET').toUpperCase(); this.url = String(url || ''); this.readyState = 1; }
    setRequestHeader(key, value) { this.headers[String(key).toLowerCase()] = String(value); }
    getResponseHeader() { return null; }
    getAllResponseHeaders() { return ''; }
    send(body = null) {
      capture('xhr', this.url, { method: this.method, headers: this.headers, body });
      this.readyState = 4;
      this.dispatchEvent(new MiniEvent('readystatechange', { target: this }));
      this.dispatchEvent(new MiniEvent('load', { target: this }));
    }
    abort() { this.readyState = 0; }
  }

  class MiniImage extends MiniElement {
    constructor() { super('img'); this.width = 0; this.height = 0; }
    set src(value) { this._src = String(value || ''); if (this._src) { capture('image', this._src, { method: 'GET' }); setTimeout(() => this.dispatchEvent(new MiniEvent('load', { target: this })), 0); } }
    get src() { return this._src || ''; }
  }

  const navigator = {
    userAgent: opts.profile.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    appCodeName: 'Mozilla',
    appName: 'Netscape',
    appVersion: '5.0',
    platform: opts.profile.platform || 'Win32',
    product: 'Gecko',
    vendor: 'Google Inc.',
    language: opts.profile.language || 'en-US',
    languages: opts.profile.languages || ['en-US', 'en'],
    cookieEnabled: true,
    onLine: true,
    hardwareConcurrency: Number(opts.profile.hardwareConcurrency || 8),
    deviceMemory: Number(opts.profile.deviceMemory || 8),
    maxTouchPoints: Number(opts.profile.maxTouchPoints || 0),
    webdriver: false,
    connection: { effectiveType: '4g', rtt: 50, downlink: 10, saveData: false, type: 'wifi' },
    permissions: { async query() { return { state: 'prompt', onchange: null }; } },
    mediaDevices: { async enumerateDevices() { return []; }, getUserMedia() { return Promise.reject(new Error('not available')); } },
    sendBeacon(url, body = null) { capture('beacon', url, { method: 'POST', body }); return true; },
  };

  function postMessage(data, targetOrigin = '*') {
    messages.push({ data: toPlain(data), targetOrigin: String(targetOrigin), at: Date.now() });
    const ev = new MiniEvent('message', { data, origin: page.origin, source: sandbox });
    setTimeout(() => sandbox.dispatchEvent(ev), 0);
  }

  const SandboxURL = class extends URL {
    static createObjectURL(blob) {
      const id = `blob:${page.origin}/awswaf-${blobSeq++}`;
      objectUrls.set(id, blob);
      return id;
    }
    static revokeObjectURL(url) { objectUrls.delete(String(url)); }
  };

  sandbox = attachEventTarget({
    console,
    Date, Math, JSON, URL: SandboxURL, URLSearchParams, Error, TypeError, SyntaxError, Promise,
    Array, Object, String, Number, Boolean, RegExp, Function, Symbol, Map, Set, WeakMap, WeakSet,
    Uint8Array, Uint8ClampedArray, Uint16Array, Uint32Array, Int8Array, Int16Array, Int32Array, Float32Array, Float64Array, ArrayBuffer, DataView,
    TextEncoder, TextDecoder,
    Blob: MiniBlob,
    File: MiniFile,
    FormData: MiniFormData,
    Headers: MiniHeaders,
    Request: MiniRequest,
    Response: MiniResponse,
    Event: MiniEvent,
    MessageEvent: MiniEvent,
    Image: MiniImage,
    XMLHttpRequest: MiniXMLHttpRequest,
    crypto: webcrypto,
    msCrypto: webcrypto,
    location,
    document,
    navigator,
    screen: { width: 1920, height: 1080, availWidth: 1920, availHeight: 1040, colorDepth: 24, pixelDepth: 24, orientation: { type: 'landscape-primary', angle: 0 } },
    innerWidth: 1920,
    innerHeight: 963,
    outerWidth: 1920,
    outerHeight: 1080,
    devicePixelRatio: 1,
    performance,
    PerformanceObserver: MiniPerformanceObserver,
    localStorage: new MiniStorage(opts.profile.localStorage || {}),
    sessionStorage: new MiniStorage(opts.profile.sessionStorage || {}),
    history: { length: 2, scrollRestoration: 'auto', pushState() {}, replaceState() {}, back() {}, forward() {}, go() {} },
    chrome: { runtime: {}, app: {}, csi() { return {}; }, loadTimes() { return {}; } },
    atob: atobCompat,
    btoa: btoaCompat,
    setTimeout, clearTimeout, setInterval, clearInterval,
    setImmediate: setImmediateCompat,
    clearImmediate: clearImmediateCompat,
    queueMicrotask: queueMicrotaskCompat,
    requestAnimationFrame: requestAnimationFrameCompat,
    cancelAnimationFrame: cancelAnimationFrameCompat,
    getComputedStyle() { return { display: 'block', visibility: 'visible', opacity: '1', getPropertyValue(name) { return this[String(name || '').replace(/-([a-z])/g, (_, c) => c.toUpperCase())] || ''; } }; },
    matchMedia(query) { return attachEventTarget({ matches: !/max-width:\s*[0-9]+px/.test(String(query)), media: String(query), onchange: null }, 'media-query'); },
    fetch(input, init = {}) {
      const req = input instanceof MiniRequest ? input : new MiniRequest(input, init);
      if (init && Object.keys(init).length) {
        if (init.method) req.method = String(init.method).toUpperCase();
        if (init.headers) req.headers = new MiniHeaders(init.headers);
        if (init.body !== undefined) req.body = init.body;
      }
      capture('fetch', req.url, { method: req.method, headers: req.headers, body: req.body });
      return Promise.resolve(new MiniResponse('{}'));
    },
    postMessage,
    close() {},
    open() { return null; },
    MutationObserver: class MutationObserver { constructor(cb) { this.cb = cb; } observe() {} disconnect() {} takeRecords() { return []; } },
    IntersectionObserver: class IntersectionObserver { constructor(cb) { this.cb = cb; } observe() {} unobserve() {} disconnect() {} takeRecords() { return []; } },
    ResizeObserver: class ResizeObserver { constructor(cb) { this.cb = cb; } observe() {} unobserve() {} disconnect() {} },
    __awsWafRequests: requests,
    __awsWafMessages: messages,
    __awsWafEvents: events,
    __awsWafErrors: errors,
    __awsWafCookieJar: cookieJar,
    __awsWafObjectUrls: objectUrls,
    __awsWafPerformanceEntries: performanceEntries,
    __awsWafConfig: opts.config,
    __context: null,
  }, 'window');
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.top = sandbox;
  sandbox.parent = sandbox;
  sandbox.frames = sandbox;
  sandbox.opener = { postMessage };
  document.defaultView = sandbox;
  return sandbox;
}

const BUILTIN_GLOBALS = new Set([
  'console', 'Date', 'Math', 'JSON', 'URL', 'URLSearchParams', 'Error', 'TypeError', 'SyntaxError', 'Promise',
  'Array', 'Object', 'String', 'Number', 'Boolean', 'RegExp', 'Function', 'Symbol', 'Map', 'Set', 'WeakMap', 'WeakSet',
  'Uint8Array', 'Uint8ClampedArray', 'Uint16Array', 'Uint32Array', 'Int8Array', 'Int16Array', 'Int32Array', 'Float32Array', 'Float64Array', 'ArrayBuffer', 'DataView',
  'TextEncoder', 'TextDecoder', 'Blob', 'File', 'FormData', 'Headers', 'Request', 'Response', 'Event', 'MessageEvent',
  'Image', 'XMLHttpRequest', 'crypto', 'msCrypto', 'location', 'document', 'navigator', 'screen', 'performance', 'PerformanceObserver',
  'localStorage', 'sessionStorage', 'history', 'chrome', 'atob', 'btoa', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval',
  'setImmediate', 'clearImmediate', 'queueMicrotask', 'requestAnimationFrame', 'cancelAnimationFrame', 'getComputedStyle', 'matchMedia', 'fetch',
  'postMessage', 'close', 'open', 'MutationObserver', 'IntersectionObserver', 'ResizeObserver', 'window', 'self', 'globalThis', 'top', 'parent', 'frames', 'opener',
  '__awsWafRequests', '__awsWafMessages', '__awsWafEvents', '__awsWafErrors', '__awsWafCookieJar', '__awsWafObjectUrls', '__awsWafPerformanceEntries', '__awsWafConfig', '__context',
]);

function toPlain(value, depth = 3, seen = new WeakSet()) {
  if (value == null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.length > 5000 ? `${value.slice(0, 5000)}...<truncated>` : value;
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'function') return `[Function ${value.name || 'anonymous'}]`;
  if (depth <= 0) return '[Object]';
  if (typeof value === 'object') {
    if (seen.has(value)) return '[Circular]';
    seen.add(value);
    if (value instanceof URLSearchParams) return value.toString();
    if (value instanceof MiniFormData) return value.toString();
    if (value instanceof MiniBlob) return value.textSync();
    if (Array.isArray(value)) return value.slice(0, 80).map(item => toPlain(item, depth - 1, seen));
    const out = {};
    for (const key of Object.keys(value).slice(0, 120)) {
      if (key === 'window' || key === 'self' || key === 'globalThis' || key === 'top' || key === 'parent' || key === 'frames') continue;
      try { out[key] = toPlain(value[key], depth - 1, seen); } catch (_) {}
    }
    return out;
  }
  return String(value);
}

function pick(obj, names) {
  if (!obj || typeof obj !== 'object') return undefined;
  const entries = Object.entries(obj);
  for (const name of names) {
    const lowered = String(name).toLowerCase();
    for (const [key, value] of entries) if (String(key).toLowerCase() === lowered && value != null && value !== '') return value;
  }
  return undefined;
}

function looksInterestingKey(key) {
  return /(aws|waf|challenge|captcha|verify|config|goku|token|hmac|difficulty|memory|signal|crypto|type|region|checksum|telemetry)/i.test(String(key));
}

function looksInterestingObject(obj) {
  if (!obj || typeof obj !== 'object') return false;
  return Object.keys(obj).some(looksInterestingKey);
}

function tryJson(text) {
  const value = String(text || '').trim();
  if (!value || !['{', '['].includes(value[0])) return null;
  try { return JSON.parse(value); } catch (_) { return null; }
}

function parseQueryLike(text) {
  const value = String(text || '');
  if (!value.includes('=')) return null;
  try {
    const out = {};
    const params = new URLSearchParams(value);
    for (const [key, val] of params.entries()) {
      const parsed = tryJson(val);
      out[key] = parsed == null ? val : parsed;
    }
    return Object.keys(out).length ? out : null;
  } catch (_) { return null; }
}

function makeExtractor(script) {
  const extracted = { challenge: {}, crypto: {}, endpoints: [], endpoint_type: '', candidates: [] };
  const globalClues = [];
  const seenObjects = new WeakSet();
  const endpointSet = new Set();
  const candidatePaths = new Set();

  function addEndpoint(value) {
    if (!value || typeof value !== 'string') return;
    if (!/(verify|challenge|captcha|awswaf|token|sdk)/i.test(value)) return;
    endpointSet.add(value);
  }
  function addCandidate(path, value, source = 'object') {
    if (candidatePaths.has(path)) return;
    candidatePaths.add(path);
    const plain = toPlain(value, 3);
    const item = { path, source, value: plain };
    globalClues.push(item);
    if (extracted.candidates.length < 60) extracted.candidates.push(item);
  }
  function setChallengeField(name, value) {
    if (value == null || value === '') return;
    if (!extracted.challenge[name]) extracted.challenge[name] = String(value);
  }
  function setNumberField(name, value) {
    if (value == null || value === '') return;
    const num = Number(value);
    if (Number.isFinite(num) && !extracted[name]) extracted[name] = num;
  }
  function setStringField(name, value) {
    if (value == null || value === '') return;
    if (!extracted[name]) extracted[name] = String(value);
  }
  function setChallengeType(value) {
    if (value == null || value === '' || extracted.challenge_type) return;
    const text = String(value);
    const match = text.match(/((?:ha9faaffd|h72f957df|h7b0c470f)[0-9a-f]{8,})/i);
    if (match) extracted.challenge_type = match[1];
  }
  function normalizeEndpointType(value) {
    if (value == null || value === '') return '';
    const text = String(value).trim().toLowerCase();
    if (text === 'mp_verify' || text === 'mpverify' || text === 'multi_page_verify') return 'mp_verify';
    if (text === 'verify') return 'verify';
    return '';
  }
  function setEndpointType(value) {
    const normalized = normalizeEndpointType(value);
    if (normalized && !extracted.endpoint_type) extracted.endpoint_type = normalized;
  }
  function setCryptoField(name, value) {
    if (value == null || value === '') return;
    if (!extracted.crypto[name]) extracted.crypto[name] = typeof value === 'object' ? toPlain(value, 4) : String(value);
  }
  function considerText(text, path) {
    const value = String(text || '');
    if (!value) return;
    for (const match of value.matchAll(/https?:\/\/[^\s'"<>]+|\/(?:[^\s'"<>]*?)(?:mp_verify|verify|challenge|captcha|token)[^\s'"<>]*/gi)) addEndpoint(match[0]);
    if (!extracted.challenge.input) {
      const m = value.match(/(?:^|[^A-Za-z0-9+/=])(eyJ[A-Za-z0-9+/=]{20,})(?=$|[^A-Za-z0-9+/=])/);
      if (m) setChallengeField('input', m[1]);
    }
    if (!extracted.challenge_type) {
      const m = value.match(/\b((?:ha9faaffd|h72f957df|h7b0c470f)[0-9a-f]{8,})\b/i);
      if (m) setChallengeType(m[1]);
    }
    const parsed = tryJson(value) || parseQueryLike(value);
    if (parsed) considerObject(parsed, `${path}:parsed`, 0);
  }
  function considerObject(obj, path, depth = 0) {
    if (!obj || typeof obj !== 'object') return;
    if (seenObjects.has(obj)) return;
    seenObjects.add(obj);
    const keys = Object.keys(obj);
    if (looksInterestingObject(obj)) addCandidate(path, obj);

    const challenge = pick(obj, ['challenge', 'Challenge', 'challengeDetails', 'challengeData']);
    if (challenge && typeof challenge === 'object') {
      setChallengeField('input', pick(challenge, ['input', 'Input', 'challengeInput']));
      setChallengeField('hmac', pick(challenge, ['hmac', 'Hmac']));
      setChallengeField('region', pick(challenge, ['region', 'Region']));
      addCandidate(`${path}.challenge`, challenge, 'challenge');
    }
    setChallengeField('input', pick(obj, ['input', 'Input', 'challengeInput']));
    setChallengeField('hmac', pick(obj, ['hmac', 'Hmac']));
    setChallengeField('region', pick(obj, ['region', 'Region']));
    setChallengeType(pick(obj, ['challenge_type', 'challengeType', 'challengeTypeHash', 'typeHash', 'typeName']));
    setNumberField('difficulty', pick(obj, ['difficulty', 'Difficulty', 'difficultyLevel']));
    setNumberField('memory', pick(obj, ['memory', 'Memory', 'scryptMemory', 'memoryCost']));
    setStringField('checksum', pick(obj, ['checksum', 'Checksum']));
    setEndpointType(pick(obj, ['endpoint_type', 'endpointType', 'verifyEndpointType']));

    const cryptoObj = pick(obj, ['crypto', 'Crypto', 'cryptoConfig', 'signalCrypto', 'encryption', 'awsWafEncryption']);
    if (cryptoObj && typeof cryptoObj === 'object') {
      setCryptoField('key', pick(cryptoObj, ['key', 'keyHex', 'key_hex', 'secret']));
      setCryptoField('identifier', pick(cryptoObj, ['identifier', 'name', 'signalIdentifier']));
      setCryptoField('signalVersion', pick(cryptoObj, ['signalVersion', 'signal_version', 'version']));
      setCryptoField('typeNames', pick(cryptoObj, ['typeNames', 'type_names']));
      addCandidate(`${path}.crypto`, cryptoObj, 'crypto');
    }
    setCryptoField('key', pick(obj, ['keyHex', 'key_hex', 'aesKeyHex']));
    setCryptoField('identifier', pick(obj, ['identifier', 'signalIdentifier', 'signalsIdentifier', 'encryptedSignalsName']));
    setCryptoField('signalVersion', pick(obj, ['signalVersion', 'signal_version', 'tVersion']));
    setCryptoField('typeNames', pick(obj, ['typeNames', 'type_names']));

    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') considerText(value, `${path}.${key}`);
      if (/endpoint|url|verify|challenge|captcha|token/i.test(key) && typeof value === 'string') addEndpoint(value);
      if (depth < 5 && value && typeof value === 'object' && !['window', 'self', 'globalThis', 'top', 'parent', 'frames'].includes(key)) {
        considerObject(value, `${path}.${key}`, depth + 1);
      }
    }
    for (const key of keys) if (looksInterestingKey(key) && typeof obj[key] !== 'object') addCandidate(`${path}.${key}`, { [key]: obj[key] });
  }
  function finalize() {
    considerText(script, 'script');
    extracted.endpoints = Array.from(endpointSet);
    extracted.endpoint_type = normalizeEndpointType(extracted.endpoint_type);
    if (!extracted.endpoint_type && extracted.crypto && typeof extracted.crypto.typeNames === 'object' && extracted.challenge_type) {
      setEndpointType(extracted.crypto.typeNames[extracted.challenge_type]);
    }
    if (!extracted.endpoint_type) {
      if (extracted.endpoints.some(url => /mp_verify/i.test(url))) extracted.endpoint_type = 'mp_verify';
      else if (extracted.endpoints.some(url => /verify/i.test(url))) extracted.endpoint_type = 'verify';
    }
    if (!extracted.endpoint_type && extracted.challenge_type) {
      if (/^(h7b0c470f|h72f957df)/i.test(extracted.challenge_type)) extracted.endpoint_type = 'verify';
      else if (/^ha9faaffd/i.test(extracted.challenge_type)) extracted.endpoint_type = 'mp_verify';
    }
    if (extracted.crypto && Object.keys(extracted.crypto).length === 0) delete extracted.crypto;
    return { extracted, globals: globalClues };
  }
  return { considerObject, considerText, finalize };
}

async function solve(input) {
  const opts = normalize(input || {});
  if (!opts.script.trim()) throw new Error('AWS WAF challenge VM requires non-empty script');
  const sandbox = makeSandbox(opts);
  const context = vm.createContext(sandbox);
  sandbox.__context = context;
  try {
    vm.runInContext(opts.script, context, { timeout: opts.vmTimeoutMs, filename: opts.scriptUrl });
  } catch (error) {
    context.__awsWafErrors.push({ type: 'eval-error', message: error && error.message ? error.message : String(error) });
  }
  for (const ev of ['DOMContentLoaded', 'readystatechange', 'load']) {
    try {
      context.document.dispatchEvent(new MiniEvent(ev));
      context.dispatchEvent(new MiniEvent(ev));
    } catch (error) {
      context.__awsWafErrors.push({ type: 'dispatch-error', event: ev, message: error && error.message ? error.message : String(error) });
    }
  }
  await new Promise(resolve => setTimeout(resolve, Math.max(0, opts.settleMs)));

  const extractor = makeExtractor(opts.script);
  for (const [key, value] of Object.entries(context)) {
    if (BUILTIN_GLOBALS.has(key)) continue;
    if (key.startsWith('__')) continue;
    if (typeof value === 'string') extractor.considerText(value, `global.${key}`);
    if (value && typeof value === 'object') extractor.considerObject(value, `global.${key}`);
    if (looksInterestingKey(key)) extractor.considerObject({ [key]: value }, `global.${key}`);
  }
  for (const request of context.__awsWafRequests) {
    extractor.considerObject(request, `request.${request.kind}`);
    extractor.considerText(request.url, `request.${request.kind}.url`);
    if (request.body) extractor.considerText(request.body, `request.${request.kind}.body`);
  }
  for (const message of context.__awsWafMessages) extractor.considerObject(message, 'postMessage');
  const { extracted, globals } = extractor.finalize();

  return {
    requests: context.__awsWafRequests,
    messages: context.__awsWafMessages,
    events: context.__awsWafEvents,
    errors: context.__awsWafErrors,
    cookies: context.__awsWafCookieJar.toJSON(),
    cookie: context.document.cookie,
    globals,
    extracted,
    diagnostics: {
      scriptUrl: opts.scriptUrl,
      pageUrl: opts.pageUrl,
      requestCount: context.__awsWafRequests.length,
      messageCount: context.__awsWafMessages.length,
      errorCount: context.__awsWafErrors.length,
      globalClueCount: globals.length,
      endpointType: extracted.endpoint_type || null,
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
