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
  const profile = opts.profile || {};
  const config = opts.config || {};
  const page = new URL(opts.pageUrl);
  const cookieJar = makeCookieJar(opts.cookie || profile.cookie || '');

  function capture(kind, url, options = {}) {
    const isRequest = url && typeof url === 'object' && typeof url.url === 'string';
    const rawUrl = isRequest ? url.url : String(url);
    const finalUrl = opts.endpointUrl && rawUrl.includes('__DATADOME_ENDPOINT__') ? opts.endpointUrl : rawUrl;
    const requestHeaders = isRequest ? headersToObject(url.headers || {}) : {};
    const optionHeaders = headersToObject(options.headers || {});
    const body = options.body ?? (isRequest ? url.body : null);
    const method = String(options.method || (isRequest ? url.method : '') || (body == null ? 'GET' : 'POST')).toUpperCase();
    const item = {
      kind,
      url: finalUrl,
      method,
      headers: { ...requestHeaders, ...optionHeaders },
      body: body == null ? null : String(body),
      at: Date.now(),
    };
    requests.push(item);
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

  const sandbox = {
    console: { log() {}, error() {}, warn() {}, info() {}, debug() {} },
    Date, Math, JSON, URL, URLSearchParams, Error, TypeError, Promise,
    Array, Object, String, Number, Boolean, RegExp, Function, Symbol, Map, Set, WeakMap, WeakSet,
    Uint8Array, Uint16Array, Uint32Array, Int8Array, Int16Array, Int32Array, ArrayBuffer, DataView,
    TextEncoder, TextDecoder,
    Event: MiniEvent,
    CustomEvent: MiniEvent,
    MessageEvent: MiniEvent,
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
    setTimeout, clearTimeout, setInterval, clearInterval,
    performance: { now: () => Number(process.hrtime.bigint() / 1000000n), timeOrigin: Date.now() },
    devicePixelRatio: Number(profile.devicePixelRatio || 1),
    innerWidth: Number(profile.innerWidth || profile.screen_width || 1920),
    innerHeight: Number(profile.innerHeight || profile.screen_height || 1080),
    outerWidth: Number(profile.outerWidth || profile.screen_width || 1920),
    outerHeight: Number(profile.outerHeight || profile.screen_height || 1080),
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
      permissions: { query: async () => ({ state: 'prompt' }) },
      sendBeacon(url, data = null) { capture('beacon', url, { method: 'POST', body: data }); return true; },
      userAgentData: profile.userAgentData || {
        brands: [{ brand: 'Chromium', version: '120' }, { brand: 'Google Chrome', version: '120' }, { brand: 'Not=A?Brand', version: '99' }],
        mobile: false,
        platform: profile.platform || 'Windows',
        getHighEntropyValues: async () => ({ architecture: 'x86', bitness: '64', mobile: false, model: '', platform: profile.platform || 'Windows', platformVersion: '10.0.0', uaFullVersion: '120.0.0.0', wow64: false }),
      },
    },
    screen: { width: Number(profile.screen_width || 1920), height: Number(profile.screen_height || 1080), colorDepth: 24, pixelDepth: 24 },
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
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.parent = sandbox;
  sandbox.top = sandbox;

  sandbox.document = {
    location: sandbox.location,
    URL: opts.pageUrl,
    documentURI: opts.pageUrl,
    referrer: profile.referrer || '',
    readyState: 'complete',
    hidden: false,
    visibilityState: 'visible',
    currentScript: { src: opts.scriptUrl },
    title: profile.title || '',
    body: { appendChild(child) { if (child && child.src) capture('element', child.src, { method: 'GET' }); if (typeof child.onload === 'function') setTimeout(() => child.onload(), 0); return child; }, removeChild() {} },
    head: { appendChild(child) { if (child && child.src) capture('element', child.src, { method: 'GET' }); if (typeof child.onload === 'function') setTimeout(() => child.onload(), 0); return child; }, removeChild() {} },
    documentElement: { appendChild() {} },
    addEventListener, removeEventListener, dispatchEvent,
    createElement(tag) {
      const lowered = String(tag || '').toLowerCase();
      const el = { tagName: lowered.toUpperCase(), style: {}, children: [], setAttribute(k, v) { this[k] = String(v); }, getAttribute(k) { return this[k] || null; }, appendChild(child) { this.children.push(child); return child; }, remove() {} };
      if (lowered === 'script') { el.src = ''; el.async = false; el.onload = null; el.onerror = null; }
      if (lowered === 'iframe') { el.contentWindow = sandbox; }
      if (lowered === 'canvas') { el.getContext = () => ({ getParameter: () => null, getExtension: () => null }); }
      if (lowered === 'img' || lowered === 'image') {
        Object.defineProperty(el, 'src', { get() { return this._src || ''; }, set(value) { this._src = String(value); capture('image', this._src, { method: 'GET' }); if (typeof this.onload === 'function') setTimeout(() => this.onload(), 0); } });
      }
      return el;
    },
    getElementById() { return null; },
    getElementsByTagName() { return []; },
    getElementsByClassName() { return []; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
  };
  Object.defineProperty(sandbox.document, 'cookie', { get() { return cookieJar.get(); }, set(value) { cookieJar.set(value); } });

  sandbox.localStorage = new MiniStorage(profile.localStorage || {});
  sandbox.sessionStorage = new MiniStorage(profile.sessionStorage || {});
  sandbox.chrome = profile.chrome || { runtime: {}, app: {}, csi() { return {}; }, loadTimes() { return {}; } };
  sandbox.history = { length: Number(profile.historyLength || 2), pushState() {}, replaceState() {} };
  sandbox.Image = class Image {
    constructor() { this.onload = null; this.onerror = null; this.width = 0; this.height = 0; }
    set src(value) { this._src = String(value); capture('image', this._src, { method: 'GET' }); if (typeof this.onload === 'function') setTimeout(() => this.onload(), 0); }
    get src() { return this._src || ''; }
  };
  sandbox.XMLHttpRequest = class XMLHttpRequest {
    constructor() { this.headers = {}; this.readyState = 0; this.status = 204; this.responseText = ''; this.onreadystatechange = null; this.onload = null; }
    open(method, url) { this.method = String(method || 'GET').toUpperCase(); this.url = String(url); this.readyState = 1; }
    setRequestHeader(key, value) { this.headers[String(key).toLowerCase()] = String(value); }
    getAllResponseHeaders() { return ''; }
    send(body = null) {
      capture('xhr', this.url || '', { method: this.method || 'GET', headers: this.headers, body });
      this.readyState = 4;
      if (typeof this.onreadystatechange === 'function') this.onreadystatechange();
      if (typeof this.onload === 'function') this.onload();
    }
  };
  sandbox.FormData = class FormData { constructor() { this.items = []; } append(k, v) { this.items.push([String(k), String(v)]); } entries() { return this.items[Symbol.iterator](); } [Symbol.iterator]() { return this.entries(); } };
  sandbox.Blob = class Blob { constructor(parts = [], opts = {}) { this.parts = parts; this.type = opts.type || ''; this.size = parts.reduce((n, p) => n + String(p).length, 0); } async text() { return this.parts.map(p => String(p)).join(''); } };
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
