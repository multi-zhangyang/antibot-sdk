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

function bytesFromResource(value) {
  if (value == null) return new Uint8Array();
  if (typeof value === 'string') {
    if (value.startsWith('base64:')) return new Uint8Array(Buffer.from(value.slice(7), 'base64'));
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(value) && value.length > 24) {
      try { return new Uint8Array(Buffer.from(value, 'base64')); } catch {}
    }
    return new TextEncoder().encode(value);
  }
  if (Array.isArray(value)) return new Uint8Array(value.map(x => Number(x) & 0xff));
  if (value && typeof value === 'object') {
    if (value.base64) return new Uint8Array(Buffer.from(String(value.base64), 'base64'));
    if (value.hex) return new Uint8Array(Buffer.from(String(value.hex), 'hex'));
    if (value.text) return new TextEncoder().encode(String(value.text));
    if (Array.isArray(value.bytes)) return new Uint8Array(value.bytes.map(x => Number(x) & 0xff));
  }
  return new TextEncoder().encode(String(value));
}

function resourceLookup(resources, url) {
  const key = String(url);
  if (Object.prototype.hasOwnProperty.call(resources, key)) return resources[key];
  try {
    const u = new URL(key);
    if (Object.prototype.hasOwnProperty.call(resources, u.pathname)) return resources[u.pathname];
    if (Object.prototype.hasOwnProperty.call(resources, u.pathname.split('/').pop())) return resources[u.pathname.split('/').pop()];
  } catch {}
  if (key.startsWith('data:')) {
    const idx = key.indexOf(',');
    if (idx >= 0) {
      const meta = key.slice(0, idx);
      const body = key.slice(idx + 1);
      return meta.includes(';base64') ? { base64: body } : decodeURIComponent(body);
    }
  }
  return null;
}

class MiniResponse {
  constructor(body = new Uint8Array(), init = {}) {
    this._bytes = body instanceof Uint8Array ? body : bytesFromResource(body);
    this.ok = init.ok ?? true;
    this.status = init.status || 200;
    this.url = init.url || '';
    this.headers = new MiniHeaders(init.headers || {});
  }
  async text() { return new TextDecoder().decode(this._bytes); }
  async json() { return JSON.parse(await this.text()); }
  async arrayBuffer() { return this._bytes.buffer.slice(this._bytes.byteOffset, this._bytes.byteOffset + this._bytes.byteLength); }
  clone() { return new MiniResponse(this._bytes, { ok: this.ok, status: this.status, url: this.url, headers: this.headers }); }
}

class MiniHeaders {
  constructor(init = {}) {
    this.map = new Map();
    if (init instanceof MiniHeaders) {
      for (const [k, v] of init.entries()) this.set(k, v);
    } else if (Array.isArray(init)) {
      for (const [k, v] of init) this.set(k, v);
    } else if (init && typeof init === 'object') {
      for (const [k, v] of Object.entries(init)) this.set(k, v);
    }
  }
  set(k, v) { this.map.set(String(k).toLowerCase(), String(v)); }
  get(k) { return this.map.get(String(k).toLowerCase()) ?? null; }
  has(k) { return this.map.has(String(k).toLowerCase()); }
  append(k, v) { const key = String(k).toLowerCase(); const old = this.map.get(key); this.map.set(key, old ? `${old}, ${v}` : String(v)); }
  entries() { return this.map.entries(); }
  [Symbol.iterator]() { return this.entries(); }
  toJSON() { return Object.fromEntries(this.map.entries()); }
}

function normalize(input) {
  return {
    script: String(input.script || ''),
    req: input.req ?? input.request ?? input.challenge ?? {},
    args: Array.isArray(input.args) ? input.args : [],
    functionName: input.function_name || input.functionName || '',
    scriptUrl: input.script_url || input.scriptUrl || 'https://newassets.hcaptcha.com/captcha/v1/hsw.js',
    pageUrl: input.page_url || input.pageUrl || 'https://example.test/',
    profile: input.profile && typeof input.profile === 'object' ? input.profile : {},
    resources: input.resources && typeof input.resources === 'object' ? input.resources : {},
    vmTimeoutMs: Number(input.vm_timeout_ms || input.vmTimeoutMs || 10000),
  };
}

function makeSandbox(opts) {
  const profile = opts.profile || {};
  const resources = opts.resources || {};
  const requests = [];
  const page = new URL(opts.pageUrl);
  const module = { exports: {} };
  const exports = module.exports;
  const wasmShim = Object.create(WebAssembly);
  wasmShim.compile = WebAssembly.compile.bind(WebAssembly);
  wasmShim.compileStreaming = async (source) => WebAssembly.compile(await (await source).arrayBuffer());
  wasmShim.instantiate = WebAssembly.instantiate.bind(WebAssembly);
  wasmShim.instantiateStreaming = async (source, imports = {}) => WebAssembly.instantiate(await (await source).arrayBuffer(), imports);
  wasmShim.Module = WebAssembly.Module;
  wasmShim.Instance = WebAssembly.Instance;
  wasmShim.Memory = WebAssembly.Memory;
  wasmShim.Table = WebAssembly.Table;
  wasmShim.CompileError = WebAssembly.CompileError;
  wasmShim.LinkError = WebAssembly.LinkError;
  wasmShim.RuntimeError = WebAssembly.RuntimeError;

  async function fetchShim(url, options = {}) {
    const finalUrl = url && typeof url === 'object' && typeof url.url === 'string' ? url.url : String(url);
    requests.push({ url: finalUrl, method: String(options.method || 'GET').toUpperCase(), headers: options.headers || {}, body: options.body == null ? null : String(options.body), at: Date.now() });
    const resource = resourceLookup(resources, finalUrl);
    if (resource != null) return new MiniResponse(bytesFromResource(resource), { status: 200, url: finalUrl });
    return new MiniResponse(new Uint8Array(), { status: 204, url: finalUrl });
  }

  const sandbox = {
    console: { log() {}, error() {}, warn() {}, info() {}, debug() {} },
    Date, Math, JSON, URL, URLSearchParams, Error, TypeError, Promise,
    Array, Object, String, Number, Boolean, RegExp, Function, Symbol, Map, Set, WeakMap, WeakSet,
    Uint8Array, Uint16Array, Uint32Array, Int8Array, Int16Array, Int32Array, Float32Array, Float64Array,
    BigInt64Array, BigUint64Array, ArrayBuffer, SharedArrayBuffer, DataView,
    TextEncoder, TextDecoder, WebAssembly: wasmShim,
    Buffer,
    crypto: webcrypto,
    btoa: btoaCompat,
    atob: atobCompat,
    setTimeout, clearTimeout, setInterval, clearInterval, setImmediate, clearImmediate, queueMicrotask,
    requestAnimationFrame: (cb) => setTimeout(() => cb(Date.now()), 16),
    cancelAnimationFrame: clearTimeout,
    performance: { now: () => Number(process.hrtime.bigint() / 1000000n), timeOrigin: Date.now() },
    Headers: MiniHeaders,
    Request: class Request { constructor(url, init = {}) { this.url = String(url); this.method = String(init.method || 'GET').toUpperCase(); this.headers = new MiniHeaders(init.headers || {}); this.body = init.body; } },
    Response: MiniResponse,
    fetch: fetchShim,
    module,
    exports,
    require(name) {
      if (name === 'crypto') return { webcrypto, randomBytes: (n) => Buffer.from(webcrypto.getRandomValues(new Uint8Array(n))) };
      if (name === 'buffer') return { Buffer };
      if (name === 'util') return {};
      return {};
    },
    define(factoryOrDeps, maybeFactory) {
      const factory = typeof factoryOrDeps === 'function' ? factoryOrDeps : maybeFactory;
      if (typeof factory === 'function') {
        const ret = factory(sandbox.require, exports, module);
        if (ret !== undefined) module.exports = ret;
      }
    },
    importScripts(...urls) {
      for (const u of urls) {
        const resource = resourceLookup(resources, u);
        if (resource != null) vm.runInContext(new TextDecoder().decode(bytesFromResource(resource)), sandbox.__context, { filename: String(u) });
      }
    },
    location: { href: opts.pageUrl, origin: page.origin, protocol: page.protocol, host: page.host, hostname: page.hostname, pathname: page.pathname, search: page.search, hash: page.hash, toString() { return this.href; } },
    navigator: {
      userAgent: profile.user_agent || profile.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      webdriver: false,
      platform: profile.platform || 'Win32',
      language: profile.language || 'en-US',
      languages: profile.languages || ['en-US', 'en'],
      hardwareConcurrency: Number(profile.hardwareConcurrency || 8),
      deviceMemory: Number(profile.deviceMemory || 8),
      cookieEnabled: true,
      permissions: { query: async () => ({ state: 'prompt' }) },
      userAgentData: profile.userAgentData || { brands: [{ brand: 'Chromium', version: '120' }, { brand: 'Google Chrome', version: '120' }], mobile: false, platform: profile.platform || 'Windows', getHighEntropyValues: async () => ({ architecture: 'x86', bitness: '64', mobile: false, model: '', platform: profile.platform || 'Windows', platformVersion: '10.0.0', uaFullVersion: '120.0.0.0', wow64: false }) },
    },
    screen: { width: Number(profile.screen_width || 1920), height: Number(profile.screen_height || 1080), colorDepth: 24, pixelDepth: 24 },
    document: {
      location: null,
      URL: opts.pageUrl,
      documentURI: opts.pageUrl,
      referrer: profile.referrer || '',
      currentScript: { src: opts.scriptUrl },
      readyState: 'complete',
      cookie: String(profile.cookie || ''),
      createElement(tag = 'div') {
        const lowered = String(tag).toLowerCase();
        const el = { tagName: lowered.toUpperCase(), style: {}, children: [], setAttribute(k, v) { this[k] = String(v); }, getAttribute(k) { return this[k] || null; }, appendChild(child) { this.children.push(child); return child; }, remove() {} };
        if (lowered === 'canvas') {
          el.width = 300; el.height = 150;
          el.getContext = () => ({ getParameter: () => null, getExtension: () => null, fillRect() {}, clearRect() {}, getImageData: () => ({ data: new Uint8ClampedArray(16) }), putImageData() {}, createImageData: () => ({ data: new Uint8ClampedArray(16) }), measureText: (text) => ({ width: String(text).length * 6 }) });
          el.toDataURL = () => 'data:image/png;base64,';
        }
        return el;
      },
      querySelector() { return null; },
      querySelectorAll() { return []; },
      addEventListener() {},
      removeEventListener() {},
    },
    localStorage: { getItem() { return null; }, setItem() {}, removeItem() {}, clear() {} },
    sessionStorage: { getItem() { return null; }, setItem() {}, removeItem() {}, clear() {} },
    __hswRequests: requests,
  };
  sandbox.define.amd = true;
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.document.location = sandbox.location;
  sandbox.__context = sandbox;
  return sandbox;
}

function getPath(root, path) {
  if (!path) return undefined;
  let obj = root;
  for (const part of String(path).split('.')) {
    if (!part) continue;
    if (obj == null) return undefined;
    obj = obj[part];
  }
  return obj;
}

function resolveFunction(context, requested) {
  const candidates = [];
  if (requested) candidates.push(requested);
  candidates.push(
    'hsw', 'window.hsw', 'self.hsw', '__hsw', 'window.__hsw',
    'get_hsw', 'generate', 'generateHsw', 'hcaptcha_hsw',
    'module.exports', 'module.exports.hsw', 'module.exports.default', 'module.exports.generate',
    'exports.hsw', 'exports.default', 'exports.generate',
    'hcaptcha.hsw', 'window.hcaptcha.hsw'
  );
  for (const name of candidates) {
    const value = getPath(context, name);
    if (typeof value === 'function') return { name, fn: value };
  }
  const deep = findFunctionDeep(context.module.exports, 'module.exports') || findFunctionDeep(context.window, 'window');
  if (deep) return deep;
  return { name: '', fn: null };
}

function findFunctionDeep(root, prefix, seen = new Set(), depth = 0) {
  if (!root || depth > 4 || seen.has(root)) return null;
  if (typeof root === 'function') return { name: prefix, fn: root };
  if (typeof root !== 'object') return null;
  seen.add(root);
  const keys = Object.keys(root).slice(0, 200);
  const preferred = keys.filter(k => /hsw|hsl|proof|generate|answer|n/i.test(k)).concat(keys.filter(k => !/hsw|hsl|proof|generate|answer|n/i.test(k)));
  for (const key of preferred) {
    const value = root[key];
    if (typeof value === 'function') return { name: `${prefix}.${key}`, fn: value };
    if (value && typeof value === 'object') {
      const nested = findFunctionDeep(value, `${prefix}.${key}`, seen, depth + 1);
      if (nested) return nested;
    }
  }
  return null;
}

async function solve(input) {
  const opts = normalize(input || {});
  if (!opts.script.trim()) throw new Error('hCaptcha HSW VM requires non-empty script');
  const sandbox = makeSandbox(opts);
  const context = vm.createContext(sandbox);
  sandbox.__context = context;
  vm.runInContext(opts.script, context, { timeout: opts.vmTimeoutMs, filename: opts.scriptUrl });
  const resolved = resolveFunction(context, opts.functionName);
  if (!resolved.fn) throw new Error('hCaptcha HSW function was not found; pass function_name or expose window.hsw/module.exports');
  const started = Date.now();
  const value = await resolved.fn.call(context.window, opts.req, ...opts.args);
  const elapsed = Date.now() - started;
  return {
    value,
    valueType: typeof value,
    valueJson: value && typeof value === 'object' ? value : null,
    valueString: typeof value === 'string' ? value : JSON.stringify(value),
    functionName: resolved.name,
    requests: context.__hswRequests,
    diagnostics: {
      scriptUrl: opts.scriptUrl,
      pageUrl: opts.pageUrl,
      elapsedMs: elapsed,
      requestCount: context.__hswRequests.length,
      moduleExportKeys: context.module && context.module.exports && typeof context.module.exports === 'object' ? Object.keys(context.module.exports).slice(0, 60) : [],
      windowKeys: Object.keys(context.window).filter(k => /hsw|hcaptcha/i.test(k)).slice(0, 60),
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
