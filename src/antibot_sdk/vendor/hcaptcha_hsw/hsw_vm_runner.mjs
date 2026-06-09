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
    vmTimeoutMs: Number(input.vm_timeout_ms || input.vmTimeoutMs || 10000),
  };
}

function makeSandbox(opts) {
  const profile = opts.profile || {};
  const requests = [];
  const page = new URL(opts.pageUrl);
  const module = { exports: {} };
  const exports = module.exports;

  async function fetchShim(url, options = {}) {
    requests.push({ url: String(url), method: String(options.method || 'GET').toUpperCase(), headers: options.headers || {}, body: options.body == null ? null : String(options.body), at: Date.now() });
    return { ok: true, status: 204, url: String(url), headers: new MiniHeaders(), text: async () => '', json: async () => ({}), arrayBuffer: async () => new ArrayBuffer(0), clone() { return this; } };
  }

  const sandbox = {
    console: { log() {}, error() {}, warn() {}, info() {}, debug() {} },
    Date, Math, JSON, URL, URLSearchParams, Error, TypeError, Promise,
    Array, Object, String, Number, Boolean, RegExp, Function, Symbol, Map, Set, WeakMap, WeakSet,
    Uint8Array, Uint16Array, Uint32Array, Int8Array, Int16Array, Int32Array, Float32Array, Float64Array,
    BigInt64Array, BigUint64Array, ArrayBuffer, SharedArrayBuffer, DataView,
    TextEncoder, TextDecoder, WebAssembly,
    crypto: webcrypto,
    btoa: btoaCompat,
    atob: atobCompat,
    setTimeout, clearTimeout, setInterval, clearInterval,
    performance: { now: () => Number(process.hrtime.bigint() / 1000000n), timeOrigin: Date.now() },
    Headers: MiniHeaders,
    Request: class Request { constructor(url, init = {}) { this.url = String(url); this.method = String(init.method || 'GET').toUpperCase(); this.headers = new MiniHeaders(init.headers || {}); this.body = init.body; } },
    Response: class Response {},
    fetch: fetchShim,
    module,
    exports,
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
      createElement() { return { style: {}, getContext: () => ({ getParameter: () => null, getExtension: () => null }) }; },
      querySelector() { return null; },
      querySelectorAll() { return []; },
      addEventListener() {},
      removeEventListener() {},
    },
    localStorage: { getItem() { return null; }, setItem() {}, removeItem() {}, clear() {} },
    sessionStorage: { getItem() { return null; }, setItem() {}, removeItem() {}, clear() {} },
    __hswRequests: requests,
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.document.location = sandbox.location;
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
  return { name: '', fn: null };
}

async function solve(input) {
  const opts = normalize(input || {});
  if (!opts.script.trim()) throw new Error('hCaptcha HSW VM requires non-empty script');
  const sandbox = makeSandbox(opts);
  const context = vm.createContext(sandbox);
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
