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

function btoaCompat(value) {
  return Buffer.from(String(value), 'binary').toString('base64');
}

function atobCompat(value) {
  return Buffer.from(String(value), 'base64').toString('binary');
}

function normalizeProfile(input) {
  const profile = input && typeof input === 'object' ? input : {};
  const webgl = profile.w || profile.webgl || {};
  return {
    scriptUrl: profile.script_url || profile.scriptUrl || 'https://example.test/_vercel/botid/c.js?i=1&v=3&h=example.test',
    href: profile.href || profile.url || 'https://example.test/',
    userAgent: profile.user_agent || profile.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
    webdriver: !!profile.webdriver,
    outerWidth: Number(profile.outerWidth || profile.outer_width || 1200),
    innerWidth: Number(profile.innerWidth || profile.inner_width || 1200),
    outerHeight: Number(profile.outerHeight || profile.outer_height || 900),
    innerHeight: Number(profile.innerHeight || profile.inner_height || 900),
    webglVendor: String(webgl.v || webgl.vendor || profile.webglVendor || profile.webgl_vendor || 'Google Inc. (Intel)'),
    webglRenderer: String(webgl.r || webgl.renderer || profile.webglRenderer || profile.webgl_renderer || 'ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)'),
  };
}

function makeSandbox(profile) {
  const debugExt = { UNMASKED_VENDOR_WEBGL: 37445, UNMASKED_RENDERER_WEBGL: 37446 };
  const fakeWebgl = {
    getExtension(name) {
      return String(name || '').toLowerCase().includes('debug') ? debugExt : null;
    },
    getParameter(param) {
      if (param === debugExt.UNMASKED_VENDOR_WEBGL) return profile.webglVendor;
      if (param === debugExt.UNMASKED_RENDERER_WEBGL) return profile.webglRenderer;
      return null;
    },
  };
  const sandbox = {
    console: { log() {}, error() {}, warn() {}, info() {} },
    Date,
    Math,
    URL,
    Error,
    Promise,
    Uint8Array,
    Array,
    Object,
    String,
    Number,
    Boolean,
    RegExp,
    Function,
    TextEncoder,
    TextDecoder,
    crypto: webcrypto,
    btoa: btoaCompat,
    atob: atobCompat,
    setTimeout,
    clearTimeout,
    outerWidth: profile.outerWidth,
    innerWidth: profile.innerWidth,
    outerHeight: profile.outerHeight,
    innerHeight: profile.innerHeight,
    location: { href: profile.href, origin: new URL(profile.href).origin },
    navigator: { webdriver: profile.webdriver, userAgent: profile.userAgent },
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.V_C = [];
  sandbox.document = {
    currentScript: { src: profile.scriptUrl },
    body: { appendChild() {} },
    createElement(tag) {
      const lowered = String(tag || '').toLowerCase();
      if (lowered === 'iframe') {
        return { srcdoc: '', contentWindow: sandbox, remove() {}, style: {} };
      }
      if (lowered === 'canvas') {
        return { getContext() { return fakeWebgl; } };
      }
      if (lowered === 'script') {
        return { _src: '', onerror: null, set src(value) { this._src = value; }, get src() { return this._src; } };
      }
      return { style: {}, remove() {}, appendChild() {} };
    },
  };
  return sandbox;
}

async function solve(input) {
  if (!input || typeof input.script !== 'string' || !input.script.trim()) {
    throw new Error('raw VM solver requires non-empty script');
  }
  const profile = normalizeProfile({ ...(input.profile || {}), scriptUrl: input.script_url || input.scriptUrl || input.profile?.scriptUrl });
  const sandbox = makeSandbox(profile);
  const context = vm.createContext(sandbox);
  vm.runInContext(input.script, context, { timeout: Number(input.vm_timeout_ms || 10000) });
  const callbacks = Array.from(context.V_C || []).filter(value => typeof value === 'function');
  if (!callbacks.length) {
    throw new Error('BotID raw VM did not register a V_C callback');
  }
  const payload = await callbacks[callbacks.length - 1]();
  if (!payload || typeof payload !== 'object' || typeof payload.s !== 'string') {
    throw new Error('BotID raw VM callback did not return an X-Is-Human payload');
  }
  return {
    payload,
    diagnostics: {
      callbackCount: callbacks.length,
      version: payload.vr,
      rand: payload.v,
      scriptUrl: profile.scriptUrl,
      webglVendor: profile.webglVendor,
      webglRenderer: profile.webglRenderer,
    },
  };
}

try {
  const raw = await readStdin();
  const input = raw.trim() ? JSON.parse(raw) : {};
  const output = await solve(input);
  process.stdout.write(JSON.stringify(output));
} catch (error) {
  process.stderr.write((error && error.message ? error.message : String(error)) + '\n');
  process.exit(1);
}
