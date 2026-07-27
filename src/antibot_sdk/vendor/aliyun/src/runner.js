#!/usr/bin/env node
'use strict';
try { require('dotenv').config({ quiet: true }); } catch {}
/*
 * Generic Aliyun CAPTCHA V3 multi-challenge runner.
 * - Opens TARGET_URL.
 * - Hooks addEventListener at document_start.
 * - Finds standard AliyunCaptcha puzzle DOM.
 * - Solves the gap from background/puzzle images.
 * - Replays a CDP mouse trajectory and can fall back to direct listener invocation.
 * - Captures VerifyCaptchaV3 network response when the target page emits it.
 */
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { installDeepHooks } = require('./deep_hooks');
const {
  CAPTCHA_TYPES,
  captchaReady,
  detectCaptchaType,
  normalizeCaptchaType,
  normalizeVendorCaptchaType,
  verifyCode,
  verifyPassed,
} = require('./challenge_types');
const { PNG } = require('pngjs');
function loadPuppeteer(useRebrowser) {
  return useRebrowser ? require('rebrowser-puppeteer-core') : require('puppeteer-core');
}

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_SELECTORS = Object.freeze({
  entry: '#aliyunCaptcha-captcha-body,#aliyunCaptcha-captcha-wrapper',
  body: '#aliyunCaptcha-sliding-body',
  slider: '#aliyunCaptcha-sliding-slider',
  track: '#aliyunCaptcha-sliding-wrapper,#aliyunCaptcha-sliding-track,#aliyunCaptcha-sliding-body',
  image: '#aliyunCaptcha-img',
  puzzle: '#aliyunCaptcha-puzzle',
  checkbox: '#aliyunCaptcha-checkbox,[id^="aliyunCaptcha-"][role="checkbox"],[id^="aliyunCaptcha-"] input[type="checkbox"]',
  prompt: '#aliyunCaptcha-title,#aliyunCaptcha-prompt,#aliyunCaptcha-sliding-text,[id^="aliyunCaptcha-"][class*="title"]',
});
const STABLE_PROFILE = Object.freeze({
  mode: 'cdpdrag',
  totalMs: 500,
  steps: 25,
  warmPoints: 18,
  releaseHoldMs: 220,
  releaseHoldJitterMs: 120,
  pressHoldMs: 80,
  pressHoldJitterMs: 0,
  postDownMs: 0,
  warmStartX: 960,
  warmStartY: 560,
  warmDtMinMs: 8,
  warmDtMaxMs: 28,
  baseDelta: 20,
  requireGapSource: '',
  alignPuzzle: 1,
  alignGain: 0.7,
  alignIters: 6,
  alignTolerancePx: 2,
  alignMaxStepPx: 22,
  maxAttempts: 5,
});
function userAgent(ua) {
  return ua || process.env.USER_AGENT || 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36';
}
function defaultOutputDir() {
  return process.env.OUTPUT_DIR ? path.resolve(process.env.OUTPUT_DIR) : path.join(ROOT, 'runs', process.env.TS || new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14));
}
function selectors(overrides = {}) {
  return {
    entry: overrides.entry || process.env.CAPTCHA_ENTRY_SELECTOR || DEFAULT_SELECTORS.entry,
    body: overrides.body || process.env.CAPTCHA_BODY_SELECTOR || DEFAULT_SELECTORS.body,
    slider: overrides.slider || process.env.CAPTCHA_SLIDER_SELECTOR || DEFAULT_SELECTORS.slider,
    track: overrides.track || process.env.CAPTCHA_TRACK_SELECTOR || DEFAULT_SELECTORS.track,
    image: overrides.image || process.env.CAPTCHA_IMAGE_SELECTOR || DEFAULT_SELECTORS.image,
    puzzle: overrides.puzzle || process.env.CAPTCHA_PUZZLE_SELECTOR || DEFAULT_SELECTORS.puzzle,
    checkbox: overrides.checkbox || process.env.CAPTCHA_CHECKBOX_SELECTOR || DEFAULT_SELECTORS.checkbox,
    prompt: overrides.prompt || process.env.CAPTCHA_PROMPT_SELECTOR || DEFAULT_SELECTORS.prompt,
  };
}

function findChromePath(explicit) {
  const xs = [explicit, process.env.CHROME_PATH, process.env.PUPPETEER_EXECUTABLE_PATH, '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/snap/bin/chromium'].filter(Boolean);
  return xs.find(x => fs.existsSync(x)) || xs[0];
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function num(name, fallback) { const v = process.env[name]; const n = Number(v); return v == null || v === '' || !Number.isFinite(n) ? fallback : n; }
function hash32(s) { let h = 2166136261 >>> 0; for (const ch of String(s || '')) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619) >>> 0; } return h >>> 0; }
function sanitizeName(s) { return String(s || 'run').replace(/[^a-zA-Z0-9_.-]/g, '_'); }
function envFlag(name, fallback = false) {
  const v = process.env[name];
  if (v == null || v === '') return fallback;
  return /^(1|true|yes|on)$/i.test(String(v));
}
function envList(name, fallback = '') {
  const v = process.env[name];
  return String(v == null || v === '' ? fallback : v)
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
}
class WatchdogTimeout extends Error {
  constructor(label, timeoutMs, elapsedMs) {
    super(`watchdog timeout: ${label} after ${elapsedMs}ms`);
    this.name = 'WatchdogTimeout';
    this.label = label;
    this.timeoutMs = timeoutMs;
    this.elapsedMs = elapsedMs;
    this.watchdog = { label, timeoutMs, elapsedMs };
  }
}
function watchdogMs(name, fallback) {
  return Math.max(0, Math.floor(num(name, fallback)));
}
async function withWatchdog(label, timeoutMs, fn, result) {
  const ms = Math.max(0, Math.floor(Number(timeoutMs) || 0));
  if (!envFlag('ALIYUN_WATCHDOG_ENABLED', true) || ms <= 0) return await fn();
  const started = Date.now();
  let timer = null;
  let fired = false;
  const op = Promise.resolve()
    .then(fn)
    .catch((e) => {
      // If the race already timed out, suppress late rejections from Puppeteer
      // operations that will be interrupted by browser/page cleanup.
      if (fired) return undefined;
      throw e;
    });
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      fired = true;
      const err = new WatchdogTimeout(label, ms, Date.now() - started);
      if (result) {
        result.watchdog = { ...err.watchdog, at: new Date().toISOString() };
        result.watchdogEvents = result.watchdogEvents || [];
        result.watchdogEvents.push({ ...result.watchdog, type: 'timeout' });
      }
      reject(err);
    }, ms);
    if (timer && timer.unref) timer.unref();
  });
  try {
    const value = await Promise.race([op, timeout]);
    if (result) {
      result.stageTimings = result.stageTimings || [];
      result.stageTimings.push({ label, elapsedMs: Date.now() - started });
    }
    return value;
  } finally {
    if (timer) clearTimeout(timer);
  }
}
function errWatchdog(e) {
  return e && e.watchdog ? e.watchdog : null;
}
function normalizeVerifyCode(code) {
  const c = String(code || '').trim().toUpperCase();
  return c || 'NONE';
}
function verifyFailureCode(result) {
  const code = result && result.verifyResponse && result.verifyResponse.VerifyCode;
  if (code) return normalizeVerifyCode(code);
  return result && result.verifyNetwork ? 'UNKNOWN' : 'NONE';
}
function verifyCodeAllowed(code, allowList) {
  const c = normalizeVerifyCode(code);
  const xs = (allowList || []).map(normalizeVerifyCode);
  return xs.includes('*') || xs.includes('ALL') || xs.includes(c);
}
function redactProxy(s) {
  try {
    if (!s) return '';
    const raw = String(s);
    const u = new URL(raw.includes('://') ? raw : `http://${raw}`);
    if (u.username || u.password) {
      u.username = '***';
      u.password = '***';
    }
    return raw.includes('://') ? u.toString() : u.toString().replace(/^http:\/\//, '');
  } catch {
    return String(s || '').replace(/\/\/([^/@]*@)/, '//***@').replace(/\/\/([^:/@]+):([^/@]+)@/, '//***:***@');
  }
}
function profileEnv(profile = {}) {
  const p = profile || {};
  const map = {
    mode: 'LISTENER_MODE',
    style: 'LISTENER_TRAJECTORY_STYLE',
    totalMs: 'LISTENER_TOTAL_MS',
    steps: 'LISTENER_STEPS',
    warmPoints: 'LISTENER_WARM_POINTS',
    warmDtMinMs: 'LISTENER_WARM_DT_MIN_MS',
    warmDtMaxMs: 'LISTENER_WARM_DT_MAX_MS',
    releaseHoldMs: 'LISTENER_RELEASE_HOLD_MS',
    releaseHoldJitterMs: 'LISTENER_RELEASE_HOLD_JITTER_MS',
    baseDelta: 'LISTENER_BASE_DELTA',
    offset: 'LISTENER_OFFSET',
    overshootPx: 'LISTENER_OVERSHOOT_PX',
    requireGapSource: 'LISTENER_REQUIRE_GAP_SOURCE',
    rawMin: 'LISTENER_RAW_MIN',
    rawMax: 'LISTENER_RAW_MAX',
    distanceMin: 'LISTENER_DISTANCE_MIN',
    distanceMax: 'LISTENER_DISTANCE_MAX',
    distanceMode: 'LISTENER_DISTANCE_MODE',
    maxMarginPx: 'LISTENER_MAX_MARGIN_PX',
    slotOnly: 'LISTENER_SLOT_ONLY',
    alignPuzzle: 'LISTENER_ALIGN_PUZZLE',
    alignGain: 'LISTENER_ALIGN_GAIN',
    alignIters: 'LISTENER_ALIGN_ITERS',
    alignTolerancePx: 'LISTENER_ALIGN_TOLERANCE_PX',
    alignMaxStepPx: 'LISTENER_ALIGN_MAX_STEP_PX',
    maxAttempts: 'LISTENER_MAX_ATTEMPTS',
  };
  const patch = {};
  for (const [k, env] of Object.entries(map)) {
    if (p[k] !== undefined && p[k] !== null && process.env[env] === undefined) {
      patch[env] = String(p[k]);
    }
  }
  return patch;
}
function patchEnv(patch) {
  const old = {};
  for (const [k, v] of Object.entries(patch || {})) {
    old[k] = Object.prototype.hasOwnProperty.call(process.env, k) ? process.env[k] : undefined;
    process.env[k] = v;
  }
  return () => {
    for (const [k, v] of Object.entries(old)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  };
}
function autoProfileFor(raw) {
  if (process.env.LISTENER_AUTO_PROFILE !== '1') return null;
  if (raw >= 240) return { totalMs: 2000, steps: 100 };
  if (raw >= 180) return { totalMs: 1200, steps: 60 };
  if (raw >= 130) return { totalMs: 800, steps: 40 };
  return { totalMs: 500, steps: 25 };
}
function resolvedProfile(overrides = {}) {
  return {
    mode: process.env.LISTENER_MODE ?? STABLE_PROFILE.mode,
    totalMs: process.env.LISTENER_TOTAL_MS ?? STABLE_PROFILE.totalMs,
    steps: process.env.LISTENER_STEPS ?? STABLE_PROFILE.steps,
    warmPoints: process.env.LISTENER_WARM_POINTS ?? STABLE_PROFILE.warmPoints,
    releaseHoldMs: process.env.LISTENER_RELEASE_HOLD_MS ?? STABLE_PROFILE.releaseHoldMs,
    releaseHoldJitterMs: process.env.LISTENER_RELEASE_HOLD_JITTER_MS ?? STABLE_PROFILE.releaseHoldJitterMs,
    pressHoldMs: process.env.LISTENER_PRESS_HOLD_MS ?? STABLE_PROFILE.pressHoldMs,
    pressHoldJitterMs: process.env.LISTENER_PRESS_HOLD_JITTER_MS ?? STABLE_PROFILE.pressHoldJitterMs,
    postDownMs: process.env.LISTENER_POST_DOWN_MS ?? STABLE_PROFILE.postDownMs,
    warmStartX: process.env.LISTENER_WARM_START_X ?? STABLE_PROFILE.warmStartX,
    warmStartY: process.env.LISTENER_WARM_START_Y ?? STABLE_PROFILE.warmStartY,
    warmDtMinMs: process.env.LISTENER_WARM_DT_MIN_MS ?? STABLE_PROFILE.warmDtMinMs,
    warmDtMaxMs: process.env.LISTENER_WARM_DT_MAX_MS ?? STABLE_PROFILE.warmDtMaxMs,
    baseDelta: process.env.LISTENER_BASE_DELTA ?? STABLE_PROFILE.baseDelta,
    requireGapSource: process.env.LISTENER_REQUIRE_GAP_SOURCE ?? STABLE_PROFILE.requireGapSource,
    alignPuzzle: process.env.LISTENER_ALIGN_PUZZLE ?? STABLE_PROFILE.alignPuzzle,
    alignGain: process.env.LISTENER_ALIGN_GAIN ?? STABLE_PROFILE.alignGain,
    alignIters: process.env.LISTENER_ALIGN_ITERS ?? STABLE_PROFILE.alignIters,
    alignTolerancePx: process.env.LISTENER_ALIGN_TOLERANCE_PX ?? STABLE_PROFILE.alignTolerancePx,
    alignMaxStepPx: process.env.LISTENER_ALIGN_MAX_STEP_PX ?? STABLE_PROFILE.alignMaxStepPx,
    maxAttempts: process.env.LISTENER_MAX_ATTEMPTS ?? STABLE_PROFILE.maxAttempts,
    ...overrides,
  };
}

async function getBuf(url, ua) {
  if (!url) throw new Error('empty image url');
  if (url.startsWith('data:')) {
    const i = url.indexOf(',');
    return Buffer.from(url.slice(i + 1), url.slice(0, i).includes(';base64') ? 'base64' : 'utf8');
  }
  const res = await fetch(url, { headers: { 'User-Agent': userAgent(ua) } });
  if (!res.ok) throw new Error(`image fetch ${res.status}: ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

function sobelMagnitude(png) {
  const gray = new Float64Array(png.width * png.height);
  for (let i = 0; i < png.width * png.height; i++) gray[i] = .299 * png.data[i * 4] + .587 * png.data[i * 4 + 1] + .114 * png.data[i * 4 + 2];
  const mag = new Float64Array(png.width * png.height);
  for (let y = 1; y < png.height - 1; y++) for (let x = 1; x < png.width - 1; x++) {
    const i = y * png.width + x;
    const gx = -gray[i - png.width - 1] + gray[i - png.width + 1] - 2 * gray[i - 1] + 2 * gray[i + 1] - gray[i + png.width - 1] + gray[i + png.width + 1];
    const gy = -gray[i - png.width - 1] - 2 * gray[i - png.width] - gray[i - png.width + 1] + gray[i + png.width - 1] + 2 * gray[i + png.width] + gray[i + png.width + 1];
    mag[i] = Math.sqrt(gx * gx + gy * gy);
  }
  return mag;
}
function alphaBounds(png) {
  let minX = png.width, minY = png.height, maxX = -1, maxY = -1, count = 0;
  for (let y = 0; y < png.height; y++) for (let x = 0; x < png.width; x++) {
    if (png.data[(y * png.width + x) * 4 + 3] <= 40) continue;
    count++; if (x < minX) minX = x; if (x > maxX) maxX = x; if (y < minY) minY = y; if (y > maxY) maxY = y;
  }
  return count ? { minX, maxX, minY, maxY, width: maxX - minX + 1, height: maxY - minY + 1, count } : null;
}

function detectRestoreStrip(bgBuf, pieceBuf, geometry = {}) {
  const bg = PNG.sync.read(bgBuf), piece = PNG.sync.read(pieceBuf);
  if (bg.height !== piece.height || piece.width >= bg.width) {
    throw new Error(`restore layers have incompatible dimensions: background=${bg.width}x${bg.height}, fragment=${piece.width}x${piece.height}`);
  }
  const cssWidth = Math.max(1, Number(geometry.cssWidth || bg.width));
  const cssPerPng = cssWidth / bg.width;
  const requestedMax = Number.isFinite(Number(geometry.maxDistance))
    ? Number(geometry.maxDistance)
    : (bg.width - piece.width) * cssPerPng;
  const maxX = Math.max(0, Math.min(bg.width - piece.width, Math.floor(requestedMax / cssPerPng + 1e-6)));
  const alphaThreshold = Math.max(1, Math.min(254, Number(geometry.alphaThreshold || 24)));
  const samples = [];
  for (let y = 0; y < piece.height; y++) for (let x = 0; x < piece.width; x++) {
    const i = (y * piece.width + x) * 4;
    const alpha = piece.data[i + 3];
    if (alpha < alphaThreshold) continue;
    samples.push({ x, y, i, weight: Math.pow(alpha / 255, 1.5) });
  }
  if (samples.length < Math.max(24, piece.width)) {
    throw new Error(`restore fragment has too few visible pixels: ${samples.length}`);
  }

  const scores = [];
  for (let offset = 0; offset <= maxX; offset++) {
    let colorError = 0, colorWeight = 0, gradientError = 0, gradientWeight = 0;
    for (const sample of samples) {
      const bi = (sample.y * bg.width + offset + sample.x) * 4;
      const pi = sample.i, weight = sample.weight;
      colorError += weight * (
        Math.abs(piece.data[pi] - bg.data[bi]) +
        Math.abs(piece.data[pi + 1] - bg.data[bi + 1]) +
        Math.abs(piece.data[pi + 2] - bg.data[bi + 2])
      ) / 3;
      colorWeight += weight;
      if (sample.x > 0 && piece.data[pi - 1] >= alphaThreshold) {
        const bp = bi - 4, pp = pi - 4;
        gradientError += weight * (
          Math.abs((piece.data[pi] - piece.data[pp]) - (bg.data[bi] - bg.data[bp])) +
          Math.abs((piece.data[pi + 1] - piece.data[pp + 1]) - (bg.data[bi + 1] - bg.data[bp + 1])) +
          Math.abs((piece.data[pi + 2] - piece.data[pp + 2]) - (bg.data[bi + 2] - bg.data[bp + 2]))
        ) / 3;
        gradientWeight += weight;
      }
      if (sample.y > 0 && piece.data[pi - piece.width * 4 + 3] >= alphaThreshold) {
        const bp = bi - bg.width * 4, pp = pi - piece.width * 4;
        gradientError += weight * (
          Math.abs((piece.data[pi] - piece.data[pp]) - (bg.data[bi] - bg.data[bp])) +
          Math.abs((piece.data[pi + 1] - piece.data[pp + 1]) - (bg.data[bi + 1] - bg.data[bp + 1])) +
          Math.abs((piece.data[pi + 2] - piece.data[pp + 2]) - (bg.data[bi + 2] - bg.data[bp + 2]))
        ) / 3;
        gradientWeight += weight;
      }
    }
    const color = colorError / Math.max(1e-9, colorWeight);
    const gradient = gradientError / Math.max(1e-9, gradientWeight);
    scores.push({ x: offset, score: color * 0.78 + gradient * 0.22, color, gradient });
  }
  scores.sort((a, b) => a.score - b.score || a.x - b.x);
  const separated = [];
  const separation = Math.max(3, Math.floor(piece.width * 0.75));
  for (const score of scores) {
    if (separated.every(candidate => Math.abs(candidate.x - score.x) >= separation)) separated.push(score);
    if (separated.length >= 5) break;
  }
  const best = separated[0], runnerUp = separated[1] || best;
  const margin = runnerUp && runnerUp !== best
    ? Math.max(0, (runnerUp.score - best.score) / Math.max(1, runnerUp.score))
    : 0;
  // Local matching is authoritative only when the fragment is both a close
  // pixel match and clearly separated from the next non-adjacent candidate.
  // Semantic restoration scenes intentionally violate the first condition and
  // are delegated to candidate-composite vision ranking.
  const absoluteQuality = Math.exp(-best.score / 32);
  const confidence = Math.max(0, Math.min(1, absoluteQuality * Math.min(1, 0.55 + margin * 3)));
  const compact = candidate => ({
    target_left_png: candidate.x,
    distance_px: Number((candidate.x * cssPerPng).toFixed(3)),
    score: Number(candidate.score.toFixed(3)),
    color_error: Number(candidate.color.toFixed(3)),
    gradient_error: Number(candidate.gradient.toFixed(3)),
  });
  return {
    source: 'local_strip_match',
    distance_px: Number((best.x * cssPerPng).toFixed(3)),
    target_left_png: best.x,
    confidence: Number(confidence.toFixed(4)),
    score_margin: Number(margin.toFixed(4)),
    css_per_png: Number(cssPerPng.toFixed(6)),
    visible_pixels: samples.length,
    fragment: { width: piece.width, height: piece.height, alpha_bounds: alphaBounds(piece) },
    background: { width: bg.width, height: bg.height },
    candidates: separated.map(compact),
  };
}

function detectRestoreBoundaryContinuity(bgBuf, pieceBuf, geometry = {}) {
  const bg = PNG.sync.read(bgBuf), piece = PNG.sync.read(pieceBuf);
  if (bg.height !== piece.height || piece.width >= bg.width) {
    throw new Error(`restore layers have incompatible dimensions: background=${bg.width}x${bg.height}, fragment=${piece.width}x${piece.height}`);
  }
  const cssWidth = Math.max(1, Number(geometry.cssWidth || bg.width));
  const cssPerPng = cssWidth / bg.width;
  const requestedMax = Number.isFinite(Number(geometry.maxDistance))
    ? Number(geometry.maxDistance)
    : (bg.width - piece.width) * cssPerPng;
  const maxX = Math.max(0, Math.min(bg.width - piece.width, Math.floor(requestedMax / cssPerPng + 1e-6)));
  const alphaThreshold = Math.max(1, Math.min(254, Number(geometry.alphaThreshold || 24)));
  const directions = [
    { name: 'top', dx: 0, dy: -1 },
    { name: 'bottom', dx: 0, dy: 1 },
    { name: 'left', dx: -1, dy: 0 },
    { name: 'right', dx: 1, dy: 0 },
  ];
  const results = [];
  for (const direction of directions) {
    const boundary = [];
    for (let y = 0; y < piece.height; y++) for (let x = 0; x < piece.width; x++) {
      const i = (y * piece.width + x) * 4;
      if (piece.data[i + 3] < alphaThreshold) continue;
      const nx = x + direction.dx, ny = y + direction.dy;
      if (nx >= 0 && nx < piece.width && ny >= 0 && ny < piece.height && piece.data[(ny * piece.width + nx) * 4 + 3] >= alphaThreshold) continue;
      boundary.push({ x, y, nx, ny, i });
    }
    if (boundary.length < 4) continue;
    const scores = [];
    for (let offset = 0; offset <= maxX; offset++) {
      let colorError = 0, samples = 0;
      for (const sample of boundary) {
        const bx = offset + sample.nx, by = sample.ny;
        if (bx < 0 || bx >= bg.width || by < 0 || by >= bg.height) continue;
        const bi = (by * bg.width + bx) * 4;
        colorError += (
          Math.abs(piece.data[sample.i] - bg.data[bi]) +
          Math.abs(piece.data[sample.i + 1] - bg.data[bi + 1]) +
          Math.abs(piece.data[sample.i + 2] - bg.data[bi + 2])
        ) / 3;
        samples++;
      }
      if (samples >= Math.max(3, boundary.length * 0.6)) scores.push({ x: offset, score: colorError / samples });
    }
    scores.sort((a, b) => a.score - b.score || a.x - b.x);
    const separated = [];
    const separation = Math.max(3, Math.floor(piece.width * 0.75));
    for (const score of scores) {
      if (separated.every(candidate => Math.abs(candidate.x - score.x) >= separation)) separated.push(score);
      if (separated.length >= 3) break;
    }
    if (!separated.length) continue;
    const best = separated[0], runnerUp = separated[1] || best;
    const margin = runnerUp !== best ? Math.max(0, (runnerUp.score - best.score) / Math.max(1, runnerUp.score)) : 0;
    const confidence = Math.max(0, Math.min(1, ((30 - best.score) / 15) * Math.min(1, margin / 0.5)));
    results.push({
      direction: direction.name,
      distance_px: Number((best.x * cssPerPng).toFixed(3)),
      target_left_png: best.x,
      confidence: Number(confidence.toFixed(4)),
      score: Number(best.score.toFixed(3)),
      score_margin: Number(margin.toFixed(4)),
      boundary_pixels: boundary.length,
      candidates: separated.map(candidate => ({
        target_left_png: candidate.x,
        distance_px: Number((candidate.x * cssPerPng).toFixed(3)),
        score: Number(candidate.score.toFixed(3)),
      })),
    });
  }
  results.sort((a, b) => b.confidence - a.confidence || a.score - b.score);
  return { source: 'boundary_continuity', css_per_png: Number(cssPerPng.toFixed(6)), directions: results };
}

function renderRestoreCandidate(bgBuf, pieceBuf, targetLeft) {
  const bg = PNG.sync.read(bgBuf), piece = PNG.sync.read(pieceBuf);
  const offset = Math.round(Number(targetLeft));
  if (!Number.isFinite(offset) || offset < 0 || offset + piece.width > bg.width || piece.height !== bg.height) {
    throw new Error(`invalid restore candidate position: ${targetLeft}`);
  }
  const rendered = new PNG({ width: bg.width, height: bg.height });
  bg.data.copy(rendered.data);
  for (let y = 0; y < piece.height; y++) for (let x = 0; x < piece.width; x++) {
    const pi = (y * piece.width + x) * 4, bi = (y * bg.width + offset + x) * 4;
    const alpha = piece.data[pi + 3] / 255;
    if (alpha <= 0) continue;
    for (let channel = 0; channel < 3; channel++) {
      rendered.data[bi + channel] = Math.round(piece.data[pi + channel] * alpha + rendered.data[bi + channel] * (1 - alpha));
    }
    rendered.data[bi + 3] = 255;
  }
  return PNG.sync.write(rendered);
}

function renderRestoreCandidateFocus(bgBuf, pieceBuf, targetLeft) {
  const bg = PNG.sync.read(bgBuf), piece = PNG.sync.read(pieceBuf);
  const bounds = alphaBounds(piece);
  if (!bounds) throw new Error('restore fragment has no visible pixels');
  const rendered = PNG.sync.read(renderRestoreCandidate(bgBuf, pieceBuf, targetLeft));
  const sourceWidth = Math.min(bg.width, Math.max(64, piece.width * 5));
  const sourceHeight = Math.min(bg.height, Math.max(64, bounds.height + 32));
  const centerX = Number(targetLeft) + (bounds.minX + bounds.maxX + 1) / 2;
  const centerY = (bounds.minY + bounds.maxY + 1) / 2;
  const sourceX = Math.max(0, Math.min(bg.width - sourceWidth, Math.round(centerX - sourceWidth / 2)));
  const sourceY = Math.max(0, Math.min(bg.height - sourceHeight, Math.round(centerY - sourceHeight / 2)));
  const scale = Math.max(2, Math.min(4, Math.floor(300 / Math.max(sourceWidth, sourceHeight))));
  const focused = new PNG({ width: sourceWidth * scale, height: sourceHeight * scale });
  for (let y = 0; y < sourceHeight; y++) for (let x = 0; x < sourceWidth; x++) {
    const sourceIndex = ((sourceY + y) * rendered.width + sourceX + x) * 4;
    for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) {
      const targetIndex = ((y * scale + dy) * focused.width + x * scale + dx) * 4;
      rendered.data.copy(focused.data, targetIndex, sourceIndex, sourceIndex + 4);
    }
  }
  return PNG.sync.write(focused);
}

function restorePuzzleTravel(sliderDistance, maxSliderDistance) {
  const slider = Math.max(0, Number(sliderDistance));
  const max = Math.max(1, Number(maxSliderDistance));
  return 12 * slider * slider / (13 * max) + slider / 13;
}

function restoreSliderTravel(targetLeft, maxSliderDistance) {
  const target = Math.max(0, Number(targetLeft));
  const max = Math.max(1, Number(maxSliderDistance));
  return max * (Math.sqrt(1 + 624 * target / max) - 1) / 24;
}

function restoreQuantizedSliderTravel(targetLeft, maxSliderDistance) {
  const target = Math.max(0, Number(targetLeft));
  const max = Math.max(1, Number(maxSliderDistance));
  const raw = restoreSliderTravel(target, max);
  const candidates = [...new Set([Math.floor(raw), Math.round(raw), Math.ceil(raw)])]
    .map(distance => Math.max(0, Math.min(max, distance)));
  candidates.sort((a, b) => Math.abs(restorePuzzleTravel(a, max) - target) - Math.abs(restorePuzzleTravel(b, max) - target) || a - b);
  return candidates[0];
}

function buildRestoreVisionCandidates(local, maxTargetPng, count = 9) {
  const total = Math.max(3, Math.min(12, Math.floor(Number(count) || 9)));
  const max = Math.max(0, Math.floor(Number(maxTargetPng) || 0));
  const cssPerPng = Math.max(1e-9, Number(local && local.css_per_png || 1));
  const grid = Array.from({ length: total }, (_, index) => Math.round(max * index / Math.max(1, total - 1)));
  const usedIndexes = new Set();
  const edgeTolerance = max / Math.max(1, total - 1) / 2;
  for (const candidate of (local && local.candidates || []).slice(0, total)) {
    const x = Math.max(0, Math.min(max, Math.round(Number(candidate.target_left_png))));
    if (Math.min(x, max - x) <= edgeTolerance) continue;
    let nearest = -1, nearestDelta = Infinity;
    for (let index = 1; index < grid.length - 1; index++) {
      if (usedIndexes.has(index)) continue;
      const delta = Math.abs(grid[index] - x);
      if (delta < nearestDelta) { nearest = index; nearestDelta = delta; }
    }
    if (nearest >= 0 && nearestDelta <= edgeTolerance) {
      grid[nearest] = x;
      usedIndexes.add(nearest);
    }
  }
  const localByX = new Map((local && local.candidates || []).map(candidate => [Number(candidate.target_left_png), candidate]));
  return [...new Set(grid)].sort((a, b) => a - b).map(x => ({
    ...(localByX.get(x) || {}),
    target_left_png: x,
    distance_px: Number((x * cssPerPng).toFixed(3)),
  }));
}

function buildRestoreRefinementCandidates(targetLeft, candidates, maxTargetPng, count = 9) {
  const total = Math.max(5, Math.min(12, Math.floor(Number(count) || 9)));
  const max = Math.max(0, Math.floor(Number(maxTargetPng) || 0));
  const sorted = [...new Set((candidates || [])
    .map(candidate => Math.max(0, Math.min(max, Math.round(Number(candidate.target_left_png)))))
    .filter(Number.isFinite))].sort((a, b) => a - b);
  if (sorted.length < 2) return Array.from({ length: total }, (_, index) => Math.round(max * index / Math.max(1, total - 1)));
  const target = Math.max(0, Math.min(max, Number(targetLeft)));
  let nearest = 0;
  for (let index = 1; index < sorted.length; index++) {
    if (Math.abs(sorted[index] - target) < Math.abs(sorted[nearest] - target)) nearest = index;
  }
  let low = sorted[Math.max(0, nearest - 1)];
  let high = sorted[Math.min(sorted.length - 1, nearest + 1)];
  if (low === high) {
    const halfSpan = Math.max(4, Math.ceil(max / Math.max(2, sorted.length - 1)));
    low = Math.max(0, Math.floor(target - halfSpan));
    high = Math.min(max, Math.ceil(target + halfSpan));
  }
  return [...new Set(Array.from({ length: total }, (_, index) => Math.round(low + (high - low) * index / Math.max(1, total - 1))))];
}

function selectRestoreBoundaryFallback(boundary, local, pieceWidthCss) {
  const tolerance = Math.max(3, Number(pieceWidthCss || 0) * 0.1);
  const directions = (boundary && boundary.directions || [])
    .filter(candidate => candidate.score <= 22 && candidate.score_margin >= 0.35);
  const localCandidates = local && local.candidates || [];
  const matches = [];
  for (const direction of directions) {
    const cluster = directions.filter(candidate => Math.abs(candidate.distance_px - direction.distance_px) <= tolerance);
    if (cluster.length < 2) continue;
    const center = cluster.reduce((sum, candidate) => sum + candidate.distance_px, 0) / cluster.length;
    const localMatch = localCandidates
      .map(candidate => ({ ...candidate, delta_px: Math.abs(candidate.distance_px - center) }))
      .filter(candidate => candidate.delta_px <= tolerance)
      .sort((a, b) => a.delta_px - b.delta_px || a.score - b.score)[0];
    if (!localMatch) continue;
    const evidence = [...cluster.map(candidate => candidate.distance_px), localMatch.distance_px].sort((a, b) => a - b);
    const middle = Math.floor(evidence.length / 2);
    const target = evidence.length % 2 ? evidence[middle] : (evidence[middle - 1] + evidence[middle]) / 2;
    matches.push({
      distance_px: Number(target.toFixed(3)),
      confidence: Number(Math.min(...cluster.map(candidate => Math.max(0.7, candidate.confidence))).toFixed(4)),
      tolerance_px: Number(tolerance.toFixed(3)),
      directions: cluster.map(candidate => candidate.direction),
      direction_targets_px: cluster.map(candidate => candidate.distance_px),
      local_target_px: localMatch.distance_px,
      local_score: localMatch.score,
      spread_px: Math.max(...evidence) - Math.min(...evidence),
    });
  }
  matches.sort((a, b) => a.spread_px - b.spread_px || b.directions.length - a.directions.length);
  return matches[0] || null;
}
function detectGapBySlotMask(bg, puzzle) {
  const pieceBox = alphaBounds(puzzle);
  if (!pieceBox) return null;
  const width = bg.width, height = bg.height, mask = new Uint8Array(width * height);
  for (let y = 0; y < height; y++) for (let x = Math.floor(width * .12); x < width; x++) {
    const i = (y * width + x) * 4, r = bg.data[i], g = bg.data[i + 1], b = bg.data[i + 2], a = bg.data[i + 3], mx = Math.max(r, g, b), mn = Math.min(r, g, b);
    if (a > 180 && mx > 185 && mx - mn < 80) mask[y * width + x] = 1;
  }
  const seen = new Uint8Array(width * height), comps = [], qx = [], qy = [];
  for (let sy = 0; sy < height; sy++) for (let sx = Math.floor(width * .12); sx < width; sx++) {
    const start = sy * width + sx;
    if (!mask[start] || seen[start]) continue;
    let head = 0, tail = 0; qx[tail] = sx; qy[tail] = sy; tail++; seen[start] = 1;
    let minX = sx, maxX = sx, minY = sy, maxY = sy, count = 0;
    while (head < tail) {
      const x = qx[head], y = qy[head]; head++; count++;
      if (x < minX) minX = x; if (x > maxX) maxX = x; if (y < minY) minY = y; if (y > maxY) maxY = y;
      for (let ny = y - 1; ny <= y + 1; ny++) { if (ny < 0 || ny >= height) continue; for (let nx = x - 1; nx <= x + 1; nx++) { if (nx < 0 || nx >= width) continue; const ni = ny * width + nx; if (!mask[ni] || seen[ni]) continue; seen[ni] = 1; qx[tail] = nx; qy[tail] = ny; tail++; } }
    }
    const bw = maxX - minX + 1, bh = maxY - minY + 1;
    const overlapY = Math.max(0, Math.min(maxY, pieceBox.maxY) - Math.max(minY, pieceBox.minY) + 1);
    const yCenterDelta = Math.abs((minY + maxY) / 2 - (pieceBox.minY + pieceBox.maxY) / 2);
    if (bw >= 24 && bw <= 75 && bh >= 24 && bh <= 75 && count >= 240 && count <= 3200 && overlapY >= Math.min(18, pieceBox.height * .45) && yCenterDelta <= Math.max(18, pieceBox.height * .45)) {
      const aspectPenalty = Math.abs(bw - pieceBox.width) + Math.abs(bh - pieceBox.height);
      comps.push({ minX, maxX, minY, maxY, width: bw, height: bh, count, overlapY, score: count - aspectPenalty * 20 + overlapY * 25 });
    }
  }
  comps.sort((a, b) => b.score - a.score);
  const best = comps[0];
  return best ? { x: Math.max(0, best.minX - pieceBox.minX), width: bg.width, height: bg.height, source: 'slot-mask', component: best, pieceBox } : null;
}
function detectGapByLightPatch(bg, puzzle) {
  const pieceBox = alphaBounds(puzzle);
  if (!pieceBox) return null;
  const points = [], edgePoints = [];
  for (let y = pieceBox.minY; y <= pieceBox.maxY; y++) for (let x = pieceBox.minX; x <= pieceBox.maxX; x++) {
    const idx = (y * puzzle.width + x) * 4;
    if (puzzle.data[idx + 3] <= 40) continue;
    points.push({ x, y });
    let edge = false;
    for (const [dx, dy] of [[1, 0], [-1, 0], [0, 1], [0, -1]]) {
      const xx = x + dx, yy = y + dy;
      if (xx < 0 || yy < 0 || xx >= puzzle.width || yy >= puzzle.height || puzzle.data[(yy * puzzle.width + xx) * 4 + 3] <= 40) { edge = true; break; }
    }
    if (edge) edgePoints.push({ x, y });
  }
  if (!points.length) return null;
  function lumaScore(i) {
    const r = bg.data[i], g = bg.data[i + 1], b = bg.data[i + 2];
    const mx = Math.max(r, g, b), mn = Math.min(r, g, b), avg = (r + g + b) / 3;
    return avg - (mx - mn) * 0.25;
  }
  let best = null;
  const startX = Math.floor(bg.width * .12);
  for (let x = startX; x <= bg.width - puzzle.width; x++) {
    let score = 0, edgeScore = 0;
    for (const p of points) score += lumaScore((p.y * bg.width + x + p.x) * 4);
    for (const p of edgePoints) edgeScore += lumaScore((p.y * bg.width + x + p.x) * 4);
    score /= points.length;
    edgeScore = edgePoints.length ? edgeScore / edgePoints.length : 0;
    const combined = score + edgeScore * 0.06;
    if (!best || combined > best.combined) best = { x: Math.max(0, x - pieceBox.minX), width: bg.width, height: bg.height, source: 'slot-light', score: Math.round(score * 10) / 10, edgeScore: Math.round(edgeScore * 10) / 10, combined: Math.round(combined * 10) / 10, points: points.length, edgePoints: edgePoints.length, pieceBox };
  }
  return best;
}

function detectGapByPuzzle(bgBuf, puzBuf) {
  const bg = PNG.sync.read(bgBuf), puzzle = PNG.sync.read(puzBuf);
  const slot = detectGapBySlotMask(bg, puzzle);
  const light = detectGapByLightPatch(bg, puzzle);
  const slotOnly = process.env.LISTENER_SLOT_ONLY === '1';
  if (slot) {
    if (slotOnly) return slot;
    const c = slot.component || {};
    const weakSlot = (c.score || 0) < 800 || (c.count || 0) < 500 || (c.width && slot.pieceBox && c.width < slot.pieceBox.width * .70) || (c.height && slot.pieceBox && c.height < slot.pieceBox.height * .60);
    const nearLight = light && Math.abs(light.x - slot.x) <= Math.max(60, (slot.pieceBox && slot.pieceBox.width || 50) * 1.4);
    if (weakSlot && nearLight && light.score >= 120) return { ...light, slotCandidate: slot };
    return light ? { ...slot, lightCandidate: light } : slot;
  }
  if (slotOnly) return null;
  if (light && light.score >= 120) return light;
  const bgEdge = sobelMagnitude(bg), edgePoints = [];
  for (let y = 1; y < puzzle.height - 1; y++) for (let x = 1; x < puzzle.width - 1; x++) {
    const idx = (y * puzzle.width + x) * 4;
    if (puzzle.data[idx + 3] < 40) continue;
    const l = puzzle.data[(y * puzzle.width + x - 1) * 4 + 3], r = puzzle.data[(y * puzzle.width + x + 1) * 4 + 3], u = puzzle.data[((y - 1) * puzzle.width + x) * 4 + 3], d = puzzle.data[((y + 1) * puzzle.width + x) * 4 + 3];
    if (l < 40 || r < 40 || u < 40 || d < 40) edgePoints.push({ x, y });
  }
  let bestX = 0, bestScore = -Infinity;
  for (let x = Math.floor(bg.width * .12); x <= bg.width - puzzle.width; x++) {
    let score = 0; for (const p of edgePoints) score += bgEdge[p.y * bg.width + x + p.x] || 0;
    if (score > bestScore) { bestScore = score; bestX = x; }
  }
  return { x: bestX, width: bg.width, height: bg.height, source: 'puzzle-edge', score: Math.round(bestScore), edgePoints: edgePoints.length, pieceBox: alphaBounds(puzzle) };
}

function buildHumanTrajectory(startX, startY, distance) {
  const pts = [];
  const total = 1900 + Math.floor(Math.random() * 1300);
  const steps = 85 + Math.floor(Math.random() * 45);
  const overshoot = 3 + Math.random() * 6;
  let lastX = startX;
  for (let i = 1; i <= steps; i++) {
    const p = i / steps;
    let target;
    if (p < 0.72) {
      const q = p / 0.72;
      target = distance * (1 - Math.pow(1 - q, 2.6)) * 0.88;
    } else if (p < 0.88) {
      target = distance * 0.88 + (distance * 0.12 + overshoot) * ((p - 0.72) / 0.16);
    } else {
      target = distance + overshoot * (1 - (p - 0.88) / 0.12);
    }
    const wobble = Math.sin(p * Math.PI * 6) * (1.5 + Math.random() * 1.2);
    let x = startX + target + wobble;
    if (Math.random() < 0.13 && i > 8 && i < steps - 8) x -= 1 + Math.random() * 3;
    if (x < lastX - 4) x = lastX - 4;
    lastX = x;
    pts.push({
      x,
      y: startY + Math.sin(p * Math.PI * 2.2) * (1.5 + Math.random()) + (Math.random() - 0.5) * 2.5,
      t: Math.round(total * p + Math.random() * 12),
    });
  }
  pts.push({ x: startX + distance, y: startY + (Math.random() - 0.5), t: total + 80 });
  pts.__meta = { total, steps, pointCount: pts.length, overshoot: Number(overshoot.toFixed(3)), style: 'human' };
  return pts;
}

function buildTrajectory(startX, startY, distance, style, profileOverrides) {
  if (style === 'human' || process.env.LISTENER_TRAJECTORY_STYLE === 'human') return buildHumanTrajectory(startX, startY, distance);
  const isOrganic = (style === 'organic' || process.env.LISTENER_TRAJECTORY_STYLE === 'organic');
  const pts = [];
  const total = (profileOverrides && profileOverrides.totalMs) || num('LISTENER_TOTAL_MS', 500);
  const steps = (profileOverrides && profileOverrides.steps) || num('LISTENER_STEPS', 25);
  const overshoot = num('LISTENER_OVERSHOOT_PX', 2 + Math.random() * 3);
  let hesitationIdx = -1, hesitationCount = 0, hesitationDt = 0;
  let backtrackIdx = -1, backtrackAmt = 0;
  let wiggleFrom = steps + 1;
  if (isOrganic) {
    hesitationIdx = Math.floor(steps * (0.30 + Math.random() * 0.35));
    hesitationCount = 2 + Math.floor(Math.random() * 3);
    hesitationDt = 60 + Math.floor(Math.random() * 140);
    if (Math.random() < 0.50) {
      backtrackIdx = Math.floor(steps * (0.84 + Math.random() * 0.10));
      backtrackAmt = 2 + Math.random() * 4;
    }
    wiggleFrom = steps - (2 + Math.floor(Math.random() * 4));
  }
  let lastX = startX;
  let extraT = 0;
  for (let i = 1; i <= steps; i++) {
    const p = i / steps;
    let target;
    if (p < .18) { const q = p / .18; target = distance * (.08 * q + .06 * q * q); }
    else if (p < .76) { const q = (p - .18) / .58; target = distance * (.14 + .74 * (1 - Math.pow(1 - q, 2.15))); }
    else if (p < .91) { const q = (p - .76) / .15; target = distance * (.88 + .12 * q) + overshoot * Math.sin(q * Math.PI * .8); }
    else { const q = (p - .91) / .09; target = distance + overshoot * (1 - q); }
    let x = startX + target + Math.sin(p * Math.PI * 5.2) * (0.7 + Math.random() * 0.9);
    let y = startY + Math.sin(p * Math.PI * 1.55) * (0.5 + Math.random() * .7) + (Math.random() * 2 - 1) * .55;
    let t = Math.round(total * p + Math.random() * 8);
    if (isOrganic) {
      if (i >= hesitationIdx && i < hesitationIdx + hesitationCount) {
        extraT += hesitationDt;
        x += (Math.random() - 0.5) * 1.2;
        y += (Math.random() - 0.5) * 1.0;
      }
      if (backtrackIdx > 0 && i >= backtrackIdx) {
        const bt = backtrackAmt * Math.pow((i - backtrackIdx) / Math.max(1, steps - backtrackIdx), 0.7);
        x -= bt;
      }
      if (i >= wiggleFrom) {
        x += (Math.random() - 0.5) * 3.0;
        y += (Math.random() - 0.5) * 1.8;
      }
      t += extraT;
      if (x < lastX - 3) x = lastX - 2 + Math.random();
      if (x > startX + distance + overshoot + 2) x = startX + distance + overshoot + Math.random();
      lastX = x;
    }
    pts.push({ x, y, t });
  }
  pts.push({ x: startX + distance, y: startY + (Math.random() * 2 - 1) * .25, t: total + extraT + 120 });
  pts.__meta = { total: total + extraT, steps, pointCount: pts.length, overshoot: Number(overshoot.toFixed(3)), style: isOrganic ? 'organic' : 'default', organic: isOrganic ? { hesitationIdx, hesitationCount, hesitationDt, backtrackIdx, backtrackAmt, wiggleFrom } : null };
  return pts;
}

function candidateMetrics(state, gap) {
  const bodyW = state.bodyRect?.width || 300, sliderW = state.sliderRect?.width || 40;
  const raw = Math.round(gap.x * (bodyW / (gap.width || bodyW || 1)));
  const effectiveOffset = num('LISTENER_OFFSET', 0);
  const baseDelta = num('LISTENER_BASE_DELTA', Number(STABLE_PROFILE.baseDelta)) + effectiveOffset;
  const max = Math.round(bodyW - sliderW);
  const maxMargin = num('LISTENER_MAX_MARGIN_PX', 0);
  const maxAllowed = Math.max(12, max - Math.max(0, maxMargin));
  const c = gap.component || {};
  const p = gap.pieceBox || {};
  const scale = bodyW / (gap.width || bodyW || 1);
  const distanceMode = process.env.LISTENER_DISTANCE_MODE || 'raw-plus-delta';
  let targetDistance = raw + baseDelta;
  if (distanceMode === 'piece-center') targetDistance = raw + Math.round(((p.width || 0) / 2) * scale) + effectiveOffset;
  else if (distanceMode === 'slot-center' && gap.component) targetDistance = Math.round(((c.minX + c.maxX) / 2) * scale) + effectiveOffset;
  else if (distanceMode === 'slot-min-plus-delta' && gap.component) targetDistance = Math.round(c.minX * scale) + baseDelta;
  const distance = Math.max(12, Math.min(Math.round(targetDistance), maxAllowed));
  const reasons = [];
  const minRaw = process.env.LISTENER_RAW_MIN === undefined ? null : Number(process.env.LISTENER_RAW_MIN);
  const maxRaw = process.env.LISTENER_RAW_MAX === undefined ? null : Number(process.env.LISTENER_RAW_MAX);
  const minDist = process.env.LISTENER_DISTANCE_MIN === undefined ? null : Number(process.env.LISTENER_DISTANCE_MIN);
  const maxDist = process.env.LISTENER_DISTANCE_MAX === undefined ? null : Number(process.env.LISTENER_DISTANCE_MAX);
  if (Number.isFinite(minRaw) && raw < minRaw) reasons.push(`raw<${minRaw}`);
  if (Number.isFinite(maxRaw) && raw > maxRaw) reasons.push(`raw>${maxRaw}`);
  if (Number.isFinite(minDist) && distance < minDist) reasons.push(`distance<${minDist}`);
  if (Number.isFinite(maxDist) && distance > maxDist) reasons.push(`distance>${maxDist}`);
  const requireSource = process.env.LISTENER_REQUIRE_GAP_SOURCE === undefined ? STABLE_PROFILE.requireGapSource : process.env.LISTENER_REQUIRE_GAP_SOURCE;
  if (requireSource && gap.source !== requireSource) reasons.push(`source:${gap.source}`);
  return { raw, distance, max, maxAllowed, distanceMode, effectiveOffset, baseDelta, source: gap.source, componentMinY: c.minY, componentMaxY: c.maxY, componentScore: c.score, componentCount: c.count, ok: reasons.length === 0, reasons };
}

function makeFingerprint(seedInput) {
  const salt = process.env.FINGERPRINT_SALT || '';
  const seed = hash32(`${seedInput}:${Date.now()}:${Math.random()}:${salt}`);
  let x = seed >>> 0;
  const rnd = () => { x = (Math.imul(1664525, x) + 1013904223) >>> 0; return x / 0x100000000; };
  const pick = (arr) => arr[Math.floor(rnd() * arr.length) % arr.length];
  const viewports = [
    { width: 1920, height: 1080 }, { width: 1680, height: 1050 }, { width: 1600, height: 900 },
    { width: 1536, height: 864 }, { width: 1440, height: 900 }, { width: 1366, height: 768 }, { width: 1280, height: 720 },
  ];
  const vp = pick(viewports);
  const chromeVersion = process.env.CHROME_UA_VERSION || '148.0.0.0';
  const major = chromeVersion.split('.')[0] || '148';
  const language = pick(['en-US', 'en-GB', 'zh-CN']);
  const languages = language === 'en-US' ? ['en-US', 'en'] : (language === 'en-GB' ? ['en-GB', 'en-US', 'en'] : ['zh-CN', 'en-US', 'en']);
  const timezone = pick(['America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'Asia/Shanghai', 'Europe/London', 'Europe/Berlin']);
  return {
    ua: process.env.USER_AGENT || `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion} Safari/537.36`,
    chromeVersion, chromeMajor: major,
    acceptLanguage: `${language},en;q=0.9`, language, languages,
    platform: 'Linux x86_64',
    hardwareConcurrency: pick([2, 4, 6, 8]),
    deviceMemory: pick([2, 4, 8, 16]),
    maxTouchPoints: 0,
    timezone,
    width: vp.width, height: vp.height,
    screenWidth: vp.width, screenHeight: vp.height,
    deviceScaleFactor: 1,
  };
}

function requestCarriesCaptchaVerifyParam(postData) {
  return /captchaVerifyParam/i.test(String(postData || ''));
}

function isAliyunVerificationEndpoint(url) {
  try {
    const host = new URL(String(url || '')).hostname.toLowerCase();
    return /(?:^|\.)captcha-open(?:-[a-z0-9-]+)?\.aliyuncs\.com$/.test(host);
  } catch {
    return false;
  }
}

function responseDecisionSummary(text) {
  const raw = String(text || '');
  if (!raw) return { kind: 'empty' };
  let parsed;
  try { parsed = JSON.parse(raw); } catch {
    const preview = raw
      .replace(/\bBearer\s+\S+/gi, 'Bearer [redacted]')
      .replace(/\b[A-Za-z0-9_-]{32,}\b/g, '[redacted]')
      .replace(/((?:captcha|password|secret|session|ticket|token)[^=:\s]{0,20}[=:]\s*)[^\s&;,]+/gi, '$1[redacted]')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 500);
    return { kind: 'text', preview };
  }
  const decisionKey = /^(?:code|status|statusCode|success|ok|valid|verified|verifyResult|verifyCode|result|resultObject|message|msg|reason|error|errorCode|errorMessage)$/i;
  const sensitiveKey = /(?:captcha|certify|credential|device|password|secret|security|session|sign(?:ature)?|ticket|token|authorization|cookie)/i;
  function visit(value, depth = 0) {
    if (value == null || typeof value === 'boolean' || typeof value === 'number') return value;
    if (typeof value === 'string') return value.slice(0, 1000);
    if (depth >= 4) return Array.isArray(value) ? `[array:${value.length}]` : '[object]';
    if (Array.isArray(value)) return value.slice(0, 10).map(item => visit(item, depth + 1));
    if (typeof value !== 'object') return String(value).slice(0, 1000);
    const out = {};
    for (const [key, item] of Object.entries(value).slice(0, 80)) {
      if (sensitiveKey.test(key)) {
        out[key] = '[redacted]';
      } else if (decisionKey.test(key)) {
        out[key] = visit(item, depth + 1);
      } else if (item && typeof item === 'object') {
        const nested = visit(item, depth + 1);
        if (nested && typeof nested === 'object' && !Array.isArray(nested) && Object.keys(nested).length) out[key] = nested;
      }
    }
    return out;
  }
  return { kind: 'json', value: visit(parsed) };
}

async function applyPreCaptchaFills(page, fills) {
  if (!Array.isArray(fills) || !fills.length) return [];
  const results = [];
  for (const fill of fills) {
    const selector = String(fill && fill.selector || '').trim();
    if (!selector) throw new Error('pre-captcha fill selector is required');
    const value = String(fill && fill.value != null ? fill.value : '');
    const timeout = Math.max(1, Number(fill && fill.timeoutMs) || 15000);
    const element = await page.waitForSelector(selector, { visible: true, timeout });
    if (!element) throw new Error(`pre-captcha fill target not found: ${selector}`);
    await element.click({ clickCount: 3 });
    await page.keyboard.press('Backspace').catch(() => {});
    await element.type(value, { delay: Math.max(0, Number(fill && fill.delayMs) || 5) });
    results.push({ selector, filled: true, valueLength: value.length });
  }
  return results;
}

async function applyPreCaptchaPresses(page, presses) {
  if (!Array.isArray(presses) || !presses.length) return [];
  const results = [];
  for (const value of presses) {
    const key = String(value || '').trim();
    if (!key) throw new Error('pre-captcha press key is required');
    await page.keyboard.press(key);
    results.push({ key, pressed: true });
  }
  return results;
}

async function applyPreCaptchaClicks(page, clicks) {
  if (!Array.isArray(clicks) || !clicks.length) return [];
  const timeout = Math.max(1, num('ALIYUN_PRE_CLICK_TIMEOUT_MS', 15000));
  const results = [];
  for (const value of clicks) {
    const locator = String(value || '').trim();
    if (!locator) throw new Error('pre-captcha click locator is required');
    if (locator.startsWith('text:')) {
      const text = locator.slice(5).trim();
      if (!text) throw new Error('pre-captcha click text is required');
      await page.waitForFunction(expected => {
        const candidates = document.querySelectorAll('button,a,[role="button"],[onclick]');
        return Array.from(candidates).some(node => {
          const rect = node.getBoundingClientRect();
          return rect.width > 1 && rect.height > 1 && String(node.textContent || '').trim() === expected;
        });
      }, { timeout }, text);
      const clicked = await page.evaluate(expected => {
        const candidates = document.querySelectorAll('button,a,[role="button"],[onclick]');
        const node = Array.from(candidates).find(candidate => {
          const rect = candidate.getBoundingClientRect();
          return rect.width > 1 && rect.height > 1 && String(candidate.textContent || '').trim() === expected;
        });
        if (!node) return false;
        node.click();
        return true;
      }, text);
      if (!clicked) throw new Error(`pre-captcha click text not found: ${text}`);
      results.push({ locator: `text:${text}`, clicked: true });
    } else {
      const element = await page.waitForSelector(locator, { visible: true, timeout });
      if (!element) throw new Error(`pre-captcha click target not found: ${locator}`);
      await element.click({ delay: 50 });
      results.push({ locator, clicked: true });
    }
    await sleep(150);
  }
  return results;
}

function mutateCaptchaVerifyParam(postData, replacement) {
  const raw = String(postData || '');
  try {
    const parsed = JSON.parse(raw);
    let changed = false;
    function visit(value, depth = 0) {
      if (!value || typeof value !== 'object' || depth > 8) return;
      for (const key of Object.keys(value)) {
        if (/^captchaVerifyParam$/i.test(key)) {
          value[key] = replacement;
          changed = true;
        } else {
          visit(value[key], depth + 1);
        }
      }
    }
    visit(parsed);
    if (changed) return JSON.stringify(parsed);
  } catch {}
  try {
    const params = new URLSearchParams(raw);
    let changed = false;
    for (const key of Array.from(params.keys())) {
      if (/^captchaVerifyParam$/i.test(key)) {
        params.set(key, replacement);
        changed = true;
      }
    }
    if (changed) return params.toString();
  } catch {}
  return null;
}

function summaryMatches(summary, pattern) {
  if (!pattern) return false;
  const text = JSON.stringify(summary || {});
  try { return new RegExp(String(pattern), 'i').test(text); } catch { return text.includes(String(pattern)); }
}

function classifySiteVerificationEvidence(result, options = {}) {
  const primary = result && result.siteVerificationNetwork;
  const control = result && result.siteVerificationControlNetwork;
  const acceptedPattern = options.siteVerificationAcceptedPattern || '';
  const rejectedPattern = options.siteVerificationRejectedPattern || '';
  const responsesDiffer = !!primary && !!control && JSON.stringify(primary.responseSummary) !== JSON.stringify(control.responseSummary);
  const acceptedPatternMatched = !!primary && summaryMatches(primary.responseSummary, acceptedPattern);
  const rejectedPatternMatched = !!control && summaryMatches(control.responseSummary, rejectedPattern);
  const siteSecondaryPass = responsesDiffer && acceptedPatternMatched && rejectedPatternMatched;
  return {
    classification: siteSecondaryPass ? 'site_secondary_check_pass' : 'site_secondary_check_not_proven',
    site_secondary_pass: siteSecondaryPass,
    responses_differ: responsesDiffer,
    accepted_pattern_configured: !!acceptedPattern,
    accepted_pattern_matched: acceptedPatternMatched,
    rejected_pattern_configured: !!rejectedPattern,
    rejected_pattern_matched: rejectedPatternMatched,
    vendor_production_pass: verifyPassed(result && result.verifyResponse),
  };
}

async function runSiteVerificationControl(page, result, options = {}) {
  const request = result && result.__siteVerificationRequest;
  if (!request) return { attempted: false, error: 'site verification request not captured' };
  const marker = `antibot-invalid-control-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const body = mutateCaptchaVerifyParam(request.postData, marker);
  if (!body) return { attempted: false, error: 'captchaVerifyParam could not be mutated' };
  result.__siteVerificationControlMarker = marker;
  const replay = await page.evaluate(async ({ url, method, body, contentType }) => {
    try {
      const response = await fetch(url, {
        method,
        credentials: 'include',
        headers: contentType ? { 'Content-Type': contentType } : {},
        body,
      });
      await response.text().catch(() => '');
      return { attempted: true, status: response.status };
    } catch (error) {
      return { attempted: true, error: String(error && error.message || error) };
    }
  }, { url: request.url, method: request.method, body, contentType: request.contentType });
  const started = Date.now();
  const timeoutMs = Math.max(500, Number(options.siteVerificationControlWaitMs) || 10000);
  while (!result.siteVerificationControlNetwork && Date.now() - started < timeoutMs) await sleep(100);
  return {
    ...replay,
    response_observed: !!result.siteVerificationControlNetwork,
    elapsed_ms: Date.now() - started,
  };
}

function attachResponseLogger(page, result) {
  if (!page || !result || result.__responseLoggerAttached) return;
  Object.defineProperty(result, '__responseLoggerAttached', { value: true, enumerable: false, configurable: true });
  Object.defineProperty(result, '__siteVerificationRequest', { value: null, writable: true, enumerable: false, configurable: true });
  Object.defineProperty(result, '__siteVerificationControlMarker', { value: '', writable: true, enumerable: false, configurable: true });
  page.on('response', async res => {
    const url = res.url();
    const req = res.request();
    const postData = req.postData() || '';
    const vendorUrl = /captcha|aliyun|cloudauth|VerifyCaptcha/i.test(url);
    const siteVerificationRequest = requestCarriesCaptchaVerifyParam(postData);
    if (!vendorUrl && !siteVerificationRequest) return;
    let text = ''; try { text = await res.text(); } catch {}
    if (siteVerificationRequest && !isAliyunVerificationEndpoint(url)) {
      let contentType = '';
      let requestContentType = '';
      try { contentType = String(res.headers()['content-type'] || '').slice(0, 200); } catch {}
      try { requestContentType = String(req.headers()['content-type'] || '').slice(0, 200); } catch {}
      const siteItem = {
        at: Date.now(),
        method: req.method(),
        url,
        status: res.status(),
        requestBodyLen: postData.length,
        responseBodyLen: text.length,
        contentType,
        responseSummary: responseDecisionSummary(text),
      };
      const isControl = !!result.__siteVerificationControlMarker && postData.includes(result.__siteVerificationControlMarker);
      if (isControl) {
        result.siteVerificationControlNetwork = siteItem;
      } else {
        result.__siteVerificationRequest = { url, method: req.method(), postData, contentType: requestContentType };
        result.siteVerificationNetwork = siteItem;
        result.siteVerificationNetworks = result.siteVerificationNetworks || [];
        result.siteVerificationNetworks.push(siteItem);
        while (result.siteVerificationNetworks.length > 20) result.siteVerificationNetworks.shift();
      }
      return;
    }
    const isVerifyRequest = /Action=VerifyCaptchaV3|VerifyIntelligentCaptcha|CaptchaVerifyParam/i.test(`${url} ${postData}`);
    const item = { at: Date.now(), method: req.method(), url, status: res.status(), postDataLen: postData.length, isVerifyRequest, text: text.slice(0, 20000) };
    result.net.push(item);
    try {
      const parsed = JSON.parse(text);
      const payload = parsed && parsed.Result && typeof parsed.Result === 'object'
        ? parsed.Result
        : parsed;
      const vendorType = String(payload && payload.CaptchaType || '').trim().toUpperCase();
      const captchaType = normalizeVendorCaptchaType(vendorType);
      if (captchaType) {
        result.initCaptcha = {
          vendorType,
          captchaType,
          staticPath: String(payload.StaticPath || '').slice(0, 200),
        };
      }
    } catch {}
    if (isVerifyRequest && /VerifyCode|VerifyResult|[TF]\d{3}/.test(text)) {
      result.verifyNetwork = item;
      try { const j = JSON.parse(text); result.verifyResponse = j.Result || j; } catch {}
    }
  });
}

async function installHooks(page, fp = null, swapData = null, captureInternals = false) {
  await page.evaluateOnNewDocument((fp, swapData, captureInternals) => {
    Object.defineProperty(navigator, 'webdriver', { get: () => false, configurable: true });
    if (fp) {
      if (fp.hardwareConcurrency != null) Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => fp.hardwareConcurrency, configurable: true });
      if (fp.deviceMemory != null) Object.defineProperty(navigator, 'deviceMemory', { get: () => fp.deviceMemory, configurable: true });
      if (fp.maxTouchPoints != null) Object.defineProperty(navigator, 'maxTouchPoints', { get: () => fp.maxTouchPoints, configurable: true });
      if (fp.language != null) Object.defineProperty(navigator, 'language', { get: () => fp.language, configurable: true });
      if (fp.languages != null) Object.defineProperty(navigator, 'languages', { get: () => fp.languages, configurable: true });
      if (fp.platform != null) Object.defineProperty(navigator, 'platform', { get: () => fp.platform, configurable: true });
    }
    window.__AC = { listeners: [], calls: [], errors: [], jsonHits: [], payloads: [], formOps: [], trackLists: [], captchaParams: [], btoaHits: [], sfcHits: [], joinHits: [], strHits: [], u8Hits: [], addedAt: Date.now() };
    const nativeToString = Function.prototype.toString;
    const origAdd = EventTarget.prototype.addEventListener;
    const origRemove = EventTarget.prototype.removeEventListener;
    let nextId = 1;
    function pushBounded(name, item, limit) { try { const arr = window.__AC[name]; arr.push(item); while (arr.length > limit) arr.shift(); } catch {} }
    function clip(v, n = 20000) { try { return String(v == null ? '' : v).slice(0, n); } catch { return ''; } }
    function stack() { try { return clip((new Error()).stack || '', 4000); } catch { return ''; } }
    function targetInfo(t) { try { const r = t && t.getBoundingClientRect && t.getBoundingClientRect(); return { tag: t === window ? 'Window' : (t === document ? 'HTMLDocument' : (t && t.tagName) || Object.prototype.toString.call(t)), id: t && t.id || '', cls: String(t && t.className || '').slice(0, 160), rect: r ? { x: r.x, y: r.y, w: r.width, h: r.height } : null }; } catch { return { tag: String(t) }; } }
    function optCapture(options) { try { return options === true || !!(options && options.capture); } catch { return false; } }
    function snapshotValue(v, depth = 0, seen = []) {
      try {
        if (v == null || typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') return v;
        if (typeof v === 'bigint') return String(v);
        if (typeof v === 'function') return `[Function ${v.name || ''}]`;
        if (seen.includes(v)) return '[Circular]';
        if (depth >= 3) return Object.prototype.toString.call(v);
        const nextSeen = seen.concat([v]);
        if (typeof FormData !== 'undefined' && v instanceof FormData) {
          const out = {};
          v.forEach((val, key) => { out[key] = snapshotValue(val, depth + 1, nextSeen); });
          return { __type: 'FormData', fields: out };
        }
        if (typeof URLSearchParams !== 'undefined' && v instanceof URLSearchParams) return { __type: 'URLSearchParams', value: String(v) };
        if (typeof Blob !== 'undefined' && v instanceof Blob) return { __type: 'Blob', size: v.size, type: v.type };
        if (v instanceof ArrayBuffer) {
          try {
            const bytes = new Uint8Array(v);
            return { __type: 'ArrayBuffer', byteLength: v.byteLength, hex: Array.from(bytes.slice(0, 200)).map(b => b.toString(16).padStart(2, '0')).join('') };
          } catch { return { __type: 'ArrayBuffer', byteLength: v.byteLength }; }
        }
        if (ArrayBuffer.isView && ArrayBuffer.isView(v)) {
          try {
            return { __type: v.constructor && v.constructor.name || 'TypedArray', byteLength: v.byteLength, hex: Array.from(new Uint8Array(v.buffer, v.byteOffset, Math.min(v.byteLength, 200))).map(b => b.toString(16).padStart(2, '0')).join('') };
          } catch { return { __type: v.constructor && v.constructor.name || 'TypedArray', byteLength: v.byteLength }; }
        }
        if (Array.isArray(v)) return v.slice(0, 80).map(x => snapshotValue(x, depth + 1, nextSeen));
        const keys = Object.keys(v).slice(0, 80), out = {};
        for (const k of keys) out[k] = snapshotValue(v[k], depth + 1, nextSeen);
        return out;
      } catch (e) { return `[snapshot-error:${e && e.message || e}]`; }
    }
    function stringifyBody(body) {
      try {
        if (body == null) return '';
        if (typeof body === 'string') return body;
        if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) return body.toString();
        if (typeof FormData !== 'undefined' && body instanceof FormData) { const xs = []; body.forEach((v, k) => xs.push(`${k}=${typeof v === 'string' ? v : `[${v && v.constructor && v.constructor.name || typeof v}]`}`)); return xs.join('&'); }
        if (body instanceof ArrayBuffer || (ArrayBuffer.isView && ArrayBuffer.isView(body))) return `[binary:${body.byteLength || 0}]`;
        return JSON.stringify(snapshotValue(body));
      } catch { return clip(body); }
    }
    function interesting(s) { return /TrackList|deviceToken|captchaVerifyParam|VerifyCaptcha|xPos|slidePos|certifyId|SceneId|sceneId|sig|arg|captcha-open|"data":/i.test(String(s || '')); }
    EventTarget.prototype.addEventListener = function(type, listener, options) {
      try { window.__AC.listeners.push({ id: nextId++, at: Date.now(), type, target: this, listener, options, capture: optCapture(options), stack: stack(), src: typeof listener === 'function' ? nativeToString.call(listener).slice(0, 1000) : String(listener).slice(0, 1000), targetInfo: targetInfo(this), removed: false }); } catch {}
      return origAdd.apply(this, arguments);
    };
    EventTarget.prototype.removeEventListener = function(type, listener, options) {
      try { for (const r of window.__AC.listeners) if (!r.removed && r.type === type && r.listener === listener && r.target === this) r.removed = true; } catch {}
      return origRemove.apply(this, arguments);
    };
    const origJson = JSON.stringify;
    const origJsonStringify = JSON.stringify;
    JSON.stringify = function(v) {
      const s = origJson.apply(this, arguments);
      try {
        const hasTrack = v && (v.trackList !== undefined || v.TrackList !== undefined || v.data !== undefined || v.xPos !== undefined || v.slidePos !== undefined || v.SlidePos !== undefined || v.XPos !== undefined);
        if (interesting(s) || hasTrack) {
          pushBounded('jsonHits', { at: Date.now(), len: s.length, s: s.slice(0, 24000), value: snapshotValue(v), stack: stack() }, 120);
          // Deep capture by parsing the JSON string directly (complete object)
          try {
            const parsed = JSON.parse(s);
            if (parsed && (parsed.TrackList || parsed.trackList || parsed.data || parsed.Data || parsed.xPos || parsed.XPos || parsed.slidePos || parsed.SlidePos)) {
              pushBounded('trackLists', { at: Date.now(), parsed, stack: stack() }, 20);
            }
          } catch {}
        }
      } catch {}
      return s;
    };
    if (captureInternals) try {
      const origBtoa = window.btoa;
      window.btoa = function(v) {
        try {
          if (v && typeof v === 'string') {
            const isTracklike = v.length > 200 && /track|slide|pos|scene|certify/i.test(v);
            const isDataLength = v.length > 1200 && v.length < 2500;
            if (isTracklike || isDataLength) {
              pushBounded('btoaHits', { at: Date.now(), len: v.length, preview: clip(v, 500), stack: stack() }, 40);
            }
          }
        } catch {}
        return origBtoa.apply(this, arguments);
      };
    } catch {}
    if (captureInternals) try {
      if (typeof Uint8Array !== 'undefined') {
        const origU8 = Uint8Array;
        window.Uint8Array = function(...args) {
          const arr = new origU8(...args);
          try { if (arr.length > 200 && arr[0] === 0x25 && arr[1] === 0x13 && arr[2] === 0x27) pushBounded('u8Hits', { at: Date.now(), len: arr.length, first32: Array.from(arr.slice(0, 32)), stack: stack() }, 20); } catch {}
          return arr;
        };
        window.Uint8Array.prototype = origU8.prototype;
      }
    } catch {}
    try {
      const origOpen = XMLHttpRequest.prototype.open;
      const origSetHeader = XMLHttpRequest.prototype.setRequestHeader;
      const origSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function(method, url) {
        try { this.__AC_xhr = { method, url: String(url || ''), headers: {}, openedAt: Date.now() }; } catch {}
        return origOpen.apply(this, arguments);
      };
      XMLHttpRequest.prototype.setRequestHeader = function(k, v) {
        try { if (this.__AC_xhr) this.__AC_xhr.headers[String(k)] = String(v); } catch {}
        return origSetHeader.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function(body) {
        let sendBody = body;
        try {
          const meta = this.__AC_xhr || {};
          const bodyText = stringifyBody(body);
          if (interesting(meta.url) || interesting(bodyText)) pushBounded('payloads', { at: Date.now(), via: 'xhr', method: meta.method || '', url: meta.url || '', headers: meta.headers || {}, bodyType: body && body.constructor && body.constructor.name || typeof body, bodyText: clip(bodyText, 50000), bodySnapshot: snapshotValue(body), stack: stack() }, 80);
          let captchaParam = null;
          if (typeof body === 'string' && body) {
            const m = body.match(/CaptchaVerifyParam=([^&]+)/i);
            if (m) try { captchaParam = decodeURIComponent(m[1]); } catch {}
          } else if (body && typeof FormData !== 'undefined' && body instanceof FormData) {
            try { body.forEach((v, k) => { if (/captchaVerifyParam/i.test(k)) captchaParam = String(v); }); } catch {}
          }
          if (captchaParam) {
            try {
              const obj = JSON.parse(captchaParam);
              pushBounded('captchaParams', { at: Date.now(), url: meta.url || '', param: obj }, 20);
              const runtimeSwap = window.__AC && window.__AC.poolSwap;
              const dataSwap = swapData || runtimeSwap || null;
              if (dataSwap && /VerifyCaptchaV3/i.test(meta.url || '')) {
                obj.data = dataSwap;
                const newCp = JSON.stringify(obj);
                if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
                  body.set('CaptchaVerifyParam', newCp);
                  sendBody = body;
                } else if (typeof FormData !== 'undefined' && body instanceof FormData) {
                  if (typeof body.set === 'function') body.set('CaptchaVerifyParam', newCp);
                  else body.append('CaptchaVerifyParam', newCp);
                  sendBody = body;
                } else if (typeof body === 'string') {
                  sendBody = body.replace(/CaptchaVerifyParam=[^&]+/i, 'CaptchaVerifyParam=' + encodeURIComponent(newCp));
                }
                pushBounded('payloads', { at: Date.now(), via: 'xhr-swap', url: meta.url || '', dataLen: String(dataSwap).length }, 80);
              }
            } catch {}
          }
        } catch {}
        return origSend.call(this, sendBody);
      };
    } catch {}
    try {
      const origFetch = window.fetch;
      if (origFetch) window.fetch = function(input, init) {
        try {
          const url = typeof input === 'string' ? input : (input && input.url) || '';
          const method = (init && init.method) || (input && input.method) || 'GET';
          const body = init && init.body;
          const bodyText = stringifyBody(body);
          if (interesting(url) || interesting(bodyText)) pushBounded('payloads', { at: Date.now(), via: 'fetch', method, url: String(url), bodyType: body && body.constructor && body.constructor.name || typeof body, bodyText: clip(bodyText, 50000), bodySnapshot: snapshotValue(body), stack: stack() }, 80);
          // Extract raw CaptchaVerifyParam before serialization
          let captchaParam = null;
          if (body) {
            if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
              captchaParam = body.get('CaptchaVerifyParam') || body.get('captchaVerifyParam');
            } else if (typeof FormData !== 'undefined' && body instanceof FormData) {
              try { body.forEach((v, k) => { if (/captchaVerifyParam/i.test(k)) captchaParam = String(v); }); } catch {}
            } else if (typeof body === 'string') {
              const m = body.match(/CaptchaVerifyParam=([^&]+)/i);
              if (m) try { captchaParam = decodeURIComponent(m[1]); } catch {}
            }
          }
          if (captchaParam) {
            try {
              const obj = JSON.parse(captchaParam);
              const st = (function(){ try { return (new Error()).stack || ''; } catch { return ''; } })();
              pushBounded('captchaParams', { at: Date.now(), url: String(url), param: obj, stack: st }, 20);
              // Swap data if requested (supports both immediate swapData and runtime poolSwap)
              const runtimeSwap = window.__AC && window.__AC.poolSwap;
              const dataSwap = swapData || runtimeSwap || null;
              if (dataSwap && /VerifyCaptchaV3/i.test(url)) {
                try {
                  obj.data = dataSwap;
                  const newCp = JSON.stringify(obj);
                  if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
                    body.set('CaptchaVerifyParam', newCp);
                    init = { ...init, body };
                  } else if (typeof FormData !== 'undefined' && body instanceof FormData) {
                    if (typeof body.set === 'function') body.set('CaptchaVerifyParam', newCp);
                    else body.append('CaptchaVerifyParam', newCp);
                    init = { ...init, body };
                  } else if (typeof body === 'string') {
                    init = { ...init, body: body.replace(/CaptchaVerifyParam=[^&]+/, 'CaptchaVerifyParam=' + encodeURIComponent(newCp)) };
                  }
                } catch {}
              }
            } catch {}
          }
        } catch {}
        return origFetch.call(this, input, init);
      };
    } catch {}
    try {
      const origAppend = FormData.prototype.append;
      const origSet = FormData.prototype.set;
      FormData.prototype.append = function(k, v) { try { if (interesting(k) || interesting(v)) pushBounded('formOps', { at: Date.now(), op: 'append', key: String(k), value: snapshotValue(v), stack: stack() }, 80); } catch {} return origAppend.apply(this, arguments); };
      if (origSet) FormData.prototype.set = function(k, v) { try { if (interesting(k) || interesting(v)) pushBounded('formOps', { at: Date.now(), op: 'set', key: String(k), value: snapshotValue(v), stack: stack() }, 80); } catch {} return origSet.apply(this, arguments); };
    } catch {}
    try {
      const uspAppend = URLSearchParams.prototype.append;
      const uspSet = URLSearchParams.prototype.set;
      URLSearchParams.prototype.append = function(k, v) { try { if (interesting(k) || interesting(v)) pushBounded('formOps', { at: Date.now(), op: 'urlappend', key: String(k), value: String(v), stack: stack() }, 80); } catch {} return uspAppend.apply(this, arguments); };
      URLSearchParams.prototype.set = function(k, v) { try { if (interesting(k) || interesting(v)) pushBounded('formOps', { at: Date.now(), op: 'urlset', key: String(k), value: String(v), stack: stack() }, 80); } catch {} return uspSet.apply(this, arguments); };
    } catch {}
    if (captureInternals) try {
      const origSFC = String.fromCharCode;
      String.fromCharCode = function(...args) {
        try { if (args.length > 1200 && args.length < 1500 && args[0] === 0x25 && args[1] === 0x13 && args[2] === 0x27) pushBounded('sfcHits', { at: Date.now(), len: args.length, first32: args.slice(0, 32), stack: stack() }, 20); } catch {}
        return origSFC.apply(this, args);
      };
    } catch {}
    if (captureInternals) try {
      const origJoin = Array.prototype.join;
      Array.prototype.join = function(sep) {
        try {
          if (this.length > 1200 && this.length < 1500) {
            const preview = this.slice(0, 10).map(x => typeof x === 'number' ? x : String(x).charCodeAt(0));
            if (preview[0] === 0x25 && preview[1] === 0x13 && preview[2] === 0x27) {
              pushBounded('joinHits', { at: Date.now(), len: this.length, first32: this.slice(0, 32), stack: stack() }, 20);
            }
          }
        } catch {}
        return origJoin.apply(this, arguments);
      };
    } catch {}
    if (captureInternals) try {
      const origCharAt = String.prototype.charAt;
      const origCharCodeAt = String.prototype.charCodeAt;
      String.prototype.charAt = function(i) {
        try { if (this.length > 1200 && this.length < 1500 && i === 0 && this.charCodeAt(0) === 0x25 && this.charCodeAt(1) === 0x13) pushBounded('strHits', { at: Date.now(), len: this.length, first32: this.slice(0, 32), stack: stack() }, 20); } catch {}
        return origCharAt.apply(this, arguments);
      };
    } catch {}

    if (captureInternals) try {
      window.__AC.foundTrackObjects = [];
      function isTrackLikeObj(o) {
        try {
          if (!o || typeof o !== 'object') return false;
          const keys = Object.keys(o);
          const hasMm = typeof o.mm === 'string' && o.mm.length > 40 && o.mm.includes('|');
          const hasMp = typeof o.mp === 'string' && o.mp.length > 40 && o.mp.includes('|');
          const hasMeta = keys.includes('startTime') || keys.includes('si') || (keys.includes('mm') && keys.includes('mp') && keys.includes('mc') && keys.includes('mu'));
          return hasMm && hasMp && hasMeta;
        } catch { return false; }
      }
      function scanObj(root, depth, seen) {
        try {
          if (depth <= 0 || !root || typeof root !== 'object' || seen.has(root)) return;
          seen.add(root);
          const keys = Object.keys(root).slice(0, 120);
          for (const k of keys) {
            try {
              const v = root[k];
              if (isTrackLikeObj(v)) {
                const ident = { key: k, keys: Object.keys(v), mmLen: v.mm.length, mpLen: v.mp.length, at: Date.now() };
                if (!window.__AC.foundTrackObjects.some(x => x.key === ident.key && x.mmLen === ident.mmLen)) {
                  window.__AC.foundTrackObjects.push(ident);
                }
              } else if (v && typeof v === 'object' && !Array.isArray(v)) {
                scanObj(v, depth - 1, seen);
              }
            } catch {}
          }
        } catch {}
      }
      setInterval(() => { try { scanObj(window, 2, new WeakSet()); } catch {} }, 800);
    } catch {}

    window.__AC_run = async function(spec) {
      const mode = spec.mode || 'nativecall';
      const slider = document.querySelector(spec.sliderSelector || '#aliyunCaptcha-sliding-slider');
      const body = document.querySelector(spec.bodySelector || '#aliyunCaptcha-sliding-body') || document.body;
      if (!slider) return { ok: false, error: 'slider-not-found' };
      function chainFor(tg) { const arr = []; let n = tg; while (n && n !== document && n !== window) { if (!arr.includes(n)) arr.push(n); n = n.parentNode; } arr.push(document); arr.push(window); return arr; }
      function fireDirect(type, x, y, buttons, target, t) {
        const ev = new MouseEvent(type, { bubbles: true, cancelable: true, view: window, clientX: x, clientY: y, screenX: (window.screenX || 0) + x, screenY: (window.screenY || 0) + y, button: 0, buttons });
        try { Object.defineProperty(ev, 'timeStamp', { configurable: true, get: () => t }); } catch {}
        target.dispatchEvent(ev);
        window.__AC.calls.push({ at: Date.now(), type, mode: 'dispatch', x: Math.round(x), y: Math.round(y), buttons });
      }
      function fireNative(type, x, y, buttons, target, t) {
        const path = chainFor(target);
        const ev = new MouseEvent(type, { bubbles: true, cancelable: true, view: window, clientX: x, clientY: y, screenX: (window.screenX || 0) + x, screenY: (window.screenY || 0) + y, button: 0, buttons });
        const def = (k, getter) => { try { Object.defineProperty(ev, k, { configurable: true, get: getter }); } catch {} };
        let current = null, phase = 2;
        def('target', () => target); def('srcElement', () => target); def('currentTarget', () => current); def('eventPhase', () => phase); def('path', () => path.slice()); def('timeStamp', () => t);
        try { ev.composedPath = () => path.slice(); } catch {}
        const all = window.__AC.listeners.filter(r => !r.removed && r.type === type);
        const invoke = [];
        for (const tg of path.slice().reverse()) for (const r of all.filter(r => r.target === tg && r.capture).sort((a, b) => a.id - b.id)) invoke.push({ r, phase: tg === target ? 2 : 1 });
        for (const tg of path) for (const r of all.filter(r => r.target === tg && !r.capture).sort((a, b) => a.id - b.id)) invoke.push({ r, phase: tg === target ? 2 : 3 });
        let called = 0, errs = [];
        for (const it of invoke) { try { current = it.r.target; phase = it.phase; const l = it.r.listener; if (typeof l === 'function') l.call(it.r.target, ev); else if (l && typeof l.handleEvent === 'function') l.handleEvent(ev); called++; } catch (e) { errs.push({ id: it.r.id, message: e && e.message || String(e) }); } }
        if (errs.length) window.__AC.errors.push({ at: Date.now(), type, errs });
        window.__AC.calls.push({ at: Date.now(), type, mode: 'nativecall', x: Math.round(x), y: Math.round(y), buttons, called, errs: errs.length });
      }
      const fire = mode === 'dispatch' ? fireDirect : fireNative;
      const base = performance.now() + 100;
      const sx = spec.startX, sy = spec.startY;
      for (const p of (spec.warm || [])) { fire('mousemove', p.x, p.y, 0, document.body, base + p.t); await new Promise(r => setTimeout(r, Math.max(0, p.dt || 8))); }
      fire('mousedown', sx, sy, 1, slider, base + 200);
      let lastT = 0;
      for (const p of spec.points) { const d = Math.max(0, Math.min(80, p.t - lastT)); lastT = p.t; if (d) await new Promise(r => setTimeout(r, d)); fire('mousemove', p.x, p.y, 1, document, base + 200 + p.t); }
      const hold = Math.max(0, (spec.releaseHoldMs || 0) + Math.floor(Math.random() * Math.max(0, spec.releaseHoldJitterMs || 0)));
      await new Promise(r => setTimeout(r, hold));
      const last = spec.points[spec.points.length - 1] || { x: sx, y: sy, t: 0 };
      fire('mouseup', last.x, last.y, 0, document, base + 420 + last.t);
      return { ok: true, listenerCount: window.__AC.listeners.length, calls: window.__AC.calls.slice(-40), errors: window.__AC.errors.slice(-20), jsonHits: window.__AC.jsonHits.slice(-20) };
    };
  }, fp, swapData, !!captureInternals);
}

async function setupDynamicJsForce(page) {
  const pe = String(process.env.ALIYUN_FORCE_DYNAMIC_PE || '').match(/\d+/)?.[0]?.padStart(3, '0');
  if (!pe) return null;
  const dir = path.join(ROOT, 'vendor', 'aliyun', 'dynamicjs');
  const file = fs.existsSync(dir) ? fs.readdirSync(dir).find(x => new RegExp(`^pe\\.${pe}\\..*\\.js$`).test(x)) : '';
  if (!file) throw new Error(`ALIYUN_FORCE_DYNAMIC_PE=${pe} but asset not found under ${dir}`);
  const body = fs.readFileSync(path.join(dir, file));
  await page.setRequestInterception(true);
  page.on('request', req => {
    const url = req.url();
    if (/\/captcha-frontend\/dynamicJS\//.test(url) && /\/pe\.\d+\./.test(url)) return req.respond({ status: 200, contentType: 'application/javascript; charset=utf-8', body });
    req.continue().catch(() => {});
  });
  return { pe, file };
}

async function captchaState(page, sel = selectors(), requestedType = CAPTCHA_TYPES.AUTO, verifyResponse = null, initCaptcha = null) {
  const state = await page.evaluate((SEL, REQUESTED) => {
    function one(el) {
      if (!el) return null;
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      const visible = !!(r.width > 1 && r.height > 1 && cs.display !== 'none' && cs.visibility !== 'hidden' && Number(cs.opacity || 1) !== 0);
      return { visible, x: r.left + r.width / 2, y: r.top + r.height / 2, width: r.width, height: r.height, left: r.left, top: r.top, right: r.right, bottom: r.bottom, id: el.id || '', cls: String(el.className || ''), tag: el.tagName || '', role: el.getAttribute && el.getAttribute('role') || '', text: (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 240), src: el.src || '' };
    }
    function all(sel) { try { return Array.from(document.querySelectorAll(sel || '')).map(one).filter(Boolean); } catch { return []; } }
    function pick(sel) { const xs = all(sel); xs.sort((a, b) => (b.visible - a.visible) || (b.width * b.height - a.width * a.height)); return xs[0] || null; }
    function hasAliyunMarker(value) {
      return /aliyun[-_]?captcha|aliyuncaptcha/i.test(`${value && value.id || ''} ${value && value.cls || ''}`);
    }
    function nearAny(value, anchors, pad = 80) {
      return anchors.some(anchor => anchor && anchor.visible && !(
        value.right < anchor.left - pad || value.left > anchor.right + pad ||
        value.bottom < anchor.top - pad || value.top > anchor.bottom + pad
      ));
    }
    function vendorCandidates(values, anchors) {
      const scoped = values.filter(value => hasAliyunMarker(value) || nearAny(value, anchors));
      // Explicit challenge types may use caller-provided selectors on wrappers without Aliyun IDs.
      return scoped.length || REQUESTED === 'auto' ? scoped : values;
    }
    function autoSlider(anchors) {
      const xs = vendorCandidates(all('[id*=slide],[class*=slide],[id*=slider],[class*=slider],[role=slider]'), anchors)
        .filter(x => x.visible && x.width >= 16 && x.width <= 140 && x.height >= 16 && x.height <= 100);
      xs.sort((a, b) => Math.abs(a.width - a.height) - Math.abs(b.width - b.height) || (a.width * a.height - b.width * b.height));
      return xs[0] || null;
    }
    function imageCandidates() { return all('img').filter(x => x.visible && x.src && x.width >= 10 && x.height >= 10); }
    function autoBg(anchors) {
      const xs = vendorCandidates(imageCandidates(), anchors).filter(x => x.width >= 120 && x.height >= 60);
      xs.sort((a, b) => b.width * b.height - a.width * a.height);
      return xs[0] || null;
    }
    function autoPuzzle(bg, anchors) {
      const bgSrc = bg && bg.src;
      const xs = vendorCandidates(imageCandidates(), anchors).filter(x => x.src !== bgSrc && x.width >= 18 && x.height >= 18 && x.width <= 160 && x.height <= 160);
      xs.sort((a, b) => Math.abs(a.width - a.height) - Math.abs(b.width - b.height) || b.width * b.height - a.width * a.height);
      return xs[0] || null;
    }
    function autoCheckbox(anchors) {
      const xs = vendorCandidates(all('[role="checkbox"],input[type="checkbox"],[id*="checkbox"],[class*="checkbox"]'), anchors)
        .filter(x => x.visible && x.width >= 12 && x.height >= 12 && x.width <= 160 && x.height <= 120);
      xs.sort((a, b) => (a.id.startsWith('aliyunCaptcha-') ? -1 : 0) - (b.id.startsWith('aliyunCaptcha-') ? -1 : 0) || a.width * a.height - b.width * b.height);
      return xs[0] || null;
    }
    function autoTrack(slider, anchors) {
      const xs = vendorCandidates(all('[id*=track],[class*=track],[id*=wrapper],[class*=wrapper]'), anchors)
        .filter(x => x.visible && slider && x.width >= slider.width * 2 && x.height >= slider.height * 0.7 && x.height <= slider.height * 3);
      xs.sort((a, b) => a.width * a.height - b.width * b.height);
      return xs[0] || null;
    }
    const entry = pick(SEL.entry);
    const pickedBody = pick(SEL.body);
    const pickedSlider = pick(SEL.slider);
    const pickedTrack = pick(SEL.track);
    const pickedImg = pick(SEL.image);
    const pickedPuzzle = pick(SEL.puzzle);
    const pickedCheckbox = pick(SEL.checkbox);
    const pickedPrompt = pick(SEL.prompt);
    const anchors = [entry, pickedBody, pickedSlider, pickedTrack, pickedPrompt, pickedCheckbox].filter(Boolean);
    const slider = pickedSlider || autoSlider(anchors);
    const track = pickedTrack || autoTrack(slider, [...anchors, slider].filter(Boolean));
    const img = pickedImg || autoBg([...anchors, slider, track].filter(Boolean));
    const puzzle = pickedPuzzle || autoPuzzle(img, [...anchors, slider, track, img].filter(Boolean));
    const checkbox = pickedCheckbox || autoCheckbox([...anchors, slider, track, img].filter(Boolean));
    const body = pickedBody || img || track;
    const roots = [entry, body, track, pickedPrompt, checkbox].filter(Boolean);
    const text = roots.map(x => x.text).filter(Boolean).join(' ').slice(0, 1200);
    const hintNode = document.querySelector([
      '[id^="aliyunCaptcha-"][data-captcha-type]',
      '[id^="aliyunCaptcha-"][data-verify-type]',
      '[id^="aliyunCaptcha-"][data-type]',
      '[id^="aliyunCaptcha-"][class*="restore"]',
      '[id^="aliyunCaptcha-"][class*="puzzle"]',
      '[class*="aliyunCaptcha"][data-captcha-type]',
      '[class*="aliyunCaptcha"][data-verify-type]',
    ].join(','));
    const challengeHint = hintNode ? [hintNode.getAttribute('data-captcha-type'), hintNode.getAttribute('data-verify-type'), hintNode.getAttribute('data-type'), hintNode.id, hintNode.className].filter(Boolean).join(' ').slice(0, 400) : '';
    const visibleChallenge = !![entry, body, track, slider, img, puzzle, checkbox].find(x => x && x.visible);
    return {
      bodyRect: body && { x: body.left, y: body.top, width: body.width, height: body.height },
      sliderRect: slider && { x: slider.left, y: slider.top, width: slider.width, height: slider.height },
      trackRect: track && { x: track.left, y: track.top, width: track.width, height: track.height },
      imageRect: img && { x: img.left, y: img.top, width: img.width, height: img.height },
      imgSrc: img && img.src,
      puzzleSrc: puzzle && puzzle.src,
      entry,
      slider,
      track,
      checkbox,
      puzzle,
      prompt: pickedPrompt && pickedPrompt.text,
      text,
      challengeHint,
      visibleChallenge,
      selectorAuto: { body: !pickedBody && !!body, slider: !pickedSlider && !!slider, track: !pickedTrack && !!track, image: !pickedImg && !!img, puzzle: !pickedPuzzle && !!puzzle, checkbox: !pickedCheckbox && !!checkbox },
      href: location.href,
      title: document.title,
    };
  }, sel, requestedType).catch(e => ({ ready: false, error: e.message }));
  state.verifyResponse = verifyResponse;
  state.vendorCaptchaType = initCaptcha && initCaptcha.vendorType || '';
  state.captchaType = detectCaptchaType(state, requestedType);
  state.ready = captchaReady(state, requestedType);
  delete state.verifyResponse;
  return state;
}

async function clickEntry(page, result, sel = selectors()) {
  const forceHiddenEntry = envFlag('ALIYUN_FORCE_ENTRY_DOM_CLICK', false);
  const clicked = await page.evaluate((SEL, FORCE_HIDDEN_ENTRY) => {
    function vis(el) { if (!el) return null; const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); if (!(r.width > 20 && r.height > 10) || cs.display === 'none' || cs.visibility === 'hidden') return null; return { x: r.left + r.width / 2, y: r.top + r.height / 2, text: (el.textContent || '').replace(/\s+/g, ' ').trim(), id: el.id || '', cls: String(el.className || ''), area: r.width * r.height }; }
    const explicitEntries = Array.from(document.querySelectorAll(SEL.entry || ''));
    const explicitItems = explicitEntries.map(vis).filter(Boolean);
    explicitItems.sort((a, b) => a.area - b.area);
    if (explicitItems[0]) return { ...explicitItems[0], score: 100, method: 'mouse' };
    const hiddenEntry = FORCE_HIDDEN_ENTRY && explicitEntries[0];
    if (hiddenEntry && typeof hiddenEntry.click === 'function') {
      hiddenEntry.click();
      return {
        method: 'dom-click',
        text: (hiddenEntry.textContent || '').replace(/\s+/g, ' ').trim(),
        id: hiddenEntry.id || '',
        cls: String(hiddenEntry.className || ''),
      };
    }
    const items = [];
    for (const el of Array.from(document.querySelectorAll('button,div,span,a'))) { const v = vis(el); if (!v) continue; if (/click to verify|verify|验证|点击验证/i.test(v.text)) items.push({ ...v, score: 50 }); }
    items.sort((a, b) => a.area - b.area);
    if (items[0]) return { ...items[0], method: 'mouse' };
    return null;
  }, sel, forceHiddenEntry).catch(e => ({ error: e.message }));
  if (clicked && !clicked.error && clicked.method === 'mouse') {
    await page.mouse.move(clicked.x - 40, clicked.y - 24, { steps: 10 }).catch(() => {});
    await page.mouse.click(clicked.x, clicked.y, { delay: 80 }).catch(() => {});
  }
  result.entryClicks.push({ at: Date.now(), clicked });
  return clicked;
}

async function waitForCaptcha(page, result, sel = selectors(), requestedType = CAPTCHA_TYPES.AUTO) {
  const timeout = num('CAPTCHA_WAIT_MS', 90000), clickEvery = num('CAPTCHA_CLICK_RETRY_MS', 1000);
  const started = Date.now(); let lastClick = 0, state = null;
  result.entryClicks = [];
  while (Date.now() - started < timeout) {
    state = await captchaState(page, sel, requestedType, result.verifyResponse, result.initCaptcha);
    if (state.ready) return state;
    if (Date.now() - lastClick >= clickEvery) { await clickEntry(page, result, sel); lastClick = Date.now(); }
    await sleep(300);
  }
  throw new Error(`captcha not ready after ${timeout}ms: ${JSON.stringify(state)}`);
}

async function captureChallengeArtifact(page, state, outputDir) {
  const target = state && (
    state.imageRect ||
    state.checkbox ||
    state.bodyRect ||
    state.entry
  );
  if (!target) return null;
  const left = Number(target.left ?? target.x);
  const top = Number(target.top ?? target.y);
  const width = Number(target.width);
  const height = Number(target.height);
  if (![left, top, width, height].every(Number.isFinite) || width <= 1 || height <= 1) return null;
  const viewport = await page.evaluate(() => ({ width: window.innerWidth, height: window.innerHeight }));
  const padding = 8;
  const x = Math.max(0, left - padding);
  const y = Math.max(0, top - padding);
  const clip = {
    x,
    y,
    width: Math.max(1, Math.min(viewport.width - x, width + padding * 2)),
    height: Math.max(1, Math.min(viewport.height - y, height + padding * 2)),
  };
  const artifact = path.join(outputDir, `aliyun_challenge_${state.captchaType}.png`);
  await page.screenshot({ path: artifact, type: 'png', clip, captureBeyondViewport: false });
  return artifact;
}

async function waitForVerification(result, timeoutMs) {
  const started = Date.now();
  while (!result.verifyNetwork && !verifyPassed(result.verifyResponse) && !result.siteVerificationNetwork && Date.now() - started < timeoutMs) {
    await sleep(150);
  }
  return {
    elapsedMs: Date.now() - started,
    observed: !!result.verifyNetwork || !!result.verifyResponse || !!result.siteVerificationNetwork,
    code: verifyCode(result.verifyResponse),
    passed: verifyPassed(result.verifyResponse),
  };
}

function challengeRunSpec(state, distance, profile, runMode, sel) {
  if (!state.sliderRect) throw new Error('captcha slider geometry not found');
  const sx = state.sliderRect.x + state.sliderRect.width / 2;
  const sy = state.sliderRect.y + state.sliderRect.height / 2;
  const points = buildTrajectory(sx, sy, distance, profile.style || null, profile);
  return {
    points,
    spec: {
      mode: runMode,
      startX: sx,
      startY: sy,
      points,
      warm: buildWarm(sx, sy, {
        warmPoints: profile.warmPoints,
        warmDtMin: profile.warmDtMinMs,
        warmDtMax: profile.warmDtMaxMs,
        warmStartX: profile.warmStartX,
        warmStartY: profile.warmStartY,
      }),
      releaseHoldMs: Number(profile.releaseHoldMs),
      releaseHoldJitterMs: Number(profile.releaseHoldJitterMs),
      pressHoldMs: profile.pressHoldMs,
      pressHoldJitterMs: profile.pressHoldJitterMs,
      postDownMs: profile.postDownMs,
      sliderSelector: sel.slider,
      bodySelector: sel.body,
      imageSelector: sel.image,
      puzzleSelector: sel.puzzle,
      requestedSliderDistancePx: Number(distance),
      alignPuzzle: false,
    },
  };
}

async function runConfiguredDrag(page, runMode, spec) {
  if (runMode === 'cdpdrag' || runMode === 'mouse') return runCdpMouse(page, spec);
  if (runMode === 'xdotool') return runXdotoolDrag(page, spec);
  return page.evaluate((value) => window.__AC_run(value), spec);
}

async function runOneClick(page, state) {
  const target = state.checkbox || state.entry;
  if (!target || !target.visible) throw new Error('one-click checkbox geometry not found');
  const fromX = Math.max(1, target.x - 70 - Math.random() * 30);
  const fromY = Math.max(1, target.y - 30 - Math.random() * 20);
  await page.mouse.move(fromX, fromY, { steps: 10 + Math.floor(Math.random() * 8) });
  await sleep(80 + Math.floor(Math.random() * 180));
  await page.mouse.move(target.x, target.y, { steps: 7 + Math.floor(Math.random() * 7) });
  await sleep(60 + Math.floor(Math.random() * 100));
  await page.mouse.click(target.x, target.y, { delay: 60 + Math.floor(Math.random() * 100) });
  return { type: CAPTCHA_TYPES.ONE_CLICK, target: { x: target.x, y: target.y, id: target.id, cls: target.cls } };
}

async function runSliderToRight(page, state, profile, runMode, sel) {
  const slider = state.sliderRect;
  const track = state.trackRect || state.bodyRect;
  if (!slider || !track) throw new Error('slider or track geometry not found');
  const startX = slider.x + slider.width / 2;
  const targetX = track.x + track.width - slider.width / 2;
  const distance = Math.max(1, targetX - startX);
  const built = challengeRunSpec(state, distance, profile, runMode, sel);
  const run = await runConfiguredDrag(page, runMode, built.spec);
  return { run, distance, trajectory: built.points.__meta, start: { x: built.spec.startX, y: built.spec.startY } };
}

function extractJsonObject(text) {
  const source = String(text || '').trim();
  if (!source) return null;
  const fenced = source.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidates = [source, fenced && fenced[1]].filter(Boolean);
  for (const candidate of candidates) {
    try { const parsed = JSON.parse(candidate.trim()); if (parsed && typeof parsed === 'object') return parsed; } catch {}
    const start = candidate.indexOf('{'), end = candidate.lastIndexOf('}');
    if (start >= 0 && end > start) {
      try { const parsed = JSON.parse(candidate.slice(start, end + 1)); if (parsed && typeof parsed === 'object') return parsed; } catch {}
    }
  }
  return null;
}

function messageText(value) {
  if (typeof value === 'string') return value;
  if (!Array.isArray(value)) return '';
  return value.map(item => typeof item === 'string' ? item : (item && typeof item.text === 'string' ? item.text : '')).join('');
}

function visionEndpoint(baseUrl) {
  const normalized = String(baseUrl || '').replace(/\/+$/, '');
  if (normalized.endsWith('/chat/completions')) return normalized;
  if (normalized.endsWith('/v1')) return `${normalized}/chat/completions`;
  return `${normalized}/v1/chat/completions`;
}

async function requestRestoreDistance(image, geometry, options = {}, layers = {}, requestOptions = {}) {
  const configured = options.vision || {};
  const staticAnswer = options.imageRestoreAnswer || configured.answer;
  if (staticAnswer && typeof staticAnswer === 'object') {
    const answerSpace = Number.isFinite(Number(staticAnswer.target_left_px)) ? 'image_target_left' : 'slider';
    return { answer: staticAnswer, metadata: { backend: 'configured_answer', answer_space: answerSpace } };
  }
  if (Number.isFinite(Number(options.restoreDistancePx))) {
    return {
      answer: { distance_px: Number(options.restoreDistancePx), confidence: 1 },
      metadata: { backend: 'configured_distance', answer_space: 'slider' },
    };
  }

  const baseUrl = configured.baseUrl || process.env.ANTIBOT_VISION_BASE_URL || '';
  const model = configured.model || process.env.ANTIBOT_VISION_MODEL || '';
  const apiKeyEnv = configured.apiKeyEnv || 'ANTIBOT_VISION_API_KEY';
  const apiKey = process.env[apiKeyEnv] || '';
  const missing = [!baseUrl && 'vision_base_url', !model && 'vision_model', !apiKey && `vision_api_key/${apiKeyEnv}`].filter(Boolean);
  if (missing.length) throw new Error(`image_restore requires a vision backend; missing ${missing.join(', ')}`);

  const retries = Math.max(1, Math.min(5, Number(configured.retries || 2)));
  const minConfidence = Math.max(0, Math.min(1, Number(configured.minConfidence ?? 0.35)));
  const timeoutMs = Math.max(1000, Number(configured.timeoutMs || 180000));
  const hasSeparateLayers = Buffer.isBuffer(layers.background) && Buffer.isBuffer(layers.fragment);
  const maxVisionCandidates = Math.max(3, Math.min(12, Number(configured.maxCandidates || 9)));
  const candidateDetails = Array.isArray(geometry.localCandidates)
    ? geometry.localCandidates.slice(0, maxVisionCandidates).map(candidate => ({
      distance: Number(Number(candidate.distance_px ?? candidate.distance).toFixed(1)),
      targetLeft: Number(candidate.target_left_png),
    })).filter(candidate => Number.isFinite(candidate.distance) && Number.isFinite(candidate.targetLeft))
    : [];
  const candidates = candidateDetails.map(candidate => candidate.distance);
  const refinement = requestOptions.stage === 'refinement';
  const instruction = hasSeparateLayers ? [
    'Solve this generic horizontal image-restoration task.',
    `Image 1 is a ${geometry.backgroundWidth}x${geometry.backgroundHeight} background. Image 2 is a separate ${geometry.fragmentWidth}x${geometry.fragmentHeight} transparent fragment.`,
    'The fragment starts at left=0 and can move only right. Find the left-edge position where overlaying it best restores the background.',
    refinement
      ? 'The layer images are followed by labeled, magnified local composites around a coarse target. Determine the precise horizontal attachment point.'
      : 'The layer images are followed by labeled candidate composites covering the full horizontal range.',
    'First identify the detached object and the exact object in the scene that is missing this part.',
    'Choose the composite that attaches the fragment at the same vertical level and produces one coherent completed scene.',
    'Reject a candidate that overlays an already complete repeated object, covers an object body, leaves the missing connection open, or floats at an unrelated edge.',
    candidates.length ? `The candidate fragment left positions in image CSS pixels are: ${candidates.join(', ')}. Choose among them or interpolate between adjacent candidates when that makes the connection exact.` : '',
    `The valid target_left_px range is 0 through ${geometry.maxDistance.toFixed(1)} image CSS pixels.`,
    'Return ONLY compact JSON: {"target_left_px":123.4,"confidence":0.85}.',
    'Do not return slider travel, screen coordinates, prose, Markdown, or a negative position. If uncertain return confidence 0.',
  ].filter(Boolean).join(' ') : [
    'Solve this generic horizontal image-restoration task.',
    'The image shows a movable object or fragment and the location where it semantically belongs.',
    `Estimate the horizontal slider travel in CSS pixels from its initial position to the correct restored position. The valid range is 0 through ${geometry.maxDistance.toFixed(1)}.`,
    `The supplied PNG is ${geometry.pngWidth}x${geometry.pngHeight} pixels and represents a ${geometry.cssWidth.toFixed(1)}x${geometry.cssHeight.toFixed(1)} CSS-pixel region.`,
    'Report distance_px in CSS pixels, not PNG pixel coordinates.',
    'Return ONLY compact JSON: {"distance_px":123.4,"confidence":0.85}.',
    'Do not return screen coordinates, prose, Markdown, or a negative distance. If uncertain return confidence 0.',
  ].join(' ');
  const imageContent = hasSeparateLayers ? [
    { type: 'image_url', image_url: { url: `data:image/png;base64,${layers.background.toString('base64')}`, detail: 'high' } },
    { type: 'image_url', image_url: { url: `data:image/png;base64,${layers.fragment.toString('base64')}`, detail: 'high' } },
  ] : [
    { type: 'image_url', image_url: { url: `data:image/png;base64,${image.toString('base64')}`, detail: 'high' } },
  ];
  if (hasSeparateLayers) {
    for (const candidate of candidateDetails) {
      const rendered = refinement
        ? renderRestoreCandidateFocus(layers.background, layers.fragment, candidate.targetLeft)
        : renderRestoreCandidate(layers.background, layers.fragment, candidate.targetLeft);
      imageContent.push(
        { type: 'text', text: `Candidate target_left_px=${candidate.distance}` },
        { type: 'image_url', image_url: { url: `data:image/png;base64,${rendered.toString('base64')}`, detail: 'high' } },
      );
    }
  }
  const body = {
    model,
    messages: [{ role: 'user', content: [
      { type: 'text', text: instruction },
      ...imageContent,
    ] }],
    temperature: 0,
    stream: false,
    ...(configured.extraBody || {}),
  };
  for (const reserved of ['model', 'messages', 'stream', 'max_tokens']) {
    if (configured.extraBody && Object.prototype.hasOwnProperty.call(configured.extraBody, reserved)) {
      throw new Error(`vision extraBody cannot override reserved field: ${reserved}`);
    }
  }

  const errors = [], attempts = [];
  for (let attempt = 1; attempt <= retries; attempt++) {
    const started = Date.now();
    let httpStatus = null;
    try {
      const response = await fetch(visionEndpoint(baseUrl), {
        method: 'POST',
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
      httpStatus = response.status;
      const raw = await response.text();
      const payload = (() => { try { return JSON.parse(raw); } catch { return {}; } })();
      if (!response.ok) {
        const message = payload && payload.error && payload.error.message || 'request rejected';
        throw new Error(`vision gateway HTTP ${response.status}: ${message}`);
      }
      const choice = payload && Array.isArray(payload.choices) && payload.choices[0];
      const message = choice && choice.message || {};
      const parsed = extractJsonObject(messageText(message.content)) || extractJsonObject(messageText(message.reasoning_content));
      if (!parsed) throw new Error('vision gateway returned no parseable JSON');
      const distance = Number(parsed.target_left_px ?? parsed.target_left ?? parsed.distance_px ?? parsed.distance);
      const confidence = Number(parsed.confidence ?? 0);
      if (!Number.isFinite(distance) || distance < 0 || distance > geometry.maxDistance + 2) {
        throw new Error(`vision distance is outside 0..${geometry.maxDistance.toFixed(1)}`);
      }
      if (!Number.isFinite(confidence) || confidence < minConfidence || confidence > 1) {
        throw new Error(`vision confidence ${confidence} is below ${minConfidence}`);
      }
      return {
        answer: { distance_px: distance, confidence },
        metadata: {
          backend: 'openai_compatible',
          answer_space: hasSeparateLayers ? 'image_target_left' : 'slider',
          model: payload.model || model,
          finish_reason: choice && choice.finish_reason,
          attempt,
          errors,
          elapsed_ms: Date.now() - started,
          http_status: response.status,
          response_body_length: raw.length,
          stage: requestOptions.stage || 'coarse',
          attempts: [...attempts, { attempt, elapsed_ms: Date.now() - started, http_status: response.status, outcome: 'accepted' }],
        },
      };
    } catch (error) {
      const message = error && error.message || String(error);
      errors.push(`attempt ${attempt}: ${message}`);
      attempts.push({ attempt, elapsed_ms: Date.now() - started, http_status: httpStatus, outcome: 'error', error: message });
    }
  }
  const failure = new Error(errors[errors.length - 1] || 'vision backend returned no answer');
  failure.visionAttempts = attempts;
  throw failure;
}

async function runImageRestore(page, state, profile, runMode, sel, outputDir, options) {
  const slider = state.sliderRect;
  const track = state.trackRect || state.bodyRect;
  const imageRect = state.imageRect || state.bodyRect;
  if (!slider || !track || !imageRect) throw new Error('image restoration geometry not found');
  const viewport = await page.evaluate(() => ({ width: window.innerWidth, height: window.innerHeight }));
  const clip = {
    x: Math.max(0, imageRect.x),
    y: Math.max(0, imageRect.y),
    width: Math.max(1, Math.min(imageRect.width, viewport.width - Math.max(0, imageRect.x))),
    height: Math.max(1, Math.min(imageRect.height, viewport.height - Math.max(0, imageRect.y))),
  };
  const image = await page.screenshot({ type: 'png', clip, captureBeyondViewport: false });
  const artifact = path.join(outputDir, 'aliyun_restore_selected.png');
  fs.writeFileSync(artifact, image);
  const png = PNG.sync.read(image);
  const maxDistance = Math.max(1, track.width - slider.width);
  let background = null, fragment = null, local = null, boundary = null, layerError = '';
  let backgroundPng = null, fragmentPng = null;
  const backgroundArtifact = path.join(outputDir, 'aliyun_restore_background.png');
  const fragmentArtifact = path.join(outputDir, 'aliyun_restore_fragment.png');
  try {
    if (state.imgSrc && state.puzzleSrc) {
      [background, fragment] = await Promise.all([getBuf(state.imgSrc, options.userAgent), getBuf(state.puzzleSrc, options.userAgent)]);
      fs.writeFileSync(backgroundArtifact, background);
      fs.writeFileSync(fragmentArtifact, fragment);
      backgroundPng = PNG.sync.read(background);
      fragmentPng = PNG.sync.read(fragment);
      local = detectRestoreStrip(background, fragment, { maxDistance, cssWidth: clip.width });
      boundary = detectRestoreBoundaryContinuity(background, fragment, { maxDistance, cssWidth: clip.width });
    }
  } catch (error) {
    layerError = error && error.message || String(error);
  }
  const configuredAnswer = options.imageRestoreAnswer || (options.vision && options.vision.answer);
  const configuredDistance = Number.isFinite(Number(options.restoreDistancePx));
  const localMinConfidence = Math.max(0, Math.min(1, Number(options.vision?.localMinConfidence ?? 0.72)));
  const maxTargetPng = backgroundPng && fragmentPng
    ? Math.min(backgroundPng.width - fragmentPng.width, Math.floor(maxDistance / Math.max(1e-9, local && local.css_per_png || 1)))
    : 0;
  const visionCandidates = local
    ? buildRestoreVisionCandidates(local, maxTargetPng, options.vision?.maxCandidates || 9)
    : [];
  const boundaryFallback = selectRestoreBoundaryFallback(
    boundary,
    local,
    fragmentPng ? fragmentPng.width * Math.max(1e-9, Number(local && local.css_per_png || 1)) : 0,
  );
  let vision;
  if (!configuredAnswer && !configuredDistance && local && local.confidence >= localMinConfidence) {
    vision = {
      answer: { target_left_px: local.target_left_png, confidence: local.confidence },
      metadata: { backend: 'local_strip_match', answer_space: 'image_target_left', local, layer_error: layerError || null },
    };
  } else if (!configuredAnswer && !configuredDistance && boundaryFallback) {
    vision = {
      answer: { target_left_px: boundaryFallback.distance_px, confidence: boundaryFallback.confidence },
      metadata: {
        backend: 'boundary_continuity_consensus',
        answer_space: 'image_target_left',
        boundary_fallback: boundaryFallback,
        local,
        boundary,
        layer_error: layerError || null,
      },
    };
  } else {
    vision = await requestRestoreDistance(image, {
    maxDistance,
    pngWidth: png.width,
    pngHeight: png.height,
    cssWidth: clip.width,
    cssHeight: clip.height,
      backgroundWidth: backgroundPng && backgroundPng.width,
      backgroundHeight: backgroundPng && backgroundPng.height,
      fragmentWidth: fragmentPng && fragmentPng.width,
      fragmentHeight: fragmentPng && fragmentPng.height,
      localCandidates: visionCandidates,
    }, options, { background, fragment }, { stage: 'coarse' });
    if (vision.metadata.backend === 'openai_compatible' && backgroundPng && fragmentPng && visionCandidates.length >= 2) {
      const coarseTarget = Number(vision.answer.target_left_px ?? vision.answer.distance_px);
      const refinementTargets = buildRestoreRefinementCandidates(
        coarseTarget,
        visionCandidates,
        maxTargetPng,
        options.vision?.refinementCandidates || 9,
      );
      const cssPerPng = Math.max(1e-9, Number(local && local.css_per_png || 1));
      const refinementCandidates = refinementTargets.map(target => ({
        target_left_png: target,
        distance_px: Number((target * cssPerPng).toFixed(3)),
      }));
      try {
        const refined = await requestRestoreDistance(image, {
          maxDistance,
          pngWidth: png.width,
          pngHeight: png.height,
          cssWidth: clip.width,
          cssHeight: clip.height,
          backgroundWidth: backgroundPng.width,
          backgroundHeight: backgroundPng.height,
          fragmentWidth: fragmentPng.width,
          fragmentHeight: fragmentPng.height,
          localCandidates: refinementCandidates,
        }, options, { background, fragment }, { stage: 'refinement' });
        const refinedTarget = Number(refined.answer.target_left_px ?? refined.answer.distance_px);
        const evidenceWindow = Math.max(12, maxTargetPng / Math.max(1, visionCandidates.length - 1) * 0.6);
        const localTarget = Number(local && local.distance_px);
        const boundaryMatch = (boundary && boundary.directions || [])
          .filter(candidate => candidate.score <= 20 && candidate.score_margin >= 0.35)
          .map(candidate => ({
            ...candidate,
            coarse_delta_px: Math.abs(candidate.distance_px - coarseTarget),
            refined_delta_px: Math.abs(candidate.distance_px - refinedTarget),
            local_delta_px: Number.isFinite(localTarget) ? Math.abs(candidate.distance_px - localTarget) : null,
          }))
          .filter(candidate => candidate.coarse_delta_px <= evidenceWindow)
          .sort((a, b) => a.coarse_delta_px - b.coarse_delta_px || a.score - b.score)[0];
        refined.metadata.coarse = {
          target_left_px: coarseTarget,
          confidence: vision.answer.confidence,
          candidates: visionCandidates.map(candidate => candidate.distance_px),
          request: vision.metadata,
        };
        refined.metadata.refinement_candidates = refinementCandidates.map(candidate => candidate.distance_px);
        const localRefines = Number.isFinite(localTarget)
          && local.score_margin >= 0.12
          && Math.abs(localTarget - coarseTarget) <= evidenceWindow
          && Math.abs(localTarget - refinedTarget) <= evidenceWindow;
        if (localRefines) {
          refined.metadata.stage = 'local_evidence_refinement';
          refined.metadata.local_refinement = {
            target_left_px: localTarget,
            score: local.score,
            score_margin: local.score_margin,
            coarse_delta_px: Number(Math.abs(localTarget - coarseTarget).toFixed(3)),
            refined_delta_px: Number(Math.abs(localTarget - refinedTarget).toFixed(3)),
            evidence_window_px: Number(evidenceWindow.toFixed(3)),
          };
          refined.answer = {
            distance_px: localTarget,
            confidence: Math.min(Number(refined.answer.confidence), Math.max(0.7, Number(local.confidence))),
          };
        } else if (boundaryMatch) {
          const evidence = [coarseTarget, refinedTarget, boundaryMatch.distance_px];
          const localCorroborates = Number.isFinite(localTarget) && evidence.some(value => Math.abs(value - localTarget) <= evidenceWindow);
          if (localCorroborates) evidence.push(localTarget);
          evidence.sort((a, b) => a - b);
          const middle = Math.floor(evidence.length / 2);
          const consensus = evidence.length % 2
            ? evidence[middle]
            : (evidence[middle - 1] + evidence[middle]) / 2;
          refined.metadata.stage = 'evidence_fusion';
          refined.metadata.boundary_refinement = {
            ...boundaryMatch,
            refined_target_left_px: refinedTarget,
            evidence_window_px: Number(evidenceWindow.toFixed(3)),
            local_corroborates: localCorroborates,
            evidence_target_left_px: evidence,
            consensus_target_left_px: Number(consensus.toFixed(3)),
          };
          refined.answer = {
            distance_px: consensus,
            confidence: Math.min(Number(refined.answer.confidence), Math.max(0.7, boundaryMatch.confidence)),
          };
        }
        vision = refined;
      } catch (error) {
        vision.metadata.refinement_error = error && error.message || String(error);
        vision.metadata.refinement_candidates = refinementCandidates.map(candidate => candidate.distance_px);
      }
    }
    vision.metadata.local = local;
    vision.metadata.boundary = boundary;
    vision.metadata.layer_error = layerError || null;
  }
  const answerSpace = vision.metadata.answer_space || 'slider';
  const targetLeft = answerSpace === 'image_target_left'
    ? Number(vision.answer.target_left_px ?? vision.answer.distance_px)
    : null;
  const rawDistance = answerSpace === 'image_target_left'
    ? restoreSliderTravel(targetLeft, maxDistance)
    : Number(vision.answer.distance_px);
  const distance = answerSpace === 'image_target_left'
    ? restoreQuantizedSliderTravel(targetLeft, maxDistance)
    : rawDistance;
  if (!Number.isFinite(distance) || distance < 0 || distance > maxDistance + 2) {
    throw new Error(`restore slider distance is outside 0..${maxDistance.toFixed(1)}`);
  }
  const built = challengeRunSpec(state, distance, profile, runMode, sel);
  built.spec.targetPuzzleX = targetLeft;
  const run = await runConfiguredDrag(page, runMode, built.spec);
  const observedTargetRaw = run && run.geometry && run.geometry.observedPuzzleLeftPx;
  const observedTarget = Number(observedTargetRaw);
  const hasObservedTarget = observedTargetRaw !== null && observedTargetRaw !== undefined && Number.isFinite(observedTarget);
  return {
    run,
    distance,
    targetLeft,
    maxDistance,
    confidence: vision.answer.confidence,
    vision: vision.metadata,
    mapping: answerSpace === 'image_target_left' ? {
      type: 'aliyun_image_restore_quadratic',
      target_left_px: targetLeft,
      raw_slider_distance_px: Number(rawDistance.toFixed(3)),
      slider_distance_px: Number(distance.toFixed(3)),
      projected_fragment_left_px: Number(restorePuzzleTravel(distance, maxDistance).toFixed(3)),
      observed_fragment_left_px: hasObservedTarget ? observedTarget : null,
      observed_target_error_px: hasObservedTarget ? Number((observedTarget - targetLeft).toFixed(3)) : null,
    } : { type: 'configured_slider_distance', slider_distance_px: Number(distance.toFixed(3)) },
    artifact,
    artifacts: {
      composite: artifact,
      background: background ? backgroundArtifact : null,
      fragment: fragment ? fragmentArtifact : null,
    },
    trajectory: built.points.__meta,
    start: { x: built.spec.startX, y: built.spec.startY },
  };
}

async function readGap(page, result, outputDir, tag = 'latest', sel = selectors(), ua) {
  const state = await captchaState(page, sel);
  if (!state.imgSrc || !state.puzzleSrc) throw new Error('captcha images not found');
  const [bg, puzzle] = await Promise.all([getBuf(state.imgSrc, ua), getBuf(state.puzzleSrc, ua)]);
  fs.writeFileSync(path.join(outputDir, `aliyun_bg_${sanitizeName(tag)}.png`), bg);
  fs.writeFileSync(path.join(outputDir, `aliyun_puzzle_${sanitizeName(tag)}.png`), puzzle);
  const gap = detectGapByPuzzle(bg, puzzle);
  if (!gap) throw new Error('gap not found');
  result.state = state;
  result.gap = gap;
  return { state, gap };
}

function buildWarm(startX, startY, overrides = {}) {
  const warm = [];
  const count = overrides.warmPoints ?? num('LISTENER_WARM_POINTS', 18);
  const dtMin = overrides.warmDtMin ?? num('LISTENER_WARM_DT_MIN_MS', 8);
  const dtMax = overrides.warmDtMax ?? num('LISTENER_WARM_DT_MAX_MS', 28);
  const warmStartX = overrides.warmStartX ?? num('LISTENER_WARM_START_X', 960);
  const warmStartY = overrides.warmStartY ?? num('LISTENER_WARM_START_Y', 560);
  for (let i = 0; i < count; i++) { const p = count <= 1 ? 1 : i / (count - 1); warm.push({ x: Math.round(warmStartX + (startX - warmStartX) * p + (Math.random() * 4 - 2)), y: Math.round(warmStartY + (startY - warmStartY) * p + (Math.random() * 4 - 2)), t: Math.round(120 + i * 55), dt: dtMin + Math.floor(Math.random() * Math.max(1, dtMax - dtMin + 1)) }); }
  return warm;
}

async function runCdpMouse(page, spec) {
  const calls = [], alignReads = [];
  for (const p of (spec.warm || [])) {
    await page.mouse.move(p.x, p.y).catch(() => {});
    calls.push({ at: Date.now(), type: 'mousemove', mode: 'cdpdrag', x: Math.round(p.x), y: Math.round(p.y), buttons: 0 });
    await sleep(Math.max(0, p.dt || 8));
  }
  await page.mouse.move(spec.startX, spec.startY).catch(() => {});
  calls.push({ at: Date.now(), type: 'mousemove', mode: 'cdpdrag', x: Math.round(spec.startX), y: Math.round(spec.startY), buttons: 0 });
  const pressHold = Math.max(0, (spec.pressHoldMs || 0) + Math.floor(Math.random() * Math.max(0, spec.pressHoldJitterMs || 0)));
  await sleep(pressHold === 0 ? 0 : (pressHold || 80));
  await page.mouse.down({ button: 'left' }).catch(() => {});
  calls.push({ at: Date.now(), type: 'mousedown', mode: 'cdpdrag', x: Math.round(spec.startX), y: Math.round(spec.startY), buttons: 1 });
  const postDown = Math.max(0, spec.postDownMs || 0);
  if (postDown) await sleep(postDown);
  const initialGeometry = await readCdpDragGeometry(page, spec);
  let lastT = 0;
  let cur = { x: spec.startX, y: spec.startY };
  const maxMoveDelay = num('LISTENER_MAX_MOVE_DELAY_MS', 220);
  for (const p of spec.points) {
    const d = Math.max(0, Math.min(maxMoveDelay, p.t - lastT));
    lastT = p.t;
    if (d) await sleep(d);
    await page.mouse.move(p.x, p.y).catch(() => {});
    cur = { x: p.x, y: p.y };
    calls.push({ at: Date.now(), type: 'mousemove', mode: 'cdpdrag', x: Math.round(p.x), y: Math.round(p.y), buttons: 1 });
  }
  if (spec.alignPuzzle) {
    const tolerance = Math.max(0.5, Number(spec.alignTolerancePx || 1.5));
    const gain = Number.isFinite(Number(spec.alignGain)) ? Number(spec.alignGain) : 1;
    const maxStep = Math.max(2, Number(spec.alignMaxStepPx || 18));
    const iters = Math.max(1, Math.min(8, Number(spec.alignIters || 4)));
    for (let i = 0; i < iters; i++) {
      const st = await page.evaluate((s) => {
        const img = document.querySelector(s.imageSelector || '#aliyunCaptcha-img');
        const puzzle = document.querySelector(s.puzzleSelector || '#aliyunCaptcha-puzzle');
        const slider = document.querySelector(s.sliderSelector || '#aliyunCaptcha-sliding-slider');
        const body = document.querySelector(s.bodySelector || '#aliyunCaptcha-sliding-body');
        const rect = (el) => { if (!el) return null; const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); return { left: r.left, top: r.top, width: r.width, height: r.height, styleLeft: parseFloat(cs.left) || 0, transform: cs.transform }; };
        const ir = rect(img), pr = rect(puzzle), sr = rect(slider), br = rect(body);
        return {
          img: ir, puzzle: pr, slider: sr, body: br,
          puzzleLeft: ir && pr ? pr.left - ir.left : null,
          sliderLeft: br && sr ? sr.left - br.left : null,
        };
      }, spec).catch(e => ({ error: e.message }));
      const actual = Number(st && st.puzzleLeft);
      const target = Number(spec.targetPuzzleX);
      const error = Number.isFinite(actual) && Number.isFinite(target) ? target - actual : 0;
      alignReads.push({ at: Date.now(), i, target, actual: Number.isFinite(actual) ? Number(actual.toFixed(3)) : null, error: Number(error.toFixed(3)), sliderLeft: st && Number.isFinite(Number(st.sliderLeft)) ? Number(Number(st.sliderLeft).toFixed(3)) : null });
      if (!Number.isFinite(error) || Math.abs(error) <= tolerance) break;
      const step = Math.max(-maxStep, Math.min(maxStep, error * gain));
      cur = { x: cur.x + step, y: cur.y + (Math.random() * 0.8 - 0.4) };
      await page.mouse.move(cur.x, cur.y, { steps: Math.max(2, Math.ceil(Math.abs(step) / 4)) }).catch(() => {});
      calls.push({ at: Date.now(), type: 'mousemove', mode: 'cdpdrag-align', x: Math.round(cur.x), y: Math.round(cur.y), buttons: 1, step: Number(step.toFixed(3)), error: Number(error.toFixed(3)) });
      await sleep(70 + Math.floor(Math.random() * 45));
    }
  }
  const hold = Math.max(0, (spec.releaseHoldMs || 0) + Math.floor(Math.random() * Math.max(0, spec.releaseHoldJitterMs || 0)));
  await sleep(hold);
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))).catch(() => {});
  const preReleaseGeometry = await readCdpDragGeometry(page, spec);
  const geometry = summarizeCdpDragGeometry(initialGeometry, preReleaseGeometry, spec, cur);
  await page.mouse.up({ button: 'left' }).catch(() => {});
  calls.push({ at: Date.now(), type: 'mouseup', mode: 'cdpdrag', x: Math.round(cur.x), y: Math.round(cur.y), buttons: 0 });
  return { ok: true, mode: 'cdpdrag', align: alignReads, geometry, calls: calls.slice(-100), errors: [] };
}

async function readCdpDragGeometry(page, spec) {
  return page.evaluate((s) => {
    const img = document.querySelector(s.imageSelector || '#aliyunCaptcha-img');
    const puzzle = document.querySelector(s.puzzleSelector || '#aliyunCaptcha-puzzle');
    const slider = document.querySelector(s.sliderSelector || '#aliyunCaptcha-sliding-slider');
    const body = document.querySelector(s.bodySelector || '#aliyunCaptcha-sliding-body');
    const rect = (el) => {
      if (!el) return null;
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      return {
        left: r.left,
        top: r.top,
        width: r.width,
        height: r.height,
        styleLeft: Number.parseFloat(cs.left) || 0,
        transform: cs.transform,
      };
    };
    const imageRect = rect(img);
    const puzzleRect = rect(puzzle);
    const sliderRect = rect(slider);
    const bodyRect = rect(body);
    return {
      image: imageRect,
      puzzle: puzzleRect,
      slider: sliderRect,
      body: bodyRect,
      puzzleLeftPx: imageRect && puzzleRect ? puzzleRect.left - imageRect.left : null,
      sliderLeftPx: bodyRect && sliderRect ? sliderRect.left - bodyRect.left : null,
    };
  }, spec).catch(error => ({ error: error && error.message || String(error) }));
}

function summarizeCdpDragGeometry(initial, preRelease, spec, pointer) {
  const rounded = value => Number.isFinite(Number(value)) ? Number(Number(value).toFixed(3)) : null;
  const delta = (after, before) => Number.isFinite(Number(after)) && Number.isFinite(Number(before))
    ? rounded(Number(after) - Number(before))
    : null;
  return {
    requestedSliderDistancePx: rounded(spec.requestedSliderDistancePx),
    pointerDistancePx: delta(pointer && pointer.x, spec.startX),
    initial,
    preRelease,
    observedSliderDisplacementPx: delta(preRelease && preRelease.sliderLeftPx, initial && initial.sliderLeftPx),
    observedPuzzleDisplacementPx: delta(preRelease && preRelease.puzzleLeftPx, initial && initial.puzzleLeftPx),
    observedSliderLeftPx: rounded(preRelease && preRelease.sliderLeftPx),
    observedPuzzleLeftPx: rounded(preRelease && preRelease.puzzleLeftPx),
    observedImageLeftPx: rounded(preRelease && preRelease.image && preRelease.image.left),
  };
}

function runXdotool(args) {
  const r = spawnSync('xdotool', args, { encoding: 'utf8', timeout: 5000 });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`xdotool exited ${r.status}: ${r.stderr || ''}`);
  return r.stdout;
}

async function calibrateViewportScreenOffset(page) {
  await page.evaluate(() => {
    window.__xdotoolCalibration = null;
    if (!window.__xdotoolCalibrationHandler) {
      window.__xdotoolCalibrationHandler = (e) => {
        window.__xdotoolCalibration = {
          screenX: e.screenX, screenY: e.screenY,
          clientX: e.clientX, clientY: e.clientY, at: Date.now(),
        };
      };
      document.addEventListener('mousemove', window.__xdotoolCalibrationHandler, true);
    }
  }).catch(() => {});
  const target = await page.evaluate(() => ({
    x: Math.max(30, Math.min((window.screen?.width || 1920) - 30, (window.screenX || 0) + Math.floor((window.innerWidth || 1280) / 2))),
    y: Math.max(30, Math.min((window.screen?.height || 1080) - 30, (window.screenY || 0) + Math.floor((window.innerHeight || 720) / 2))),
  })).catch(() => ({ x: 960, y: 540 }));
  runXdotool(['mousemove', Math.round(target.x), Math.round(target.y)]);
  await sleep(180 + Math.floor(Math.random() * 120));
  const cal = await page.evaluate(() => window.__xdotoolCalibration || null).catch(() => null);
  if (cal && Number.isFinite(cal.screenX) && Number.isFinite(cal.clientX)) {
    return { offsetX: cal.screenX - cal.clientX, offsetY: cal.screenY - cal.clientY, calibration: cal };
  }
  // fallback using geometry heuristic
  const geom = await page.evaluate(() => ({
    screenX: window.screenX || 0, screenY: window.screenY || 0,
    outerWidth: window.outerWidth || 0, outerHeight: window.outerHeight || 0,
    innerWidth: window.innerWidth || 0, innerHeight: window.innerHeight || 0,
    devicePixelRatio: window.devicePixelRatio || 1,
  })).catch(() => null);
  if (!geom) return { offsetX: target.x, offsetY: target.y, calibration: null };
  const dpr = geom.devicePixelRatio || 1;
  const chromeLeft = Math.max(0, (geom.outerWidth - geom.innerWidth) / 2);
  const chromeTop = Math.max(0, geom.outerHeight - geom.innerHeight - chromeLeft);
  return {
    offsetX: (geom.screenX + chromeLeft) * dpr,
    offsetY: (geom.screenY + chromeTop) * dpr,
    calibration: null,
  };
}

async function viewportTrajectoryToScreen(page, points) {
  const offset = await calibrateViewportScreenOffset(page);
  return {
    geom: offset,
    points: points.map(p => ({ ...p, x: offset.offsetX + p.x, y: offset.offsetY + p.y })),
  };
}

async function runXdotoolDrag(page, spec) {
  const calls = [];
  const allPoints = [];
  // warm points
  if (spec.warm && spec.warm.length) {
    const warm = await viewportTrajectoryToScreen(page, spec.warm);
    for (const p of warm.points) {
      runXdotool(['mousemove', Math.round(p.x), Math.round(p.y)]);
      calls.push({ at: Date.now(), type: 'mousemove', mode: 'xdotool', x: Math.round(p.x), y: Math.round(p.y), buttons: 0 });
      await sleep(Math.max(0, p.dt || 8));
    }
  }
  const sx = await viewportTrajectoryToScreen(page, [{ x: spec.startX, y: spec.startY }]);
  const start = sx.points[0];
  runXdotool(['mousemove', Math.round(start.x), Math.round(start.y)]);
  calls.push({ at: Date.now(), type: 'mousemove', mode: 'xdotool', x: Math.round(start.x), y: Math.round(start.y), buttons: 0 });
  const pressHold = Math.max(0, (spec.pressHoldMs || 0) + Math.floor(Math.random() * Math.max(0, spec.pressHoldJitterMs || 0)));
  await sleep(pressHold || (120 + Math.floor(Math.random() * 160)));
  runXdotool(['mousedown', '1']);
  calls.push({ at: Date.now(), type: 'mousedown', mode: 'xdotool', x: Math.round(start.x), y: Math.round(start.y), buttons: 1 });
  const postDown = Math.max(0, spec.postDownMs || 0);
  if (postDown) await sleep(postDown);
  const pts = await viewportTrajectoryToScreen(page, spec.points || []);
  let elapsed = 0;
  for (const p of pts.points) {
    const delay = Math.max(0, p.t - elapsed);
    elapsed = p.t;
    if (delay) await sleep(delay);
    runXdotool(['mousemove', Math.round(p.x), Math.round(p.y)]);
    calls.push({ at: Date.now(), type: 'mousemove', mode: 'xdotool', x: Math.round(p.x), y: Math.round(p.y), buttons: 1 });
  }
  // align (optional, disabled for xdotool by default due to coordinate drift risk)
  const hold = Math.max(0, (spec.releaseHoldMs || 0) + Math.floor(Math.random() * Math.max(0, spec.releaseHoldJitterMs || 0)));
  await sleep(hold || (260 + Math.floor(Math.random() * 240)));
  const last = pts.points[pts.points.length - 1] || start;
  runXdotool(['mouseup', '1']);
  calls.push({ at: Date.now(), type: 'mouseup', mode: 'xdotool', x: Math.round(last.x), y: Math.round(last.y), buttons: 0 });
  return { ok: true, mode: 'xdotool', align: [], calls: calls.slice(-100), errors: [] };
}

async function refreshPuzzle(page, prevState) {
  return await page.evaluate(async (prev) => {
    const btn = document.querySelector('#aliyunCaptcha-btn-refresh') || document.querySelector('[id*=refresh]') || Array.from(document.querySelectorAll('button')).find(x => /refresh|刷新/i.test(x.textContent || ''));
    const before = {
      imgSrc: document.querySelector('#aliyunCaptcha-img') && document.querySelector('#aliyunCaptcha-img').src,
      puzzleSrc: document.querySelector('#aliyunCaptcha-puzzle') && document.querySelector('#aliyunCaptcha-puzzle').src,
    };
    if (!btn) return { clicked: false, before, reason: 'refresh-button-not-found' };
    btn.click();
    const started = Date.now();
    while (Date.now() - started < 6000) {
      await new Promise(r => setTimeout(r, 150));
      const img = document.querySelector('#aliyunCaptcha-img'), puzzle = document.querySelector('#aliyunCaptcha-puzzle');
      const now = { imgSrc: img && img.src, puzzleSrc: puzzle && puzzle.src };
      if (now.imgSrc && now.puzzleSrc && (now.imgSrc !== before.imgSrc || now.puzzleSrc !== before.puzzleSrc))
        return { clicked: true, changed: true, waitMs: Date.now() - started, before, after: now };
    }
    return { clicked: true, changed: false, waitMs: Date.now() - started, before };
  }, prevState || {}).catch(e => ({ clicked: false, error: e.message }));
}
async function solveCaptchaOnce(options = {}) {
  let profile = resolvedProfile(options.profile || {});
  const restoreProfileEnv = patchEnv(profileEnv(profile));
  let ownedBrowser = false;
  let browser = options.browser || null;
  let anonymizedProxyToClose = '';
  let partialResult = null;
  try {
    const targetUrl = options.targetUrl || options.url || process.env.TARGET_URL || '';
    if (!targetUrl) throw new Error('targetUrl/TARGET_URL is required');

    const outputDir = options.outputDir ? path.resolve(options.outputDir) : defaultOutputDir();
    const out = options.out ? path.resolve(options.out) : (process.env.OUT ? path.resolve(process.env.OUT) : path.join(outputDir, 'aliyun_captcha_run.json'));
    const sel = selectors(options.selectors || {});
    const requestedCaptchaType = normalizeCaptchaType(options.captchaType || process.env.ALIYUN_CAPTCHA_TYPE || CAPTCHA_TYPES.AUTO);
    const ua = userAgent(options.userAgent);
    const runMode = process.env.LISTENER_MODE || STABLE_PROFILE.mode;
    const useXdotool = runMode === 'xdotool';
    let headless;
    if (options.headless !== undefined) {
      headless = options.headless;
    } else if (process.env.HEADLESS === '0') {
      headless = false;
    } else if (process.env.HEADLESS === 'old' || process.env.HEADLESS === 'true' || process.env.HEADLESS === '1') {
      headless = true;
    } else {
      headless = 'new';
    }
    if (useXdotool) headless = false;

    fs.mkdirSync(outputDir, { recursive: true });
    const result = { at: new Date().toISOString(), targetUrl, requestedCaptchaType, selectors: sel, profile, net: [], outputDir, out };
    partialResult = result;
    result.watchdogConfig = {
      enabled: envFlag('ALIYUN_WATCHDOG_ENABLED', true),
      proxyMs: watchdogMs('ALIYUN_PROXY_WATCHDOG_MS', 30000),
      launchMs: watchdogMs('ALIYUN_LAUNCH_WATCHDOG_MS', 90000),
      pageMs: watchdogMs('ALIYUN_PAGE_WATCHDOG_MS', 30000),
      hooksMs: watchdogMs('ALIYUN_HOOKS_WATCHDOG_MS', 20000),
      gotoMs: watchdogMs('ALIYUN_GOTO_WATCHDOG_MS', (options.gotoTimeoutMs || num('GOTO_TIMEOUT_MS', 60000)) + 5000),
      preActionMs: watchdogMs('ALIYUN_PRE_ACTION_WATCHDOG_MS', 90000),
      captchaMs: watchdogMs('ALIYUN_CAPTCHA_WATCHDOG_MS', num('CAPTCHA_WAIT_MS', 90000) + 5000),
      readGapMs: watchdogMs('ALIYUN_READ_GAP_WATCHDOG_MS', 25000),
      refreshMs: watchdogMs('ALIYUN_REFRESH_WATCHDOG_MS', 12000),
      dragMs: watchdogMs('ALIYUN_DRAG_WATCHDOG_MS', Math.max(30000, Number(profile.totalMs || 0) + 10000)),
      runtimeMs: watchdogMs('ALIYUN_RUNTIME_WATCHDOG_MS', 8000),
      closeMs: watchdogMs('ALIYUN_CLOSE_WATCHDOG_MS', 8000),
    };
    const wd = (label, ms, fn) => withWatchdog(label, ms, fn, result);
    const captureInternals = envFlag('DEEP_HOOKS', false) || envFlag('CAPTURE_INTERNALS', false);
    result.deepHooksEnabled = captureInternals;
    const attemptNo = options.attempt || 1;
    const fp = process.env.FINGERPRINT_ENABLED === '0' ? null : makeFingerprint(`${attemptNo}:${out}`);
    result.fingerprint = fp;

    if (!browser) {
      ownedBrowser = true;
      const useRebrowser = options.useRebrowser !== undefined ? !!options.useRebrowser : process.env.USE_REBROWSER === '1';
      const driver = options.puppeteer || loadPuppeteer(useRebrowser);
      const chromePath = findChromePath(options.chromePath);
      let proxyAddr = options.proxyServer || process.env.PROXY_SERVER || '';
      if (proxyAddr) {
        const proxyList = proxyAddr.split(',').map(s => s.trim()).filter(Boolean);
        if (proxyList.length > 1) {
          proxyAddr = proxyList[Math.floor(Math.random() * proxyList.length)];
        }
        result.proxyPicked = redactProxy(proxyAddr);
        if (proxyAddr && (proxyAddr.includes('@') || !proxyAddr.startsWith('http://127.0.0.1'))) {
          try {
            const ProxyChain = require('proxy-chain');
            const raw = proxyAddr.includes('://') ? proxyAddr : 'http://' + proxyAddr;
            proxyAddr = await wd('proxy.anonymize', result.watchdogConfig.proxyMs, () => ProxyChain.anonymizeProxy(raw));
            anonymizedProxyToClose = proxyAddr;
            result.anonymizedProxy = redactProxy(proxyAddr);
          } catch (e) { result.proxyChainError = e.message; proxyAddr = ''; }
        }
      }
      browser = await wd('browser.launch', result.watchdogConfig.launchMs, () => driver.launch({
        executablePath: chromePath,
        headless,
        defaultViewport: {
          width: fp ? fp.width : (options.viewportWidth || num('VIEWPORT_WIDTH', 1365)),
          height: fp ? fp.height : (options.viewportHeight || num('VIEWPORT_HEIGHT', 768)),
          deviceScaleFactor: fp ? fp.deviceScaleFactor : (options.deviceScaleFactor || 1),
        },
        ignoreDefaultArgs: ['--enable-automation'],
        args: [
          '--disable-blink-features=AutomationControlled',
          '--disable-dev-shm-usage',
          '--no-sandbox',
          '--disable-gpu-sandbox',
          '--ignore-gpu-blocklist',
          '--enable-webgl',
          ...(fp ? [`--window-size=${fp.width},${fp.height}`, `--lang=${fp.language}`] : []),
          ...(proxyAddr ? [`--proxy-server=${proxyAddr}`] : []),
          ...(options.browserArgs || []),
        ],
      }));
    }
    let page;
    if (options.pageInstance) {
      page = options.pageInstance;
      attachResponseLogger(page, result);
      await wd('page.install_hooks', result.watchdogConfig.hooksMs, async () => {
        await installHooks(page, fp, options.swapData || null, captureInternals);
        if (captureInternals) await installDeepHooks(page);
        result.dynamicJsForce = await setupDynamicJsForce(page);
      });
    } else {
      page = await wd('page.new', result.watchdogConfig.pageMs, () => browser.newPage());
      attachResponseLogger(page, result);
      await wd('page.install_hooks', result.watchdogConfig.hooksMs, async () => {
        await installHooks(page, fp, options.swapData || null, captureInternals);
        if (captureInternals) await installDeepHooks(page);
        result.dynamicJsForce = await setupDynamicJsForce(page);
      });
      await page.setUserAgent((fp && fp.ua) || ua).catch(() => {});
      if (fp && fp.acceptLanguage) await page.setExtraHTTPHeaders({ 'Accept-Language': fp.acceptLanguage }).catch(() => {});
      const cdp = await page.target().createCDPSession().catch(() => null);
      if (cdp && fp && fp.timezone) await cdp.send('Emulation.setTimezoneOverride', { timezoneId: fp.timezone }).catch(() => {});
      await wd('page.goto', result.watchdogConfig.gotoMs, () => page.goto(targetUrl, { waitUntil: options.gotoWaitUntil || process.env.GOTO_WAIT_UNTIL || 'domcontentloaded', timeout: options.gotoTimeoutMs || num('GOTO_TIMEOUT_MS', 60000) }));
      await sleep(options.afterGotoMs ?? num('AFTER_GOTO_MS', 500));
      if (options.preCaptchaFills && options.preCaptchaFills.length) {
        result.preCaptchaFills = await wd('site.pre_captcha_fills', result.watchdogConfig.preActionMs, () => applyPreCaptchaFills(page, options.preCaptchaFills));
      }
      if (options.preCaptchaPresses && options.preCaptchaPresses.length) {
        result.preCaptchaPresses = await wd('site.pre_captcha_presses', result.watchdogConfig.preActionMs, () => applyPreCaptchaPresses(page, options.preCaptchaPresses));
      }
      if (options.preCaptchaClicks && options.preCaptchaClicks.length) {
        result.preCaptchaClicks = await wd('site.pre_captcha_clicks', result.watchdogConfig.preActionMs, () => applyPreCaptchaClicks(page, options.preCaptchaClicks));
      }
      if (options.preCaptchaAction) {
        result.preCaptchaAction = await wd('site.pre_captcha_action', result.watchdogConfig.preActionMs, () => options.preCaptchaAction(page, result).catch(e => ({ error: e.message })));
      }
    }
    const observedState = await wd('captcha.wait_ready', result.watchdogConfig.captchaMs, () => waitForCaptcha(page, result, sel, requestedCaptchaType));
    result.state = observedState;
    result.captchaType = observedState.captchaType;
    await sleep(options.afterCaptchaVisibleMs ?? num('AFTER_CAPTCHA_VISIBLE_MS', 500));
    result.challengeArtifact = await wd(
      'captcha.screenshot',
      result.watchdogConfig.runtimeMs,
      () => captureChallengeArtifact(page, observedState, outputDir),
    );
    if (observedState.captchaType !== CAPTCHA_TYPES.PUZZLE) {
      const waitVerify = options.verifyWaitMs || num('VERIFY_WAIT_MS', 12000);
      if (observedState.captchaType === CAPTCHA_TYPES.ONE_CLICK) {
        result.verifyNetwork = null;
        result.verifyResponse = null;
        result.interaction = await wd('captcha.one_click', result.watchdogConfig.dragMs, () => runOneClick(page, observedState));
      } else if (observedState.captchaType === CAPTCHA_TYPES.SLIDER) {
        result.verifyNetwork = null;
        result.verifyResponse = null;
        const sliderRun = await wd('captcha.slider_to_right', result.watchdogConfig.dragMs, () => runSliderToRight(page, observedState, profile, runMode, sel));
        result.listenerRun = sliderRun.run;
        result.distance = sliderRun.distance;
        result.trajectory = sliderRun.trajectory;
        result.start = sliderRun.start;
      } else if (observedState.captchaType === CAPTCHA_TYPES.IMAGE_RESTORE) {
        result.verifyNetwork = null;
        result.verifyResponse = null;
        const visionTimeout = Number(options.vision?.timeoutMs || 180000);
        const visionRetries = Math.max(1, Math.min(5, Number(options.vision?.retries || 2)));
        const restoreRun = await wd('captcha.image_restore', Math.max(result.watchdogConfig.dragMs, visionTimeout * visionRetries * 2 + 10000), () => runImageRestore(page, observedState, profile, runMode, sel, outputDir, options));
        result.listenerRun = restoreRun.run;
        result.distance = restoreRun.distance;
        result.restoreTargetLeft = restoreRun.targetLeft;
        result.maxDistance = restoreRun.maxDistance;
        result.trajectory = restoreRun.trajectory;
        result.start = restoreRun.start;
        result.vision = { ...restoreRun.vision, confidence: restoreRun.confidence };
        result.restoreMapping = restoreRun.mapping;
        result.restoreArtifact = restoreRun.artifact;
        result.restoreArtifacts = restoreRun.artifacts;
      } else if (observedState.captchaType !== CAPTCHA_TYPES.INVISIBLE) {
        throw new Error(`unsupported or undetected Aliyun challenge type: ${observedState.captchaType}`);
      }
      result.verificationWait = await waitForVerification(result, waitVerify);
      if (options.siteVerificationControl) {
        result.siteVerificationControl = await wd('site.verification_control', result.watchdogConfig.preActionMs, () => runSiteVerificationControl(page, result, options));
        result.siteVerificationEvidence = classifySiteVerificationEvidence(result, options);
      }
      result.runtime = await wd('runtime.snapshot:primary', result.watchdogConfig.runtimeMs, () => page.evaluate(() => ({
        calls: window.__AC && window.__AC.calls.slice(-50),
        errors: window.__AC && window.__AC.errors.slice(-20),
        payloads: window.__AC && window.__AC.payloads.slice(-40),
        formOps: window.__AC && window.__AC.formOps.slice(-40),
        listenerCount: window.__AC && window.__AC.listeners.length,
        captchaParams: window.__AC && window.__AC.captchaParams && window.__AC.captchaParams.slice(-20),
      })).catch(e => ({ error: e.message })));
      result.ok = verifyPassed(result.verifyResponse);
      result.verifyFailureCode = result.ok ? '' : verifyFailureCode(result);
      if (result.verifyFailureCode === 'F001') {
        result.f001Detected = true;
        result.retryHint = 'organic-next-attempt';
      }
      fs.writeFileSync(out, JSON.stringify(result, null, 2));
      return result;
    }
    const maxRefreshes = num('LISTENER_MAX_REFRESHES', 0);
    const maxVerifyRefreshes = num('LISTENER_MAX_VERIFY_REFRESHES', 0);
    const verifyRefreshCodes = envList('LISTENER_VERIFY_REFRESH_CODES', 'NONE').map(normalizeVerifyCode);
    let state, gap;
    result.initialReadRetries = [];
    for (let r = 0; r <= maxRefreshes; r++) {
      try {
        const tag = r === 0 ? 'selected' : `selected_retry_${r}`;
        const read = await wd(`captcha.read_gap:${tag}`, result.watchdogConfig.readGapMs, () => readGap(page, result, outputDir, tag, sel, ua));
        state = read.state; gap = read.gap;
        break;
      } catch (readErr) {
        const message = readErr && readErr.message || String(readErr);
        if (r >= maxRefreshes || !/gap not found|captcha images not found/i.test(message)) throw readErr;
        const currentState = await wd('captcha.state_before_initial_refresh', result.watchdogConfig.runtimeMs, () => captchaState(page, sel).catch(e => ({ error: e.message })));
        const refreshResult = await wd(`captcha.refresh:selected_retry_${r + 1}`, result.watchdogConfig.refreshMs, () => refreshPuzzle(page, currentState));
        result.initialReadRetries.push({ at: Date.now(), retry: r + 1, error: message, refreshResult });
        if (!refreshResult.changed) throw readErr;
        await sleep(800);
      }
    }
    if (!state || !gap) throw new Error('gap not found after refresh retries');
    let cand = candidateMetrics(state, gap);
    result.candidate = cand;
    result.refreshPolicy = { candidateMaxRefreshes: maxRefreshes, verifyMaxRefreshes: maxVerifyRefreshes, verifyRefreshCodes };
    if (!cand.ok && maxRefreshes > 0) {
      result.refreshes = result.refreshes || [];
      for (let r = 0; r < maxRefreshes; r++) {
        const refreshResult = await wd(`captcha.refresh:pre_${r + 1}`, result.watchdogConfig.refreshMs, () => refreshPuzzle(page, state));
        result.refreshes.push(refreshResult);
        if (!refreshResult.changed) break;
        await sleep(800);
        const refreshTag = `pre_${r + 1}`;
        try {
          const refreshRead = await wd(`captcha.read_gap:${refreshTag}`, result.watchdogConfig.readGapMs, () => readGap(page, result, outputDir, refreshTag, sel, ua));
          state = refreshRead.state; gap = refreshRead.gap;
          cand = candidateMetrics(state, gap);
          result[`candidate_${refreshTag}`] = cand;
          if (cand.ok) break;
        } catch (refreshErr) {
          result[`pre_refresh_${refreshTag}_error`] = { message: refreshErr.message };
        }
      }
      result.candidate = cand;
    }
    if (!cand.ok && process.env.LISTENER_ENFORCE_CANDIDATE_FILTER === '1') throw new Error(`candidate rejected: ${cand.reasons.join(',')}`);
    // Data Pool swap: if pool file exists and no explicit swapData, pick nearest successful data
    try {
      const poolPath = options.dataPoolPath || process.env.DATA_POOL_PATH || '';
      if (poolPath && !options.swapData && cand.ok && Number.isFinite(cand.raw)) {
        if (fs.existsSync(poolPath)) {
          const pool = JSON.parse(fs.readFileSync(poolPath, 'utf8'));
          const entries = Array.isArray(pool) ? pool : (pool.entries || []);
          const okEntries = entries.filter(e => e.ok && e.data && Number.isFinite(e.raw));
          if (okEntries.length) {
            const sameSource = okEntries.filter(e => e.source === cand.source);
            const searchEntries = sameSource.length ? sameSource : okEntries;
            const nearest = searchEntries.reduce((best, e) => {
              const d = Math.abs(e.raw - cand.raw);
              return d < best.d ? { e, d } : best;
            }, { e: null, d: Infinity });
            if (nearest.e && nearest.d <= Number(process.env.DATA_POOL_MAX_DIFF || 8)) {
              await page.evaluate((data) => { if (window.__AC) window.__AC.poolSwap = data; }, nearest.e.data);
              result.poolSwap = { raw: cand.raw, poolRaw: nearest.e.raw, diff: nearest.d, dataLen: nearest.e.data.length };
            }
          }
        }
      }
    } catch (poolErr) { result.poolSwapError = poolErr.message; }
    const sx = state.sliderRect.x + state.sliderRect.width / 2, sy = state.sliderRect.y + state.sliderRect.height / 2;
    const autoP = autoProfileFor(cand.raw);
    if (autoP) { if (!options.profile) options.profile = {}; options.profile.totalMs = autoP.totalMs; options.profile.steps = autoP.steps; profile = resolvedProfile(options.profile); }
    const points = buildTrajectory(sx, sy, cand.distance, profile.style || null, profile);
    result.trajectory = points.__meta;
    result.start = { x: sx, y: sy };
    const runSpec = {
      mode: runMode,
      startX: sx,
      startY: sy,
      points,
      warm: buildWarm(sx, sy, { warmPoints: profile.warmPoints, warmDtMin: profile.warmDtMinMs, warmDtMax: profile.warmDtMaxMs, warmStartX: profile.warmStartX, warmStartY: profile.warmStartY }),
      releaseHoldMs: Number(profile.releaseHoldMs),
      releaseHoldJitterMs: Number(profile.releaseHoldJitterMs),
      pressHoldMs: profile.pressHoldMs,
      pressHoldJitterMs: profile.pressHoldJitterMs,
      postDownMs: profile.postDownMs,
      sliderSelector: sel.slider,
      bodySelector: sel.body,
      imageSelector: sel.image,
      puzzleSelector: sel.puzzle,
      alignPuzzle: process.env.LISTENER_ALIGN_PUZZLE === '1',
      targetPuzzleX: cand.raw,
      alignTolerancePx: num('LISTENER_ALIGN_TOLERANCE_PX', 1.5),
      alignIters: num('LISTENER_ALIGN_ITERS', 4),
      alignGain: num('LISTENER_ALIGN_GAIN', 1),
      alignMaxStepPx: num('LISTENER_ALIGN_MAX_STEP_PX', 18),
    };
    result.verifyNetwork = null;
    result.verifyResponse = null;
    result.listenerRun = await wd('captcha.drag:primary', result.watchdogConfig.dragMs, () => (runMode === 'cdpdrag' || runMode === 'mouse') ? runCdpMouse(page, runSpec) : (runMode === 'xdotool' ? runXdotoolDrag(page, runSpec) : page.evaluate((spec) => window.__AC_run(spec), runSpec)));
    const waitVerify = options.verifyWaitMs || num('VERIFY_WAIT_MS', 12000), started = Date.now();
    while (!result.verifyNetwork && Date.now() - started < waitVerify) await sleep(150);
    result.runtime = await wd('runtime.snapshot:primary', result.watchdogConfig.runtimeMs, () => page.evaluate(() => ({ calls: window.__AC && window.__AC.calls.slice(-50), errors: window.__AC && window.__AC.errors.slice(-20), jsonHits: window.__AC && window.__AC.jsonHits.slice(-40), payloads: window.__AC && window.__AC.payloads.slice(-40), formOps: window.__AC && window.__AC.formOps.slice(-40), listenerCount: window.__AC && window.__AC.listeners.length, captchaParams: window.__AC && window.__AC.captchaParams && window.__AC.captchaParams.slice(-20), btoaHits: window.__AC && window.__AC.btoaHits && window.__AC.btoaHits.slice(-20), u8Hits: window.__AC && window.__AC.u8Hits && window.__AC.u8Hits.slice(-20), trackPairs: window.__AC && window.__AC.trackPairs && window.__AC.trackPairs.slice(-40), foundTrackObjects: window.__AC && window.__AC.foundTrackObjects && window.__AC.foundTrackObjects.slice(-20), trackHits: window.__AC && window.__AC.trackHits && window.__AC.trackHits.slice(-40), vmpIns: window.__AC && window.__AC.vmpIns && window.__AC.vmpIns.slice(-40), updates: window.__AC && window.__AC.updates && window.__AC.updates.slice(-20), secretHits: window.__AC && window.__AC.secretHits && window.__AC.secretHits.slice(-20), sigKeys: window.__AC && window.__AC.sigKeys && window.__AC.sigKeys.slice(-20), deepHooksInited: window.__AC && window.__AC.deepHooksInited })).catch(e => ({ error: e.message })));
    result.ok = verifyPassed(result.verifyResponse);
    result.verifyFailureCode = result.ok ? '' : verifyFailureCode(result);
    // Auto-delta search: if F015 with valid candidate, try +/- 4/8 px on SAME puzzle before refreshing
    const f015Like = result.verifyResponse && result.verifyResponse.VerifyCode === 'F015';
    const autoDeltaEnabled = envFlag('LISTENER_AUTO_DELTA', false);
    if (!result.ok && autoDeltaEnabled && f015Like && cand.ok) {
      const deltaSteps = [4, -4, 8, -8];
      for (const step of deltaSteps) {
        const adjDist = Math.max(12, Math.min(cand.maxAllowed, cand.raw + cand.baseDelta + step));
        if (adjDist === cand.distance) continue;
        const autoPAdj = autoProfileFor(cand.raw);
        if (autoPAdj) { if (!options.profile) options.profile = {}; options.profile.totalMs = autoPAdj.totalMs; options.profile.steps = autoPAdj.steps; profile = resolvedProfile(options.profile); }
        const adjPoints = buildTrajectory(sx, sy, adjDist, profile.style || null, profile);
        const adjSpec = { ...runSpec, points: adjPoints, targetPuzzleX: cand.raw };
        result.verifyNetwork = null;
        result.verifyResponse = null;
        const adjTag = `delta_${step >= 0 ? '+' : ''}${step}`;
        result[`listenerRun_${adjTag}`] = await wd(`captcha.drag:${adjTag}`, result.watchdogConfig.dragMs, () => (runMode === 'cdpdrag' || runMode === 'mouse') ? runCdpMouse(page, adjSpec) : (runMode === 'xdotool' ? runXdotoolDrag(page, adjSpec) : page.evaluate((spec) => window.__AC_run(spec), adjSpec)));
        const adjStarted = Date.now();
        while (!result.verifyNetwork && Date.now() - adjStarted < waitVerify) await sleep(150);
        const adjOk = verifyPassed(result.verifyResponse);
        result[`delta_${adjTag}`] = { step, raw: cand.raw, distance: adjDist, code: result.verifyResponse?.VerifyCode, ok: adjOk };
        if (adjOk) {
          result.ok = true;
          result.candidate = { ...cand, distance: adjDist, autoDeltaStep: step };
          result.trajectory = adjPoints.__meta;
          result.listenerRun = result[`listenerRun_${adjTag}`];
          result.finalSolve = { phase: 'auto-delta', tag: adjTag, step };
          break;
        }
      }
    }
    // F001 recovery: flag for next attempt randomization
    const f001Like = result.verifyResponse && result.verifyResponse.VerifyCode === 'F001';
    if (f001Like) { result.f001Detected = true; result.retryHint = 'organic-next-attempt'; }
    const initialVerifyRefreshAllowed = verifyCodeAllowed(result.verifyFailureCode, verifyRefreshCodes);
    if (!result.ok && maxVerifyRefreshes > 0 && initialVerifyRefreshAllowed) {
      result.refreshes = result.refreshes || [];
      for (let r = 0; r < maxVerifyRefreshes; r++) {
        const refreshResult = await wd(`captcha.refresh:verify_${r + 1}`, result.watchdogConfig.refreshMs, () => refreshPuzzle(page, result.state));
        result.refreshes.push(refreshResult);
        if (!refreshResult.changed) break;
        await sleep(800);
        const refreshTag = `refresh_${r + 1}`;
        try {
          const { state: rState, gap: rGap } = await wd(`captcha.read_gap:${refreshTag}`, result.watchdogConfig.readGapMs, () => readGap(page, result, outputDir, refreshTag, sel, ua));
          const rCand = candidateMetrics(rState, rGap);
          result[`candidate_${refreshTag}`] = rCand;
          if (!rCand.ok && process.env.LISTENER_ENFORCE_CANDIDATE_FILTER === '1') continue;
          const rSx = rState.sliderRect.x + rState.sliderRect.width / 2;
          const rSy = rState.sliderRect.y + rState.sliderRect.height / 2;
          const autoPR = autoProfileFor(rCand.raw);
          if (autoPR) { if (!options.profile) options.profile = {}; options.profile.totalMs = autoPR.totalMs; options.profile.steps = autoPR.steps; profile = resolvedProfile(options.profile); }
          const rPoints = buildTrajectory(rSx, rSy, rCand.distance, profile.style || null, profile);
          const rSpec = {
            mode: runMode,
            startX: rSx,
            startY: rSy,
            points: rPoints,
            warm: buildWarm(rSx, rSy, { warmPoints: profile.warmPoints, warmDtMin: profile.warmDtMinMs, warmDtMax: profile.warmDtMaxMs, warmStartX: profile.warmStartX, warmStartY: profile.warmStartY }),
            releaseHoldMs: Number(profile.releaseHoldMs),
            releaseHoldJitterMs: Number(profile.releaseHoldJitterMs),
            pressHoldMs: profile.pressHoldMs,
            pressHoldJitterMs: profile.pressHoldJitterMs,
            postDownMs: profile.postDownMs,
            sliderSelector: sel.slider,
            bodySelector: sel.body,
            imageSelector: sel.image,
            puzzleSelector: sel.puzzle,
            alignPuzzle: process.env.LISTENER_ALIGN_PUZZLE === '1',
            targetPuzzleX: rCand.raw,
            alignTolerancePx: num('LISTENER_ALIGN_TOLERANCE_PX', 1.5),
            alignIters: num('LISTENER_ALIGN_ITERS', 4),
            alignGain: num('LISTENER_ALIGN_GAIN', 1),
            alignMaxStepPx: num('LISTENER_ALIGN_MAX_STEP_PX', 18),
          };
          result.verifyNetwork = null;
          result.verifyResponse = null;
          result[`listenerRun_${refreshTag}`] = await wd(`captcha.drag:${refreshTag}`, result.watchdogConfig.dragMs, () => (runMode === 'cdpdrag' || runMode === 'mouse') ? runCdpMouse(page, rSpec) : (runMode === 'xdotool' ? runXdotoolDrag(page, rSpec) : page.evaluate((spec) => window.__AC_run(spec), rSpec)));
          const rStarted = Date.now();
          while (!result.verifyNetwork && Date.now() - rStarted < waitVerify) await sleep(150);
          result.ok = verifyPassed(result.verifyResponse);
          result.verifyFailureCode = result.ok ? '' : verifyFailureCode(result);
          if (result.ok) {
            result.state = rState;
            result.gap = rGap;
            result.candidate = { ...rCand, refreshTag };
            result.trajectory = rPoints.__meta;
            result.start = { x: rSx, y: rSy };
            result.listenerRun = result[`listenerRun_${refreshTag}`];
            result.finalSolve = { phase: 'refresh', tag: refreshTag };
            break;
          }
          if (!verifyCodeAllowed(result.verifyFailureCode, verifyRefreshCodes)) {
            result.verifyRefreshStopped = { code: result.verifyFailureCode, tag: refreshTag, reason: 'code-not-allowed' };
            break;
          }
        } catch (refreshErr) {
          result[`refresh_${refreshTag}_error`] = { message: refreshErr.message };
        }
      }
    } else if (!result.ok && maxVerifyRefreshes > 0) {
      result.verifyRefreshSkipped = { code: result.verifyFailureCode, reason: 'code-not-allowed' };
    }
    fs.writeFileSync(out, JSON.stringify(result, null, 2));
    return result;
  } catch (e) {
    const outputDir = options.outputDir ? path.resolve(options.outputDir) : defaultOutputDir();
    const out = options.out ? path.resolve(options.out) : (process.env.OUT ? path.resolve(process.env.OUT) : path.join(outputDir, 'aliyun_captcha_run.json'));
    const failed = {
      ...(partialResult || {}),
      ok: false,
      error: { message: e.message, stack: String(e.stack || '').slice(0, 4000) },
      watchdog: errWatchdog(e) || (partialResult && partialResult.watchdog),
      targetUrl: (partialResult && partialResult.targetUrl) || options.targetUrl || options.url || process.env.TARGET_URL || '',
      selectors: (partialResult && partialResult.selectors) || selectors(options.selectors || {}),
      outputDir,
      out,
    };
    fs.mkdirSync(outputDir, { recursive: true });
    fs.writeFileSync(out, JSON.stringify(failed, null, 2));
    throw e;
  } finally {
    if (ownedBrowser && browser) {
      await withWatchdog('browser.close', watchdogMs('ALIYUN_CLOSE_WATCHDOG_MS', 8000), () => browser.close(), partialResult).catch(() => {});
    }
    if (anonymizedProxyToClose) {
      try {
        const ProxyChain = require('proxy-chain');
        await withWatchdog('proxy.close', watchdogMs('ALIYUN_PROXY_CLOSE_WATCHDOG_MS', 8000), () => ProxyChain.closeAnonymizedProxy(anonymizedProxyToClose, true), partialResult);
      } catch {}
    }
    restoreProfileEnv();
  }
}


function copyAttemptArtifacts(result, finalOutputDir, finalOut) {
  try {
    const srcDir = result && result.outputDir;
    const hasSrcDir = !!srcDir;
    const sameDir = hasSrcDir && path.resolve(srcDir) === path.resolve(finalOutputDir);
    fs.mkdirSync(finalOutputDir, { recursive: true });
    if (hasSrcDir && !sameDir) {
      for (const name of ['aliyun_bg_selected.png', 'aliyun_puzzle_selected.png', 'aliyun_restore_selected.png', 'aliyun_restore_background.png', 'aliyun_restore_fragment.png', 'aggregate.json', 'aggregate.tsv']) {
        const src = path.join(srcDir, name), dst = path.join(finalOutputDir, name);
        if (fs.existsSync(src)) fs.copyFileSync(src, dst);
      }
    }
    if (result) {
      if (hasSrcDir && !sameDir) result.finalAttemptOutputDir = srcDir;
      result.outputDir = finalOutputDir;
      result.out = finalOut;
      fs.writeFileSync(finalOut, JSON.stringify(result, null, 2));
    }
  } catch {}
}

async function solveCaptcha(options = {}) {
  const profile = resolvedProfile(options.profile || {});
  const maxAttemptsRaw = options.maxAttempts ?? profile.maxAttempts ?? process.env.LISTENER_MAX_ATTEMPTS ?? 1;
  const maxAttempts = Math.max(1, Math.min(10, Math.floor(Number(maxAttemptsRaw) || 1)));
  const baseOutputDir = options.outputDir ? path.resolve(options.outputDir) : defaultOutputDir();
  const finalOut = options.out ? path.resolve(options.out) : (process.env.OUT ? path.resolve(process.env.OUT) : path.join(baseOutputDir, 'aliyun_captcha_run.json'));
  const attempts = [];
  let lastResult = null;
  let lastError = null;

  for (let i = 1; i <= maxAttempts; i++) {
    const attemptDir = maxAttempts === 1 ? baseOutputDir : path.join(baseOutputDir, `attempt_${i}`);
    const attemptOut = maxAttempts === 1 ? finalOut : path.join(attemptDir, 'aliyun_captcha_run.json');
    const attemptProfile = { ...profile };
    // F001 recovery: randomize trajectory style, warm start, and timing on subsequent attempts
    if (lastResult && lastResult.f001Detected) {
      attemptProfile.style = 'organic';
      attemptProfile.totalMs = num('LISTENER_F001_TOTAL_MS', 1850 + Math.floor(Math.random() * 900));
      attemptProfile.steps = num('LISTENER_F001_STEPS', 88 + Math.floor(Math.random() * 35));
      attemptProfile.warmPoints = num('LISTENER_F001_WARM_POINTS', 8 + Math.floor(Math.random() * 9));
      attemptProfile.warmStartX = 800 + Math.floor(Math.random() * 400);
      attemptProfile.warmStartY = 400 + Math.floor(Math.random() * 300);
      attemptProfile.pressHoldMs = 120 + Math.floor(Math.random() * 200);
      attemptProfile.postDownMs = 100 + Math.floor(Math.random() * 300);
      attemptProfile.releaseHoldMs = 250 + Math.floor(Math.random() * 250);
    }
    try {
      const result = await solveCaptchaOnce({ ...options, outputDir: attemptDir, out: attemptOut, profile: attemptProfile });
      result.attempt = i;
      result.maxAttempts = maxAttempts;
      attempts.push({ attempt: i, ok: !!result.ok, verifyCode: result.verifyResponse && result.verifyResponse.VerifyCode, verifyFailureCode: result.verifyFailureCode || '', retryHint: result.retryHint || '', raw: result.candidate && result.candidate.raw, distance: result.candidate && result.candidate.distance, source: result.candidate && result.candidate.source, out: attemptOut });
      result.attempts = attempts;
      fs.writeFileSync(attemptOut, JSON.stringify(result, null, 2));
      lastResult = result;
      if (result.ok || i === maxAttempts) {
        copyAttemptArtifacts(result, baseOutputDir, finalOut);
        return result;
      }
    } catch (e) {
      lastError = e;
      attempts.push({ attempt: i, ok: false, error: e.message, watchdog: errWatchdog(e), out: attemptOut });
      if (i === maxAttempts) {
        if (lastResult) {
          lastResult.attempts = attempts;
          copyAttemptArtifacts(lastResult, baseOutputDir, finalOut);
          return lastResult;
        }
        fs.mkdirSync(baseOutputDir, { recursive: true });
        fs.writeFileSync(finalOut, JSON.stringify({ ok: false, error: { message: e.message, stack: String(e.stack || '').slice(0, 4000) }, watchdog: errWatchdog(e), maxAttempts, attempts, out: finalOut, outputDir: baseOutputDir }, null, 2));
        throw e;
      }
    }
    let baseRetry = num('LISTENER_RETRY_DELAY_MS', 500);
    let retryJitter = num('LISTENER_RETRY_JITTER_MS', Math.floor(baseRetry * 0.4));
    let backoff = 0;
    const lastCode = normalizeVerifyCode(lastResult && (lastResult.verifyFailureCode || (lastResult.verifyResponse && lastResult.verifyResponse.VerifyCode)));
    if (lastCode === 'F001') {
      const f001Streak = attempts.slice().reverse().findIndex(a => normalizeVerifyCode(a.verifyFailureCode || a.verifyCode) !== 'F001');
      const streak = f001Streak === -1 ? attempts.length : f001Streak;
      baseRetry = num('LISTENER_F001_RETRY_DELAY_MS', Math.max(baseRetry, 1800));
      retryJitter = num('LISTENER_F001_RETRY_JITTER_MS', Math.max(retryJitter, 900));
      backoff = Math.max(0, streak - 1) * num('LISTENER_F001_BACKOFF_MS', 600);
    }
    await sleep(baseRetry + backoff + Math.floor(Math.random() * Math.max(0, retryJitter)));
  }
  if (lastError) throw lastError;
  return lastResult;
}


async function main() {
  const outputDir = defaultOutputDir();
  const out = process.env.OUT ? path.resolve(process.env.OUT) : path.join(outputDir, 'aliyun_captcha_run.json');
  try {
    const result = await solveCaptcha({ outputDir, out });
    const cand = result.candidate || {};
    console.log(JSON.stringify({ ok: result.ok, verifyCode: result.verifyResponse && result.verifyResponse.VerifyCode, verifyResult: result.verifyResponse && result.verifyResponse.VerifyResult, attempt: result.attempt, maxAttempts: result.maxAttempts, raw: cand.raw, distance: cand.distance, source: cand.source, trajectory: result.trajectory, out }, null, 2));
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
}

module.exports = {
  solveCaptcha,
  solveCaptchaOnce,
  detectGapByPuzzle,
  detectGapByLightPatch,
  detectGapBySlotMask,
  detectRestoreStrip,
  detectRestoreBoundaryContinuity,
  renderRestoreCandidate,
  renderRestoreCandidateFocus,
  restorePuzzleTravel,
  restoreSliderTravel,
  restoreQuantizedSliderTravel,
  buildRestoreVisionCandidates,
  buildRestoreRefinementCandidates,
  selectRestoreBoundaryFallback,
  buildTrajectory,
  candidateMetrics,
  selectors,
  DEFAULT_SELECTORS,
  STABLE_PROFILE,
  resolvedProfile,
  autoProfileFor,
  installHooks,
  setupDynamicJsForce,
  readGap,
  waitForCaptcha,
  runCdpMouse,
  buildWarm,
  CAPTCHA_TYPES,
  detectCaptchaType,
  normalizeCaptchaType,
  normalizeVendorCaptchaType,
  verifyPassed,
  requestCarriesCaptchaVerifyParam,
  isAliyunVerificationEndpoint,
  responseDecisionSummary,
  applyPreCaptchaFills,
  applyPreCaptchaPresses,
  applyPreCaptchaClicks,
  mutateCaptchaVerifyParam,
  classifySiteVerificationEvidence,
  runSiteVerificationControl,
  attachResponseLogger,
  captureChallengeArtifact,
};

if (require.main === module) main();
