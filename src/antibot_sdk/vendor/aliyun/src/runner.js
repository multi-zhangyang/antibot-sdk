#!/usr/bin/env node
'use strict';
try { require('dotenv').config({ quiet: true }); } catch {}
/*
 * Generic Aliyun CAPTCHA V3 slider runner.
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
const { PNG } = require('pngjs');
function loadPuppeteer(useRebrowser) {
  return useRebrowser ? require('rebrowser-puppeteer-core') : require('puppeteer-core');
}

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_SELECTORS = Object.freeze({
  entry: '#aliyunCaptcha-captcha-body,#aliyunCaptcha-captcha-wrapper',
  body: '#aliyunCaptcha-sliding-body',
  slider: '#aliyunCaptcha-sliding-slider',
  image: '#aliyunCaptcha-img',
  puzzle: '#aliyunCaptcha-puzzle',
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
    image: overrides.image || process.env.CAPTCHA_IMAGE_SELECTOR || DEFAULT_SELECTORS.image,
    puzzle: overrides.puzzle || process.env.CAPTCHA_PUZZLE_SELECTOR || DEFAULT_SELECTORS.puzzle,
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

function attachResponseLogger(page, result) {
  if (!page || !result || result.__responseLoggerAttached) return;
  Object.defineProperty(result, '__responseLoggerAttached', { value: true, enumerable: false, configurable: true });
  page.on('response', async res => {
    const url = res.url();
    if (!/captcha|aliyun|cloudauth|VerifyCaptcha/i.test(url)) return;
    const req = res.request();
    let text = ''; try { text = await res.text(); } catch {}
    const postData = req.postData() || '';
    const isVerifyRequest = /Action=VerifyCaptchaV3|CaptchaVerifyParam/i.test(postData);
    const item = { at: Date.now(), method: req.method(), url, status: res.status(), postDataLen: postData.length, isVerifyRequest, text: text.slice(0, 20000) };
    result.net.push(item);
    if (isVerifyRequest && /VerifyCode|VerifyResult|T001|F001|F015/.test(text)) {
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

async function captchaState(page, sel = selectors()) {
  return page.evaluate((SEL) => {
    function one(el) {
      if (!el) return null;
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      const visible = !!(r.width > 1 && r.height > 1 && cs.display !== 'none' && cs.visibility !== 'hidden' && Number(cs.opacity || 1) !== 0);
      return { visible, x: r.left + r.width / 2, y: r.top + r.height / 2, width: r.width, height: r.height, left: r.left, top: r.top, id: el.id || '', cls: String(el.className || ''), tag: el.tagName || '', text: (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 120), src: el.src || '' };
    }
    function all(sel) { try { return Array.from(document.querySelectorAll(sel || '')).map(one).filter(Boolean); } catch { return []; } }
    function pick(sel) { const xs = all(sel); xs.sort((a, b) => (b.visible - a.visible) || (b.width * b.height - a.width * a.height)); return xs[0] || null; }
    function autoSlider() {
      const xs = all('[id*=slide],[class*=slide],[id*=slider],[class*=slider],[role=slider]')
        .filter(x => x.visible && x.width >= 16 && x.width <= 140 && x.height >= 16 && x.height <= 100);
      xs.sort((a, b) => Math.abs(a.width - a.height) - Math.abs(b.width - b.height) || (a.width * a.height - b.width * b.height));
      return xs[0] || null;
    }
    function imageCandidates() { return all('img').filter(x => x.visible && x.src && x.width >= 10 && x.height >= 10); }
    function autoBg() {
      const xs = imageCandidates().filter(x => x.width >= 120 && x.height >= 60);
      xs.sort((a, b) => b.width * b.height - a.width * a.height);
      return xs[0] || null;
    }
    function autoPuzzle(bg) {
      const bgSrc = bg && bg.src;
      const xs = imageCandidates().filter(x => x.src !== bgSrc && x.width >= 18 && x.height >= 18 && x.width <= 160 && x.height <= 160);
      xs.sort((a, b) => Math.abs(a.width - a.height) - Math.abs(b.width - b.height) || b.width * b.height - a.width * a.height);
      return xs[0] || null;
    }
    const pickedBody = pick(SEL.body);
    const pickedSlider = pick(SEL.slider);
    const pickedImg = pick(SEL.image);
    const pickedPuzzle = pick(SEL.puzzle);
    const slider = pickedSlider || autoSlider();
    const img = pickedImg || autoBg();
    const puzzle = pickedPuzzle || autoPuzzle(img);
    const body = pickedBody || img;
    const entry = pick(SEL.entry);
    const ready = !!(body && body.visible && slider && slider.visible && img && img.src && puzzle && puzzle.src && img.src !== puzzle.src);
    return { ready, bodyRect: body && { x: body.left, y: body.top, width: body.width, height: body.height }, sliderRect: slider && { x: slider.left, y: slider.top, width: slider.width, height: slider.height }, imgSrc: img && img.src, puzzleSrc: puzzle && puzzle.src, entry, selectorAuto: { body: !pickedBody && !!body, slider: !pickedSlider && !!slider, image: !pickedImg && !!img, puzzle: !pickedPuzzle && !!puzzle }, href: location.href, title: document.title };
  }, sel).catch(e => ({ ready: false, error: e.message }));
}

async function clickEntry(page, result, sel = selectors()) {
  const clicked = await page.evaluate((SEL) => {
    function vis(el) { if (!el) return null; const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); if (!(r.width > 20 && r.height > 10) || cs.display === 'none' || cs.visibility === 'hidden') return null; return { x: r.left + r.width / 2, y: r.top + r.height / 2, text: (el.textContent || '').replace(/\s+/g, ' ').trim(), id: el.id || '', cls: String(el.className || ''), area: r.width * r.height }; }
    const items = [];
    for (const el of Array.from(document.querySelectorAll(SEL.entry || ''))) { const v = vis(el); if (v) items.push({ ...v, score: 100 }); }
    for (const el of Array.from(document.querySelectorAll('button,div,span,a'))) { const v = vis(el); if (!v) continue; if (/click to verify|verify|验证|点击验证/i.test(v.text)) items.push({ ...v, score: 50 }); }
    items.sort((a, b) => b.score - a.score || a.area - b.area);
    return items[0] || null;
  }, sel).catch(e => ({ error: e.message }));
  if (clicked && !clicked.error) {
    await page.mouse.move(clicked.x - 40, clicked.y - 24, { steps: 10 }).catch(() => {});
    await page.mouse.click(clicked.x, clicked.y, { delay: 80 }).catch(() => {});
  }
  result.entryClicks.push({ at: Date.now(), clicked });
  return clicked;
}

async function waitForCaptcha(page, result, sel = selectors()) {
  const timeout = num('CAPTCHA_WAIT_MS', 90000), clickEvery = num('CAPTCHA_CLICK_RETRY_MS', 1000);
  const started = Date.now(); let lastClick = 0, state = null;
  result.entryClicks = [];
  while (Date.now() - started < timeout) {
    state = await captchaState(page, sel);
    if (state.ready) return state;
    if (Date.now() - lastClick >= clickEvery) { await clickEntry(page, result, sel); lastClick = Date.now(); }
    await sleep(300);
  }
  throw new Error(`captcha not ready after ${timeout}ms: ${JSON.stringify(state)}`);
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
  await page.mouse.up({ button: 'left' }).catch(() => {});
  calls.push({ at: Date.now(), type: 'mouseup', mode: 'cdpdrag', x: Math.round(cur.x), y: Math.round(cur.y), buttons: 0 });
  return { ok: true, mode: 'cdpdrag', align: alignReads, calls: calls.slice(-100), errors: [] };
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
    const result = { at: new Date().toISOString(), targetUrl, selectors: sel, profile, net: [], outputDir, out };
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
      if (options.preCaptchaAction) {
        result.preCaptchaAction = await wd('site.pre_captcha_action', result.watchdogConfig.preActionMs, () => options.preCaptchaAction(page, result).catch(e => ({ error: e.message })));
      }
    }
    await wd('captcha.wait_ready', result.watchdogConfig.captchaMs, () => waitForCaptcha(page, result, sel));
    await sleep(options.afterCaptchaVisibleMs ?? num('AFTER_CAPTCHA_VISIBLE_MS', 500));
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
    result.ok = !!(result.verifyResponse && (result.verifyResponse.VerifyResult === true || result.verifyResponse.VerifyCode === 'T001'));
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
        const adjOk = !!(result.verifyResponse && (result.verifyResponse.VerifyResult === true || result.verifyResponse.VerifyCode === 'T001'));
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
          result.ok = !!(result.verifyResponse && (result.verifyResponse.VerifyResult === true || result.verifyResponse.VerifyCode === 'T001'));
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
      for (const name of ['aliyun_bg_selected.png', 'aliyun_puzzle_selected.png', 'aggregate.json', 'aggregate.tsv']) {
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
};

if (require.main === module) main();
