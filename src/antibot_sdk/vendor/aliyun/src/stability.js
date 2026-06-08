#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { solveCaptcha, STABLE_PROFILE, resolvedProfile, autoProfileFor } = require('./runner');

const ROOT = path.resolve(__dirname, '..');
function ts() { return new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14); }
function intEnv(name, fallback) { const n = Number(process.env[name]); return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback; }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function codeOf(r) { return r && r.verifyResponse && r.verifyResponse.VerifyCode || ''; }
function expectedProfileFor(raw, profile) {
  const auto = process.env.LISTENER_AUTO_PROFILE === '1' && Number.isFinite(Number(raw)) ? autoProfileFor(Number(raw)) : null;
  return auto ? { ...profile, ...auto, autoProfile: true } : profile;
}
function resultRow(runDir, r, profile) {
  const c = r && r.candidate || {};
  const t = r && r.trajectory || {};
  const expected = expectedProfileFor(c.raw, profile);
  return {
    run: path.basename(runDir),
    ok: !!(r && r.ok),
    verifyCode: codeOf(r),
    verifyResult: !!(r && r.verifyResponse && r.verifyResponse.VerifyResult === true),
    attempt: r && r.attempt,
    maxAttempts: r && r.maxAttempts,
    raw: c.raw,
    distance: c.distance,
    source: c.source,
    trajectoryStyle: t.style,
    trajectoryTotal: t.total,
    trajectorySteps: t.steps,
    expectedTotal: Number(expected.totalMs),
    expectedSteps: Number(expected.steps),
    expectedAutoProfile: !!expected.autoProfile,
    out: r && r.out || path.join(runDir, 'aliyun_captcha_run.json'),
  };
}
function isStableRow(row, profile) {
  const requireSource = profile.requireGapSource === undefined ? 'slot-mask' : profile.requireGapSource;
  const sourceOk = !requireSource || row.source === requireSource;
  const stepsOk = Number(row.trajectorySteps) === Number(row.expectedSteps);
  const total = Number(row.trajectoryTotal), expected = Number(row.expectedTotal);
  const totalOk = total === expected || ((row.trajectoryStyle === 'organic' || row.trajectoryStyle === 'human') && total >= expected && total <= expected + 1200);
  return !!row.ok && row.verifyCode === 'T001' && sourceOk && stepsOk && totalOk;
}
function writeTsv(file, rows) {
  const cols = Object.keys(rows[0] || { run: '' });
  fs.writeFileSync(file, [cols.join('\t'), ...rows.map(r => cols.map(c => r[c] == null ? '' : String(r[c])).join('\t'))].join('\n') + '\n');
}
async function stableCheck(options = {}) {
  const targetUrl = options.targetUrl || options.url || process.env.TARGET_URL || '';
  if (!targetUrl) throw new Error('targetUrl/TARGET_URL is required');
  const count = options.count || intEnv('STABILITY_COUNT', 4);
  const delayMs = options.delayMs ?? intEnv('STABILITY_DELAY_MS', 2000);
  const profile = resolvedProfile(options.profile || {});
  const prefix = options.prefix || process.env.STABILITY_PREFIX || `${ts()}_stable`;
  const rootDir = path.resolve(options.rootDir || process.env.STABILITY_ROOT_DIR || path.join(ROOT, 'runs'));
  const rows = [], results = [];

  for (let i = 1; i <= count; i++) {
    const runDir = path.join(rootDir, `${prefix}_${i}`);
    let result;
    try {
      result = await solveCaptcha({ ...options, targetUrl, outputDir: runDir, out: path.join(runDir, 'aliyun_captcha_run.json'), profile });
    } catch (e) {
      result = { ok: false, out: path.join(runDir, 'aliyun_captcha_run.json'), error: { message: e.message } };
    }
    const row = resultRow(runDir, result, profile);
    row.stableRow = isStableRow(row, profile);
    rows.push(row);
    results.push(result);
    console.log(JSON.stringify(row));
    if (i < count && delayMs > 0) {
      const jitter = Math.floor(delayMs * 0.3);
      await sleep(delayMs + Math.floor(Math.random() * jitter));
    }
  }

  const summaryDir = path.join(rootDir, prefix);
  const summary = {
    at: new Date().toISOString(),
    targetUrl,
    count,
    passed: rows.filter(r => r.stableRow).length,
    stable: rows.length === count && rows.every(r => r.stableRow),
    profile,
    outDir: summaryDir,
    jsonPath: path.join(summaryDir, 'stable_check.json'),
    tsvPath: path.join(summaryDir, 'stable_check.tsv'),
    rows,
  };
  fs.mkdirSync(summaryDir, { recursive: true });
  fs.writeFileSync(summary.jsonPath, JSON.stringify(summary, null, 2));
  writeTsv(summary.tsvPath, rows);
  return summary;
}

async function main() {
  try {
    const summary = await stableCheck();
    console.log(JSON.stringify({ stable: summary.stable, passed: summary.passed, count: summary.count, out: summary.jsonPath, tsv: summary.tsvPath }, null, 2));
    process.exit(summary.stable ? 0 : 1);
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
}

module.exports = { stableCheck, isStableRow, resultRow };
if (require.main === module) main();
