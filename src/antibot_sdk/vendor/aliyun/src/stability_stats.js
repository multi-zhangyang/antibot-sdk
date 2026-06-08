#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function counterInc(obj, key, n = 1) { obj[String(key ?? '')] = (obj[String(key ?? '')] || 0) + n; }
function mean(xs) { return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0; }
function median(xs) {
  if (!xs.length) return 0;
  const ys = [...xs].sort((a, b) => a - b), m = Math.floor(ys.length / 2);
  return ys.length % 2 ? ys[m] : (ys[m - 1] + ys[m]) / 2;
}
function round(n, d = 3) { const p = 10 ** d; return Math.round(n * p) / p; }
function stablePath(arg) {
  const p = path.resolve(process.cwd(), arg);
  const candidates = [
    p,
    path.join(p, 'stable_check.json'),
    path.join(ROOT, 'runs', arg, 'stable_check.json'),
  ];
  return candidates.find(x => fs.existsSync(x) && fs.statSync(x).isFile());
}
function countVerifyRequests(runJson) {
  return (runJson.net || []).filter(x => x && x.isVerifyRequest).length;
}
function summarize(arg) {
  const jsonPath = stablePath(arg);
  if (!jsonPath) throw new Error(`stable_check.json not found for ${arg}`);
  const stable = readJson(jsonPath);
  const rows = stable.rows || [];
  const out = {
    run: path.basename(path.dirname(jsonPath)),
    stable: !!stable.stable,
    passed: stable.passed || 0,
    count: stable.count || rows.length,
    attemptDist: {},
    avgAttempt: 0,
    source: {},
    style: {},
    raw: null,
    codes: {},
    preSuccessFailCodes: {},
    solverAttempts: 0,
    netVerifyPerSolved: 0,
    perRunNetVerify: {},
    finalSolve: {},
    refreshesPerAttempt: {},
    refreshPolicy: {},
    verifyRefreshSkipped: {},
    retryHints: {},
    durationSec: 0,
    solvesPerMinute: 0,
  };
  const attempts = [], raws = [];
  const startedAts = [];
  let verifyRequests = 0;
  for (const row of rows) {
    counterInc(out.attemptDist, row.attempt);
    counterInc(out.source, row.source || '');
    counterInc(out.style, row.trajectoryStyle || '');
    if (Number.isFinite(Number(row.raw))) raws.push(Number(row.raw));
    if (Number.isFinite(Number(row.attempt))) attempts.push(Number(row.attempt));
    const finalRun = row.out && fs.existsSync(row.out) ? readJson(row.out) : null;
    if (finalRun && finalRun.at) startedAts.push(Date.parse(finalRun.at));
    const attemptRows = finalRun && Array.isArray(finalRun.attempts) ? finalRun.attempts : [];
    let runVerify = 0;
    counterInc(out.finalSolve, (finalRun && finalRun.finalSolve && finalRun.finalSolve.phase) || 'initial');
    out.solverAttempts += attemptRows.length;
    for (const a of attemptRows) {
      const code = a.verifyCode || 'NONE';
      counterInc(out.codes, code);
      if (a.retryHint) counterInc(out.retryHints, a.retryHint);
      if (a !== attemptRows[attemptRows.length - 1]) counterInc(out.preSuccessFailCodes, code);
      if (a.out && fs.existsSync(a.out)) {
        const aj = readJson(a.out);
        const n = countVerifyRequests(aj);
        runVerify += n;
        verifyRequests += n;
        counterInc(out.refreshesPerAttempt, (aj.refreshes || []).length);
        const policy = aj.refreshPolicy ? JSON.stringify(aj.refreshPolicy) : '{}';
        counterInc(out.refreshPolicy, policy);
        if (aj.verifyRefreshSkipped) counterInc(out.verifyRefreshSkipped, `${aj.verifyRefreshSkipped.code || 'NONE'}:${aj.verifyRefreshSkipped.reason || ''}`);
      }
    }
    counterInc(out.perRunNetVerify, runVerify);
  }
  out.avgAttempt = round(mean(attempts));
  out.netVerifyPerSolved = rows.length ? round(verifyRequests / rows.length) : 0;
  const summaryAt = Date.parse(stable.at || '');
  const firstAt = startedAts.filter(Number.isFinite).sort((a, b) => a - b)[0];
  if (Number.isFinite(summaryAt) && Number.isFinite(firstAt) && summaryAt >= firstAt) {
    out.durationSec = round((summaryAt - firstAt) / 1000, 1);
    out.solvesPerMinute = out.durationSec > 0 ? round(rows.length / (out.durationSec / 60), 2) : 0;
  }
  if (raws.length) out.raw = { min: Math.min(...raws), max: Math.max(...raws), avg: round(mean(raws), 1), median: median(raws) };
  return out;
}
function main(argv) {
  const args = argv.slice(2);
  if (!args.length) {
    console.error('usage: node src/stability_stats.js <run-name|run-dir|stable_check.json> [...]');
    process.exit(2);
  }
  for (const arg of args) console.log(JSON.stringify(summarize(arg), null, 2));
}

module.exports = { summarize };
if (require.main === module) main(process.argv);
