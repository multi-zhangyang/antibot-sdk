#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const inputs = process.argv.slice(2);
if (!inputs.length) { console.error('usage: node src/aggregate.js <run-dir|run-json>...'); process.exit(2); }
function fileFor(x) { if (fs.existsSync(x) && fs.statSync(x).isDirectory()) return path.join(x, 'aliyun_captcha_run.json'); return x; }
function parseTrack(r) { const hits = (r.runtime && r.runtime.jsonHits || []).map(x => x && x.s).filter(Boolean); const s = [...hits].reverse().find(x => /TrackList/.test(x)); if (!s) return { mp: 0, mm: 0, dragMs: null }; try { const j = JSON.parse(s), t = j.TrackList || j.trackList || {}; const pairs = x => String(x || '').split('|').filter(Boolean); return { mp: pairs(t.mp).length, mm: pairs(t.mm).length, dragMs: null }; } catch { return { mp: 0, mm: 0, dragMs: null }; } }
const rows = [];
for (const input of inputs) {
  const f = fileFor(input);
  if (!fs.existsSync(f)) { console.error('[missing]', input); continue; }
  const r = JSON.parse(fs.readFileSync(f, 'utf8'));
  const t = parseTrack(r), vr = r.verifyResponse || {}, c = r.candidate || {};
  rows.push({ run: path.basename(path.dirname(f)), ok: !!r.ok, verifyCode: vr.VerifyCode || '', verifyResult: vr.VerifyResult === true, attempt: r.attempt, maxAttempts: r.maxAttempts, raw: c.raw, distance: c.distance, source: c.source, componentMinY: c.componentMinY, componentMaxY: c.componentMaxY, componentScore: c.componentScore, componentCount: c.componentCount, trajectoryTotal: r.trajectory && r.trajectory.total, trajectorySteps: r.trajectory && r.trajectory.steps, listenerCalls: r.listenerRun && r.listenerRun.calls && r.listenerRun.calls.length, alignReads: r.listenerRun && r.listenerRun.align && r.listenerRun.align.length, trackMp: t.mp, trackMm: t.mm, out: f });
}
if (process.env.TSV === '1') {
  const cols = Object.keys(rows[0] || { run: '' }); console.log(cols.join('\t')); for (const r of rows) console.log(cols.map(c => r[c] == null ? '' : String(r[c])).join('\t'));
} else console.log(JSON.stringify({ total: rows.length, rows }, null, 2));
