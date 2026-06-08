#!/usr/bin/env node
'use strict';
const fs = require('fs');
const { solveCaptcha } = require('./src/runner');
const { attachSiteProfile } = require('./src/site_profiles');

async function main() {
  const inputPath = process.argv[2];
  if (!inputPath) throw new Error('usage: node bridge.js <options.json>');
  let options = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
  if (options.env && typeof options.env === 'object') {
    for (const [k, v] of Object.entries(options.env)) {
      if (v !== undefined && v !== null) process.env[k] = String(v);
    }
    delete options.env;
  }
  const resolved = attachSiteProfile(options);
  options = resolved.options;
  const result = await solveCaptcha(options);
  if (resolved.siteProfile) result.siteProfile = resolved.siteProfile;
  process.stdout.write(JSON.stringify(result));
}

main().catch((e) => {
  process.stderr.write(String(e && e.stack || e) + '\n');
  process.exit(1);
});
