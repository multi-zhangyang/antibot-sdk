'use strict';

const path = require('path');

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fillVisibleInput(page, selector, value, opts = {}) {
  const timeout = opts.timeout || 15000;
  const el = await page.waitForSelector(selector, { visible: true, timeout });
  if (!el) throw new Error(`input not found: ${selector}`);
  await el.click({ clickCount: 3 });
  await page.keyboard.press('Backspace').catch(() => {});
  await el.type(String(value), { delay: opts.delay ?? 5 });
  return true;
}

async function clickFirst(page, selectors, opts = {}) {
  const xs = Array.isArray(selectors) ? selectors : [selectors];
  for (const selector of xs) {
    try {
      const el = await page.$(selector);
      if (!el) continue;
      const visible = await el.evaluate(node => {
        const r = node.getBoundingClientRect();
        const cs = getComputedStyle(node);
        return r.width > 1 && r.height > 1 && cs.display !== 'none' && cs.visibility !== 'hidden';
      }).catch(() => false);
      if (!visible && !opts.allowHidden) continue;
      await el.click({ delay: opts.delay ?? 50 });
      return { selector };
    } catch {}
  }
  return null;
}

async function qoderSignup(page, result) {
  const email = `qoder${Date.now()}${Math.floor(Math.random() * 10000)}@9527.email`;
  const password = 'TestPass123!';
  const outputDir = result && result.outputDir;

  await fillVisibleInput(page, '#basic_firstName', 'Test');
  await fillVisibleInput(page, '#basic_lastName', 'User');
  await fillVisibleInput(page, '#basic_email', email);
  const checkbox = await clickFirst(page, ['.ant-checkbox-input', '[type="checkbox"]'], { allowHidden: true });
  await clickFirst(page, ['button[type="submit"]']);

  await page.waitForSelector('#basic_password', { visible: true, timeout: 20000 });
  await fillVisibleInput(page, '#basic_password', password);
  await clickFirst(page, ['button[type="submit"]']);

  await page.waitForSelector('#aliyunCaptcha-captcha-wrapper,#aliyunCaptcha-captcha-body', {
    visible: true,
    timeout: 30000,
  });
  await sleep(400);
  await clickFirst(page, ['#aliyunCaptcha-captcha-wrapper', '#aliyunCaptcha-captcha-body']);
  await page.waitForFunction(() => {
    const body = document.querySelector('#aliyunCaptcha-sliding-body');
    const slider = document.querySelector('#aliyunCaptcha-sliding-slider');
    const img = document.querySelector('#aliyunCaptcha-img');
    const puzzle = document.querySelector('#aliyunCaptcha-puzzle');
    return body && slider && img && puzzle &&
      body.offsetWidth > 10 && slider.offsetWidth > 10 &&
      img.offsetWidth > 10 && puzzle.offsetWidth > 10 &&
      img.src && puzzle.src && img.src !== puzzle.src;
  }, { timeout: 30000 });

  const sliderPos = await page.evaluate(() => {
    const slider = document.querySelector('#aliyunCaptcha-sliding-slider');
    if (!slider) return null;
    const r = slider.getBoundingClientRect();
    return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
  });
  if (sliderPos) {
    await page.mouse.move(sliderPos.x - 70, sliderPos.y - 35, { steps: 14 }).catch(() => {});
    await sleep(250);
    await page.mouse.move(sliderPos.x, sliderPos.y, { steps: 12 }).catch(() => {});
    await sleep(260);
  }

  if (outputDir) {
    await page.screenshot({ path: path.join(outputDir, 'qoder_precaptcha.png'), fullPage: true })
      .catch(() => {});
  }
  return {
    siteProfile: 'qoder_signup',
    formFilled: true,
    passwordSubmitted: true,
    checkbox,
    captchaClicked: true,
    email,
    sliderPos,
  };
}

const SITE_PROFILES = {
  qoder_signup: qoderSignup,
  qoder: qoderSignup,
};

function autoSiteProfile(options = {}) {
  const u = String(options.targetUrl || options.url || '').toLowerCase();
  if (u.includes('qoder.com/users/sign-up')) return 'qoder_signup';
  return '';
}

function attachSiteProfile(options = {}) {
  const name = options.siteProfile || options.preCaptchaActionName || autoSiteProfile(options);
  if (!name) return { options, siteProfile: '' };
  const fn = SITE_PROFILES[name];
  if (!fn) throw new Error(`unknown Aliyun siteProfile: ${name}`);
  return { options: { ...options, preCaptchaAction: fn }, siteProfile: name };
}

module.exports = {
  SITE_PROFILES,
  attachSiteProfile,
  qoderSignup,
};
