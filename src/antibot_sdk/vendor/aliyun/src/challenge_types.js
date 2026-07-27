'use strict';

const CAPTCHA_TYPES = Object.freeze({
  AUTO: 'auto',
  INVISIBLE: 'invisible',
  ONE_CLICK: 'one_click',
  SLIDER: 'slider',
  PUZZLE: 'puzzle',
  IMAGE_RESTORE: 'image_restore',
  UNKNOWN: 'unknown',
});

const PASS_VERIFY_CODES = Object.freeze(['T001']);
const NON_PRODUCTION_VERIFY_CODES = Object.freeze(['T005', 'T006']);

const VENDOR_CAPTCHA_TYPES = Object.freeze({
  TRACELESS: CAPTCHA_TYPES.INVISIBLE,
  CHECK_BOX: CAPTCHA_TYPES.ONE_CLICK,
  CHECKBOX: CAPTCHA_TYPES.ONE_CLICK,
  SLIDING: CAPTCHA_TYPES.SLIDER,
  PUZZLE: CAPTCHA_TYPES.PUZZLE,
  INPAINTING: CAPTCHA_TYPES.IMAGE_RESTORE,
});

const TYPE_ALIASES = Object.freeze({
  '': CAPTCHA_TYPES.AUTO,
  auto: CAPTCHA_TYPES.AUTO,
  detect: CAPTCHA_TYPES.AUTO,
  automatic: CAPTCHA_TYPES.AUTO,
  invisible: CAPTCHA_TYPES.INVISIBLE,
  traceless: CAPTCHA_TYPES.INVISIBLE,
  seamless: CAPTCHA_TYPES.INVISIBLE,
  one_click: CAPTCHA_TYPES.ONE_CLICK,
  oneclick: CAPTCHA_TYPES.ONE_CLICK,
  checkbox: CAPTCHA_TYPES.ONE_CLICK,
  click: CAPTCHA_TYPES.ONE_CLICK,
  slider: CAPTCHA_TYPES.SLIDER,
  slide: CAPTCHA_TYPES.SLIDER,
  puzzle: CAPTCHA_TYPES.PUZZLE,
  jigsaw: CAPTCHA_TYPES.PUZZLE,
  slider_puzzle: CAPTCHA_TYPES.PUZZLE,
  image_restore: CAPTCHA_TYPES.IMAGE_RESTORE,
  image_restoration: CAPTCHA_TYPES.IMAGE_RESTORE,
  restoration: CAPTCHA_TYPES.IMAGE_RESTORE,
  restore: CAPTCHA_TYPES.IMAGE_RESTORE,
  unknown: CAPTCHA_TYPES.UNKNOWN,
});

function normalizeCaptchaType(value, { allowUnknown = false } = {}) {
  const key = String(value == null ? '' : value)
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
  const normalized = TYPE_ALIASES[key];
  if (normalized) return normalized;
  if (allowUnknown) return CAPTCHA_TYPES.UNKNOWN;
  throw new Error(
    `unsupported Aliyun captcha type: ${value}; expected auto, invisible, one_click, slider, puzzle, or image_restore`,
  );
}

function verifyPayload(value) {
  if (!value || typeof value !== 'object') return {};
  if (value.Result && typeof value.Result === 'object') return value.Result;
  return value;
}

function verifyCode(value) {
  const payload = verifyPayload(value);
  return String(payload.VerifyCode || payload.verifyCode || '').trim().toUpperCase();
}

function verifyPassed(value) {
  const payload = verifyPayload(value);
  return payload.VerifyResult === true && PASS_VERIFY_CODES.includes(verifyCode(payload));
}

function normalizeVendorCaptchaType(value) {
  const key = String(value == null ? '' : value)
    .trim()
    .toUpperCase()
    .replace(/[\s-]+/g, '_');
  return VENDOR_CAPTCHA_TYPES[key] || null;
}

function detectCaptchaType(state = {}, requested = CAPTCHA_TYPES.AUTO) {
  const forced = normalizeCaptchaType(requested);
  if (forced !== CAPTCHA_TYPES.AUTO) return forced;
  const vendorType = normalizeVendorCaptchaType(
    state.vendorCaptchaType || state.initCaptchaType,
  );
  if (vendorType) return vendorType;
  if (verifyPassed(state.verifyResponse) && !state.visibleChallenge) {
    return CAPTCHA_TYPES.INVISIBLE;
  }

  const text = String(state.text || state.prompt || '').toLowerCase();
  const hint = String(state.challengeHint || state.typeHint || '').toLowerCase();
  const surface = `${hint} ${text}`;
  if (/image[_ -]?restore|restoration|restore image|图像复原|图片复原|还原(?:完整)?图片|复原/.test(surface)) {
    return CAPTCHA_TYPES.IMAGE_RESTORE;
  }
  if (/one[_ -]?click|checkbox|not a robot|confirm you are human|一点即过|不是机器人|确认您不是机器人/.test(surface)) {
    return CAPTCHA_TYPES.ONE_CLICK;
  }
  if (/invisible|traceless|seamless|无痕|无感/.test(surface)) {
    return CAPTCHA_TYPES.INVISIBLE;
  }
  const puzzleNode = `${state.puzzle && state.puzzle.id || ''} ${state.puzzle && state.puzzle.cls || ''}`;
  const hasDistinctPuzzle = !!(
    state.imgSrc &&
    state.puzzleSrc &&
    state.imgSrc !== state.puzzleSrc &&
    (state.selectorAuto && state.selectorAuto.puzzle === false || /aliyun|puzzle|jigsaw/i.test(puzzleNode))
  );
  if (/puzzle|jigsaw|拼图|缺口/.test(surface) || hasDistinctPuzzle) {
    return CAPTCHA_TYPES.PUZZLE;
  }
  if (/drag.+right|slide.+right|拖动.+最右|滑动.+最右/.test(surface)) {
    return CAPTCHA_TYPES.SLIDER;
  }
  if (state.imgSrc && state.imageRect && state.sliderRect && !hasDistinctPuzzle) {
    return CAPTCHA_TYPES.IMAGE_RESTORE;
  }
  if (/slider|slide|滑块|按住.+拖动/.test(surface) || state.sliderRect) return CAPTCHA_TYPES.SLIDER;
  return CAPTCHA_TYPES.UNKNOWN;
}

function captchaReady(state = {}, requested = CAPTCHA_TYPES.AUTO) {
  const captchaType = detectCaptchaType(state, requested);
  const visible = (value) => !!(value && value.visible !== false);
  if (captchaType === CAPTCHA_TYPES.INVISIBLE) return verifyPassed(state.verifyResponse);
  if (captchaType === CAPTCHA_TYPES.ONE_CLICK) {
    return visible(state.checkbox) || (visible(state.entry) && !!state.visibleChallenge);
  }
  if (captchaType === CAPTCHA_TYPES.SLIDER) {
    return visible(state.slider) && (visible(state.track) || !!state.bodyRect);
  }
  if (captchaType === CAPTCHA_TYPES.PUZZLE) {
    return visible(state.slider) && !!state.imgSrc && !!state.puzzleSrc && state.imgSrc !== state.puzzleSrc;
  }
  if (captchaType === CAPTCHA_TYPES.IMAGE_RESTORE) {
    return visible(state.slider) && !!state.imgSrc && !!state.bodyRect;
  }
  return false;
}

module.exports = {
  CAPTCHA_TYPES,
  NON_PRODUCTION_VERIFY_CODES,
  PASS_VERIFY_CODES,
  captchaReady,
  detectCaptchaType,
  normalizeCaptchaType,
  normalizeVendorCaptchaType,
  verifyCode,
  verifyPassed,
};
