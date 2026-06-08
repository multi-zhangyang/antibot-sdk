/*
 * Tencent Captcha verify capture hook
 * 入口: 在验证码 dy/tgJCap 渲染页面执行 (iframe 内或主页面均可)。
 * 注入时机: slider 拖动前；XHR/fetch 发送 verify 前。
 * 依赖: 浏览器原生 XMLHttpRequest/fetch。
 * 输出: window.__tc_verify_capture = [{url,status,text,body,ts}]
 */
(function installTencentCaptchaVerifyCapture(){
  if (window.__tc_verify_hooked) return;
  window.__tc_verify_hooked = true;
  window.__tc_verify_capture = [];

  function pushCapture(item) {
    try {
      window.__tc_verify_capture.push(Object.assign({ ts: Date.now() }, item));
    } catch (_) {}
  }

  const XHR = window.XMLHttpRequest;
  if (XHR && XHR.prototype) {
    const open = XHR.prototype.open;
    const send = XHR.prototype.send;
    XHR.prototype.open = function(method, url) {
      this.__tc_method = method;
      this.__tc_url = String(url || '');
      return open.apply(this, arguments);
    };
    XHR.prototype.send = function(body) {
      this.__tc_body = body;
      const xhr = this;
      function capture() {
        try {
          if (xhr.__tc_url && xhr.__tc_url.indexOf('cap_union_new_verify') !== -1) {
            pushCapture({
              type: 'xhr',
              method: xhr.__tc_method,
              url: xhr.__tc_url,
              status: xhr.status,
              text: xhr.responseText,
              body: String(xhr.__tc_body || '')
            });
          }
        } catch (_) {}
      }
      xhr.addEventListener('load', capture);
      xhr.addEventListener('readystatechange', function(){
        if (xhr.readyState === 4) capture();
      });
      return send.apply(this, arguments);
    };
  }

  if (window.fetch && !window.fetch.__tc_verify_hooked) {
    const fetch0 = window.fetch;
    const fetch1 = function(input, init) {
      const url = typeof input === 'string' ? input : (input && input.url) || '';
      const body = init && init.body;
      return fetch0.apply(this, arguments).then(async function(resp) {
        try {
          if (String(url).indexOf('cap_union_new_verify') !== -1) {
            const clone = resp.clone();
            pushCapture({
              type: 'fetch',
              method: (init && init.method) || 'GET',
              url: String(url),
              status: clone.status,
              text: await clone.text(),
              body: String(body || '')
            });
          }
        } catch (_) {}
        return resp;
      });
    };
    fetch1.__tc_verify_hooked = true;
    window.fetch = fetch1;
  }
})();
