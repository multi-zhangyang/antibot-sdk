async function installDeepHooks(page) {
  await page.evaluateOnNewDocument(() => {
    // --- Phase 1: Feilin / signature hooks (rH, rS, rx.stringify) ---
    // Wait for feilin.js to load and patch its internal functions
    function tryPatchFeilin() {
      try {
        // rH signature function: deletes t.Signature, sorts keys, builds query string, then calls rS(rx.stringify(...))
        // We need to find rS and rx.stringify somehow. They are local to a webpack module.
        // Alternative: patch Object.prototype methods used by the signature builder.
        const origSort = Array.prototype.sort;
        Array.prototype.sort = function(...args) {
          // Detect if this looks like Object.keys(t).sort() pattern inside signature building
          if (this.length > 2 && this.length < 30 && typeof this[0] === 'string' && this.some(x => /Signature|data|certifyId|deviceToken|sceneId/.test(x))) {
            push(window.__AC && window.__AC.sigKeys, { at: Date.now(), keys: this.slice() }, 40);
          }
          return origSort.apply(this, args);
        };
      } catch {}
    }
    tryPatchFeilin();

    // --- Phase 2: DynamicJS / VMP hooks ---
    if (!window.__AC) window.__AC = {};
    window.__AC.deepHooksInited = Date.now();
    if (!window.__AC.updates) window.__AC.updates = [];
    if (!window.__AC.vmpIns) window.__AC.vmpIns = [];
    if (!window.__AC.trackHits) window.__AC.trackHits = [];
    if (!window.__AC.secretHits) window.__AC.secretHits = [];
    if (!window.__AC.sigKeys) window.__AC.sigKeys = [];
    function push(arr, item, limit) { try { if (!arr) return; arr.push(item); while (arr.length > limit) arr.shift(); } catch {} }

    function isTrackLike(s) {
      try { return typeof s === 'string' && s.length > 100 && /trackList|TrackList|mm\||mp\||xPos|slidePos/.test(s); } catch { return false; }
    }

    // Proxy objects containing TrackList to catch data assignment
    function proxyIfTrackList(v) {
      try {
        if (!v || typeof v !== 'object' || v.__AC_proxied) return v;
        if (v.TrackList || v.trackList) {
          v.__AC_proxied = true;
          const descs = Object.getOwnPropertyNames(v);
          for (const key of descs) {
            const d = Object.getOwnPropertyDescriptor(v, key);
            if (d && d.writable) {
              let localVal = d.value;
              Object.defineProperty(v, key, {
                get() { return localVal; },
                set(newVal) {
                  localVal = newVal;
                  if (key === 'data' && typeof newVal === 'string' && newVal.length > 100) {
                    push(window.__AC.trackHits, { at: Date.now(), type: 'data-assigned', dataLen: newVal.length, dataPrefix: newVal.slice(0, 60), keys: Object.keys(v), xPos: v.xPos, slidePos: v.slidePos, arg: v.arg }, 40);
                  }
                  if (key === 'TrackList' && newVal === undefined) {
                    push(window.__AC.trackHits, { at: Date.now(), type: 'tracklist-deleted', keys: Object.keys(v), dataExists: typeof v.data === 'string', dataLen: (typeof v.data === 'string' ? v.data.length : 0) }, 40);
                  }
                },
                configurable: true, enumerable: d.enumerable
              });
            }
          }
        }
      } catch {}
      return v;
    }

    // Hook JSON.stringify globally with deeper capture
    const origJSON = JSON.stringify;
    JSON.stringify = function(...args) {
      const v = args[0];
      proxyIfTrackList(v);
      const result = origJSON.apply(this, args);
      try {
        if (v && (v.trackList !== undefined || v.TrackList !== undefined || v.data !== undefined || v.xPos !== undefined || v.slidePos !== undefined)) {
          const mm = (v.TrackList && (v.TrackList.mm || v.TrackList.MM)) || '';
          const mp = (v.TrackList && (v.TrackList.mp || v.TrackList.MP)) || '';
          push(window.__AC.trackHits, { at: Date.now(), type: 'stringify', keys: Object.keys(v || {}), trackLen: mm.length, mpLen: mp.length, dataType: typeof v.data, argType: typeof v.arg, arg: (typeof v.arg === 'string' ? v.arg : undefined), argLen: (typeof v.arg === 'string' ? v.arg.length : 0), resultLen: result.length, xPos: v.xPos, slidePos: v.slidePos, resultPrefix: result.slice(0, 200) }, 40);
        }
      } catch {}
      return result;
    };

    // Hook String.fromCharCode to catch VMP output chunks
    const origSFC = String.fromCharCode;
    String.fromCharCode = function(...args) {
      try {
        if (args.length > 500 && args.length < 2000) {
          const first3 = args.slice(0, 3);
          if (first3[0] === 0x25 && first3[1] === 0x13) {
            push(window.__AC.vmpIns, { at: Date.now(), len: args.length, first32: first3.concat(args.slice(3, 29)), is25_13_27: true }, 20);
          }
          // Also capture if args look like base64-ish printable range
          const printable = args.every(a => a >= 32 && a <= 126);
          if (printable && !isTrackLike(origSFC.apply(this, args))) {
            push(window.__AC.vmpIns, { at: Date.now(), len: args.length, first3, printable: true }, 20);
          }
        }
      } catch {}
      return origSFC.apply(this, args);
    };

    // Hook Uint8Array constructor to catch pako output
    if (typeof Uint8Array !== 'undefined') {
      const OrigU8 = Uint8Array;
      window.Uint8Array = function(...args) {
        const arr = new OrigU8(...args);
        try {
          if (arr.length > 500 && arr.length < 3000 && arr[0] === 0x25 && arr[1] === 0x13) {
            push(window.__AC.vmpIns, { at: Date.now(), u8Len: arr.length, first32: Array.from(arr.slice(0, 32)), source: 'Uint8Array' }, 20);
          }
        } catch {}
        return arr;
      };
      window.Uint8Array.prototype = OrigU8.prototype;
    }

    // --- Phase 3: Poll for dynamicJS exports and proxy Object.update-like functions ---
    setInterval(() => {
      try {
        // Walk webpack module cache if exposed
        const caches = [window.__webpack_modules__, window.webpackJsonp, window.__webpack_require__?.m, window.__WRS_MODULES__];
        for (const cache of caches) {
          if (!cache) continue;
          for (const [key, mod] of Object.entries(cache)) {
            if (typeof mod !== 'function') continue;
            try {
              const str = mod.toString();
              if (str.length > 5000 && /update|deflate|inflate|stringify|track|data/i.test(str)) {
                if (!mod.__AC_proxied) {
                  mod.__AC_proxied = true;
                  push(window.__AC.updates, { at: Date.now(), key, hasUpdate: /update/.test(str), hasDeflate: /deflate/.test(str), length: str.length }, 20);
                }
              }
            } catch {}
          }
        }
      } catch {}
    }, 1500);
  });
}

module.exports = { installDeepHooks };
