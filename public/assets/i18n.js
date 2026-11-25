'use strict';

(function (global) {
  const DICT = {
    th: {
      nav_kiosk: 'จอ Kiosk',
      nav_admin: 'หลังบ้าน',
      nav_setup: 'ตั้งค่าครั้งแรก',
      zero_image_badge: 'Zero-Image • ML-DSA-65',
      mock_mode_warn: 'โหมดทดสอบในเครื่อง (DEMO_MOCK_AUTH=true) — ปิดเสมอเมื่อใช้งานจริง',
      needs_keys_warn: 'ยังไม่ได้ตั้งค่า LOGIN512_PUBLISHABLE_KEY และ LOGIN512_SECRET_KEY ในไฟล์ .env',
      btn_face_login: '📸 ยืนยันตัวตนด้วยใบหน้า (Login512)',
      btn_passkey_login: '👆 ใช้ลายนิ้วมือ / Passkey สำรอง',
      btn_face_enroll: '📸 ลงทะเบียนด้วยใบหน้า',
      btn_passkey_enroll: '👆 ลงทะเบียนด้วยลายนิ้วมือ / Passkey',
      wifi_lock_on: '📶 บังคับ Wi-Fi สถานที่: เปิดอยู่',
      wifi_lock_off: '🌐 บังคับ Wi-Fi สถานที่: ปิดอยู่',
      sse_connected: 'อัปเดตสดแบบ Real-time',
      sse_reconnecting: 'กำลังเชื่อมต่อสด...',
      qr_rotating_in: 'QR เปลี่ยนรหัสใหม่ใน {sec} วินาที',
      today_count_label: 'เช็กอินวันนี้',
      no_checkins_yet: 'ยังไม่มีรายการเช็กอินวันนี้ — ส่อง QR เพื่อเริ่มต้น',
      err_ORIGIN_NOT_ALLOWED: 'Login512 ยังไม่อนุญาตเว็บไซต์นี้ ({origin}) ให้เพิ่ม {origin} ในช่อง Allowed Origins ที่ Login512 Portal (หน้าตั้งค่า) แล้วลองใหม่',
      err_QR_EXPIRED: 'QR Code หมดอายุแล้ว (ป้องกันการถ่ายภาพ/วิดีโอคอลส่งต่อ) กรุณาส่องจากหน้าจอ Kiosk ใหม่อีกครั้ง',
      err_QR_INVALID_SIGNATURE: 'ลายเซ็น QR Code ไม่ถูกต้อง กรุณาส่องจากหน้าจอ Kiosk ของจริง',
      err_WIFI_IP_BLOCKED: 'ถูกปฏิเสธ: มือถือของคุณไม่ได้เชื่อมต่อ Wi-Fi ของสถานที่ (กันวิดีโอคอลส่อง QR จากระยะไกล)',
      err_WIFI_IP_MISCONFIGURED: 'จุดนี้เปิดบังคับ Wi-Fi IP แต่แอดมินยังไม่ได้เพิ่ม IP ของสถานที่',
      err_TICKET_ALREADY_USED: 'รหัสเช็กอินนี้ถูกใช้ไปแล้ว กรุณาส่อง QR ใหม่',
      err_TICKET_EXPIRED: 'หมดเวลายืนยันตัวตน (90 วิ) กรุณาส่อง QR ใหม่',
      err_NONCE_MISMATCH: 'รหัสป้องกันการยิงซ้ำ (Nonce) ไม่ตรงกัน กรุณาลองใหม่',
      err_STEP_UP_REQUIRED: 'ระบบต้องการการยืนยันเพิ่มเติม (Step-up) ไม่สามารถอนุมัติได้',
    },
    en: {
      nav_kiosk: 'Kiosk Screen',
      nav_admin: 'Admin',
      nav_setup: 'Setup',
      zero_image_badge: 'Zero-Image • ML-DSA-65',
      mock_mode_warn: 'Local Test Mode (DEMO_MOCK_AUTH=true) — MUST be false in production',
      needs_keys_warn: 'LOGIN512_PUBLISHABLE_KEY and LOGIN512_SECRET_KEY are not configured in .env yet',
      btn_face_login: '📸 Verify with Face (Login512)',
      btn_passkey_login: '👆 Fallback: Fingerprint / Passkey',
      btn_face_enroll: '📸 Enroll with Face',
      btn_passkey_enroll: '👆 Enroll with Fingerprint / Passkey',
      wifi_lock_on: '📶 On-Site Wi-Fi IP Lock: ON',
      wifi_lock_off: '🌐 On-Site Wi-Fi IP Lock: OFF',
      sse_connected: 'Live Real-Time Feed',
      sse_reconnecting: 'Reconnecting live feed...',
      qr_rotating_in: 'QR rotates in {sec}s',
      today_count_label: "Today's Check-Ins",
      no_checkins_yet: 'No check-ins yet today — scan the live QR to begin',
      err_ORIGIN_NOT_ALLOWED: 'Login512 does not allow this website ({origin}) yet. Add {origin} to Allowed Origins in the Login512 Portal (Settings), then try again.',
      err_QR_EXPIRED: 'QR expired (anti-photo/video-call protection). Please scan the live Kiosk screen again.',
      err_QR_INVALID_SIGNATURE: 'Invalid QR signature. Please scan an official Kiosk screen.',
      err_WIFI_IP_BLOCKED: 'Blocked: your device is not on the authorized on-site Wi-Fi network (blocks remote video-call relay).',
      err_WIFI_IP_MISCONFIGURED: 'Wi-Fi IP Lock is enabled, but no allowed IP/CIDR has been configured yet.',
      err_TICKET_ALREADY_USED: 'This check-in ticket was already redeemed. Please scan the live QR again.',
      err_TICKET_EXPIRED: 'Check-in session expired (90s). Please scan the live QR again.',
      err_NONCE_MISMATCH: 'Anti-replay nonce mismatch. Please try again.',
      err_STEP_UP_REQUIRED: 'Step-up verification required before access can be granted.',
    },
  };

  function getLang(defaultLang = 'th') {
    const saved = localStorage.getItem('l512_sc_lang');
    if (saved === 'th' || saved === 'en') return saved;
    return defaultLang === 'en' ? 'en' : 'th';
  }

  function setLang(lang) {
    localStorage.setItem('l512_sc_lang', lang === 'en' ? 'en' : 'th');
  }

  function t(key, lang, vars = {}) {
    const l = lang === 'en' ? 'en' : 'th';
    let str = (DICT[l] && DICT[l][key]) || (DICT.en && DICT.en[key]) || key;
    for (const [k, v] of Object.entries(vars)) {
      str = str.replaceAll(`{${k}}`, String(v));
    }
    return str;
  }

  function localizeError(errObj, lang) {
    const code = errObj?.code || '';
    const translated = t(`err_${code}`, lang);
    if (translated !== `err_${code}`) return translated;
    return errObj?.message || code || 'Request failed';
  }

  function escapeHtml(str) {
    return String(str == null ? '' : str).replace(/[&<>"']/g, (m) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    }[m]));
  }

  function formatTime(iso, lang) {
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString(lang === 'en' ? 'en-US' : 'th-TH', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return iso || '';
    }
  }

  function formatDateTime(iso, lang) {
    try {
      const d = new Date(iso);
      return d.toLocaleString(lang === 'en' ? 'en-US' : 'th-TH', {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return iso || '';
    }
  }

  let _sdkPromise = null;
  function loadLogin512Sdk(sdkUrl) {
    if (global.Login512) return Promise.resolve(global.Login512);
    if (_sdkPromise) return _sdkPromise;
    _sdkPromise = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = sdkUrl || 'https://login512.com/sdk/login512-sdk.js?v=2026.11.25';
      s.async = true;
      s.onload = () => (global.Login512 ? resolve(global.Login512) : reject(new Error('Login512 SDK loaded without global object')));
      s.onerror = () => reject(new Error(`Failed to load Login512 SDK from ${s.src}`));
      document.head.appendChild(s);
    });
    return _sdkPromise;
  }

  async function apiJson(url, options = {}) {
    const { headers: customHeaders, ...restOptions } = options;
    const res = await fetch(url, {
      credentials: 'same-origin',
      ...restOptions,
      headers: {
        'Content-Type': 'application/json',
        ...(customHeaders || {}),
      },
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data?.error?.message || `HTTP ${res.status}`);
      err.code = data?.error?.code || `HTTP_${res.status}`;
      err.status = res.status;
      err.payload = data?.error || data;
      throw err;
    }
    return data;
  }

  async function runBiometricAuth({ login512Cfg, action, method, nonce, enrollmentToken, externalUserId, mockSubject }) {
    if (login512Cfg.demoMockAuth) {
      const act = action === 'enroll' ? (method === 'passkey' ? 'enroll_passkey' : 'enroll') : 'login';
      const data = await apiJson('/api/demo/mock-token', {
        method: 'POST',
        body: JSON.stringify({
          sub: mockSubject || externalUserId || 'usr_demo_01',
          act,
          mod: method === 'passkey' ? 'PASSKEY' : 'FACE',
          nonce: method === 'face' && act === 'login' ? nonce : null,
        }),
      });
      return { token: data.token };
    }

    const Login512 = await loadLogin512Sdk(login512Cfg.sdkUrl);
    const client = Login512.init({
      publishableKey: login512Cfg.publishableKey,
      endpoint: login512Cfg.endpoint,
      locale: getLang(),
      // Errors Login512 reports while its window stays open (e.g. this site is not in Allowed Origins):
      // show them on this page too, so nobody is left looking at a screen where "nothing happens".
      onAuthError: (payload) => showLogin512Problem(payload),
    });

    if (action === 'enroll') {
      if (method === 'passkey') {
        return client.enrollPasskey({ enrollmentToken, externalUserId });
      }
      return client.enroll({ enrollmentToken, presentation: 'modal' });
    }

    if (method === 'passkey') {
      return client.loginWithPasskey({ externalUserId: externalUserId || null });
    }
    return client.login({
      mode: '1:N',
      nonce: nonce || null,
      presentation: 'modal',
    });
  }

  function showLogin512Problem(payload) {
    const code = String((payload && payload.code) || '');
    // Only problems the site owner must fix; scan results (blink, no match, ...) are already shown in the scan window.
    if (code !== 'ORIGIN_NOT_ALLOWED' && code !== 'ORIGIN_REQUIRED' && code !== 'BRIDGE_FAILED' && code !== 'CHALLENGE_FAILED') return;
    const lang = getLang();
    const key = `err_${code}`;
    let text = t(key, lang);
    if (text === key) text = (payload && payload.message) || code;
    text = text.split('{origin}').join(window.location.origin);
    let bar = document.getElementById('login512ProblemBar');
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'login512ProblemBar';
      bar.setAttribute('role', 'alert');
      bar.style.cssText = 'position:fixed;left:12px;right:12px;top:12px;z-index:2147483646;padding:12px 16px;border-radius:12px;'
        + 'background:#7f1d1d;color:#fff;font-size:14px;line-height:1.5;box-shadow:0 8px 24px rgba(0,0,0,.35);';
      document.body.appendChild(bar);
    }
    bar.textContent = '⚠️ ' + text;
  }

  function renderLangToggle(containerEl, currentLang, onChange) {
    if (!containerEl) return;
    containerEl.innerHTML = `
      <div class="lang-pill" role="group" aria-label="Language">
        <button type="button" data-lang="th" class="${currentLang === 'th' ? 'active' : ''}">TH</button>
        <button type="button" data-lang="en" class="${currentLang === 'en' ? 'active' : ''}">EN</button>
      </div>
    `;
    containerEl.querySelectorAll('button').forEach((btn) => {
      btn.addEventListener('click', () => {
        const next = btn.getAttribute('data-lang');
        setLang(next);
        onChange(next);
      });
    });
  }

  global.SC = {
    getLang,
    setLang,
    t,
    localizeError,
    escapeHtml,
    formatTime,
    formatDateTime,
    loadLogin512Sdk,
    apiJson,
    runBiometricAuth,
    renderLangToggle,
  };
})(window);
