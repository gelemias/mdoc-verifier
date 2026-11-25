// ════════════════════════════════════════════════════════════
// CBOR implementation (minimal, no deps)
// ════════════════════════════════════════════════════════════
const CBOR = (() => {
  function encode(val) {
    const parts = [];
    function w(v) { parts.push(v); }
    function encodeVal(v) {
      if (v === null || v === undefined) { w(new Uint8Array([0xf6])); return; }
      if (typeof v === 'boolean') { w(new Uint8Array([v ? 0xf5 : 0xf4])); return; }
      if (typeof v === 'number') {
        if (Number.isInteger(v) && v >= 0 && v <= 0xffffffff) {
          w(encodeUint(0, v));
        } else if (Number.isInteger(v) && v < 0) {
          w(encodeUint(1, -v - 1));
        } else {
          const buf = new ArrayBuffer(9); const dv = new DataView(buf);
          dv.setUint8(0, 0xfb); dv.setFloat64(1, v); w(new Uint8Array(buf));
        }
        return;
      }
      if (typeof v === 'bigint') {
        if (v >= 0n) w(encodeUint(0, Number(v)));
        else w(encodeUint(1, Number(-v - 1n)));
        return;
      }
      if (typeof v === 'string') {
        const bytes = new TextEncoder().encode(v);
        w(encodeUint(3, bytes.length)); w(bytes); return;
      }
      if (v instanceof Uint8Array) {
        w(encodeUint(2, v.length)); w(v); return;
      }
      if (Array.isArray(v)) {
        w(encodeUint(4, v.length));
        v.forEach(encodeVal); return;
      }
      if (v instanceof Map) {
        w(encodeUint(5, v.size));
        v.forEach((val, key) => { encodeVal(key); encodeVal(val); }); return;
      }
      if (typeof v === 'object') {
        const keys = Object.keys(v);
        w(encodeUint(5, keys.length));
        keys.forEach(k => { encodeVal(k); encodeVal(v[k]); }); return;
      }
    }
    function encodeUint(major, val) {
      const m = major << 5;
      if (val <= 23) return new Uint8Array([m | val]);
      if (val <= 0xff) return new Uint8Array([m | 24, val]);
      if (val <= 0xffff) { const b = new ArrayBuffer(3); const dv = new DataView(b); dv.setUint8(0, m | 25); dv.setUint16(1, val); return new Uint8Array(b); }
      if (val <= 0xffffffff) { const b = new ArrayBuffer(5); const dv = new DataView(b); dv.setUint8(0, m | 26); dv.setUint32(1, val); return new Uint8Array(b); }
      const b = new ArrayBuffer(9); const dv = new DataView(b); dv.setUint8(0, m | 27); dv.setBigUint64(1, BigInt(val)); return new Uint8Array(b);
    }
    encodeVal(val);
    const total = parts.reduce((a, b) => a + b.length, 0);
    const out = new Uint8Array(total); let off = 0;
    parts.forEach(p => { out.set(p, off); off += p.length; });
    return out;
  }

  function decode(buf) {
    const dv = new DataView(buf instanceof ArrayBuffer ? buf : buf.buffer, buf.byteOffset, buf.byteLength);
    let pos = 0;
    function read(depth = 0) {
      if (depth > 32) throw new Error('CBOR nesting exceeds the inspector limit.');
      const b = dv.getUint8(pos++);
      const major = b >> 5, add = b & 0x1f;
      if (major === 7) {
        if (add === 20) return false;
        if (add === 21) return true;
        if (add === 22) return null;
        if (add === 23) return undefined;
        if (add === 25) {
          const raw = dv.getUint16(pos);
          pos += 2;
          const sign = raw & 0x8000 ? -1 : 1;
          const exponent = (raw >> 10) & 31;
          const fraction = raw & 1023;
          if (exponent === 31) return fraction ? NaN : sign * Infinity;
          return sign * (exponent ? (1 + fraction / 1024) * 2 ** (exponent - 15) : fraction * 2 ** -24);
        }
        if (add === 26) { const value = dv.getFloat32(pos); pos += 4; return value; }
        if (add === 27) { const value = dv.getFloat64(pos); pos += 8; return value; }
        throw new Error('Unsupported CBOR simple value.');
      }
      let len;
      if (add <= 23) len = add;
      else if (add === 24) { len = dv.getUint8(pos++); }
      else if (add === 25) { len = dv.getUint16(pos); pos += 2; }
      else if (add === 26) { len = dv.getUint32(pos); pos += 4; }
      else if (add === 27) { len = Number(dv.getBigUint64(pos)); pos += 8; }
      else if (add === 31 && (major === 4 || major === 5)) len = Infinity;
      else throw new Error('Unsupported CBOR length.');

      if (major === 0) return len;
      if (major === 1) return -1 - len;
      if (major === 2 || major === 3) {
        if (len > dv.byteLength - pos) throw new Error('Truncated CBOR byte or text string.');
        const bytes = new Uint8Array(dv.buffer, dv.byteOffset + pos, len);
        pos += len;
        return major === 2 ? bytes : new TextDecoder('utf-8', {fatal: true}).decode(bytes);
      }
      if (major === 4) {
        if (len === Infinity) {
          const arr = [];
          while (true) { const b2 = dv.getUint8(pos); if (b2 === 0xff) { pos++; break; } arr.push(read(depth + 1)); } return arr;
        }
        const arr = []; for (let i = 0; i < len; i++) arr.push(read(depth + 1)); return arr;
      }
      if (major === 5) {
        if (len === Infinity) {
          const map = new Map();
          while (true) { const b2 = dv.getUint8(pos); if (b2 === 0xff) { pos++; break; } map.set(read(depth + 1), read(depth + 1)); } return map;
        }
        const map = new Map(); for (let i = 0; i < len; i++) map.set(read(depth + 1), read(depth + 1));
        return map;
      }
      if (major === 6) return { _tag: len, _val: read(depth + 1) };
      throw new Error('Unsupported CBOR value.');
    }
    const value = read();
    if (pos !== dv.byteLength) throw new Error('Unexpected trailing CBOR data.');
    return value;
  }

  return { encode, decode };
})();

// ════════════════════════════════════════════════════════════
// State
// ════════════════════════════════════════════════════════════
const state = {
  readerEngagementBytes: null,
  mdocUri: null,
  session: null,
  sessionStatusTimer: null,
  activeProtocol: 'mdoc',
  transportValue: null,
  digitalDebug: null,
  digitalAbort: null,
};

// ════════════════════════════════════════════════════════════
// Element definitions
// ════════════════════════════════════════════════════════════
const PHOTOID_ELEMENTS = ['portrait','family_name','given_name','birth_date','issue_date','expiry_date','issuing_country','document_number','age_over_18','age_in_years','age_birth_year'];
const MDL_ELEMENTS = ['family_name','given_name','birth_date','issuing_country','portrait','driving_privileges'];

// ════════════════════════════════════════════════════════════
// Init
// ════════════════════════════════════════════════════════════
function init() {
  const loopbackHosts = ['localhost', '127.0.0.1', '[::1]'];
  document.getElementById('endpoint-bar').hidden = !loopbackHosts.includes(window.location.hostname);

  buildCheckboxes('photoid-elements', PHOTOID_ELEMENTS, ['portrait','family_name','given_name','birth_date','age_over_18']);
  buildCheckboxes('mdl-elements', MDL_ELEMENTS, ['family_name','given_name','birth_date','issuing_country']);

  const actions = {
    clearCbor, clearLog, copyCurrentTransportValue, decodeCbor, downloadQR,
    encodeCborFromJson, generateRequest, launchDigitalRequest,
    loadCurrentRequest, openDeeplink, testEndpoint,
  };
  document.addEventListener('click', event => {
    const action = event.target.closest('[data-action]');
    if (action) actions[action.dataset.action]?.(event);
    const tab = event.target.closest('[data-tab]');
    if (tab) switchTab(tab.dataset.tab);
  });
  document.getElementById('include-mdl').addEventListener('change', updateClaimOptions);
  document.getElementById('doc-type').addEventListener('change', updateClaimOptions);
  document.getElementById('protocol-mode').addEventListener('change', updateProtocolModeUi);
  document.getElementById('endpoint-bar-url').addEventListener('input', () => {
    const status = document.getElementById('endpoint-status');
    status.textContent = '';
    status.style.color = 'var(--text3)';
  });
  updateProtocolModeUi();
}

function buildCheckboxes(containerId, elements, defaultChecked) {
  const container = document.getElementById(containerId);
  elements.forEach(el => {
    const div = document.createElement('label');
    div.className = 'checkbox-item' + (defaultChecked.includes(el) ? ' checked' : '');
    div.innerHTML = `<input type="checkbox" ${defaultChecked.includes(el) ? 'checked' : ''}><span>${el}</span>`;
    const cb = div.querySelector('input');
    cb.addEventListener('change', () => {
      div.classList.toggle('checked', cb.checked);
    });
    container.appendChild(div);
  });
}

function getCheckedElements(containerId) {
  const checks = document.querySelectorAll(`#${containerId} input[type=checkbox]`);
  const result = {};
  checks.forEach(c => { if (c.checked) result[c.nextElementSibling.textContent] = false; });
  return result;
}

function parseCustomAttributes(raw) {
  return Array.from(
    new Set(
      raw
        .split(/[,\n]/)
        .map(value => value.trim())
        .filter(Boolean)
    )
  );
}

// ════════════════════════════════════════════════════════════
// Nonce
// ════════════════════════════════════════════════════════════
function updateClaimOptions() {
  const docType = document.getElementById('doc-type').value;
  const isDigital = state.activeProtocol !== 'mdoc';
  const isMdl = docType === 'org.iso.18013.5.1.mDL';
  const includeMdl = document.getElementById('include-mdl');
  const mdlEnabled = isMdl || (!isDigital && includeMdl.checked);
  document.getElementById('photoid-options').hidden = isMdl;
  document.getElementById('mdl-options').hidden = isDigital && !isMdl;
  document.getElementById('include-mdl-label').hidden = isDigital || isMdl;
  document.getElementById('custom-mdl-attributes').disabled = !mdlEnabled;
  document.getElementById('custom-photoid-row').hidden = isMdl;
  document.getElementById('custom-mdl-row').hidden = !mdlEnabled;
  const mdl = document.getElementById('mdl-elements');
  mdl.hidden = !mdlEnabled;
  mdl.querySelectorAll('input').forEach(input => { input.disabled = !mdlEnabled; });
  document.getElementById('custom-doctype-row').style.display = docType === 'custom' ? 'block' : 'none';
}

function updateProtocolModeUi() {
  state.activeProtocol = document.getElementById('protocol-mode').value;
  const isDigital = state.activeProtocol !== 'mdoc';
  const docType = document.getElementById('doc-type');
  docType.querySelector('[value="custom"]').disabled = isDigital;
  if (isDigital && docType.value === 'custom') docType.selectedIndex = 0;
  document.getElementById('verifier-id-row').hidden = state.activeProtocol === 'openid4vp';
  document.getElementById('request-url-label').textContent = isDigital ? 'Response URL' : 'Wallet transfer URL';
  document.getElementById('transport-card-title').textContent = isDigital ? 'Digital Credentials API' : 'Wallet presentment';
  document.getElementById('generate-btn').textContent = {
    mdoc: 'Generate QR request',
    annex_c: 'Generate Annex C request',
    openid4vp: 'Generate OpenID4VP request',
  }[state.activeProtocol];
  document.getElementById('endpoint-bar-url').value = `${window.location.origin}/health`;
  document.getElementById('endpoint-status').textContent = '';
  document.getElementById('endpoint-status').style.color = 'var(--text3)';
  updateClaimOptions();
  resetTransportPanel(isDigital);
}

function resetTransportPanel(isDigital) {
  stopSessionPolling();
  state.digitalAbort?.abort();
  state.digitalAbort = null;
  state.session = null;
  state.transportValue = null;
  state.readerEngagementBytes = null;
  state.digitalDebug = null;
  state.mdocUri = null;
  document.getElementById('request-url').value = '';
  document.getElementById('qr-box').hidden = isDigital;
  document.getElementById('qr-container').hidden = isDigital;
  document.getElementById('dc-debug-card').hidden = !isDigital;
  document.getElementById('qr-box').innerHTML = '<p class="placeholder">Generate a request to show its QR code.</p>';
  document.getElementById('dc-launch-panel').hidden = true;
  document.getElementById('launch-dcapi-btn').disabled = false;
  document.getElementById('mdoc-uri-panel').style.display = 'none';
  document.getElementById('download-qr-btn').style.display = 'none';
  document.getElementById('copy-uri-btn').style.display = 'none';
  const deepLink = document.getElementById('open-deeplink');
  deepLink.style.display = isDigital ? 'none' : 'inline-flex';
  deepLink.removeAttribute('href');
  const copyLabel = isDigital ? 'Copy JSON' : 'Copy URI';
  document.getElementById('copy-uri-btn').textContent = copyLabel;
  document.getElementById('transport-value-label').textContent = isDigital ? 'Request JSON' : 'mdoc:// URI';
  document.getElementById('request-summary').textContent = 'No request generated yet.';
  updateSessionTable(null);
  setWalletResponseState('idle', 'Generate a request to receive a wallet response.');
  renderDigitalDebug();
}

function canUseDigitalCredentialsApi() {
  return window.isSecureContext && typeof window.DigitalCredential !== 'undefined'
    && typeof navigator.credentials?.get === 'function';
}

function allowsDigitalProtocol(protocol) {
  if (typeof window.DigitalCredential === 'undefined') return false;
  if (typeof window.DigitalCredential.userAgentAllowsProtocol !== 'function') return true;
  try {
    return window.DigitalCredential.userAgentAllowsProtocol(protocol);
  } catch (_err) {
    return false;
  }
}

function currentDigitalEnvironment() {
  const protocol = state.session?.request.requests[0].protocol;
  let protocolAllowed = null;
  let allowsError = null;
  if (protocol && typeof window.DigitalCredential?.userAgentAllowsProtocol === 'function') {
    try {
      protocolAllowed = window.DigitalCredential.userAgentAllowsProtocol(protocol);
    } catch (err) {
      allowsError = err && typeof err.message === 'string' ? err.message : String(err);
    }
  }
  return {
    timestamp: new Date().toISOString(),
    origin: window.location.origin,
    href: window.location.href,
    userAgent: navigator.userAgent,
    platform: navigator.platform || '',
    language: navigator.language || '',
    languages: navigator.languages || [],
    secureContext: window.isSecureContext,
    digitalCredentialPresent: typeof window.DigitalCredential !== 'undefined',
    credentialsGetPresent: typeof navigator.credentials?.get === 'function',
    userAgentAllowsProtocolPresent: typeof window.DigitalCredential?.userAgentAllowsProtocol === 'function',
    protocol,
    protocolAllowed,
    protocolCheckError: allowsError,
  };
}

function updateDigitalDebug(patch = {}, phase = null) {
  const existing = state.digitalDebug || {};
  state.digitalDebug = {
    ...existing,
    ...patch,
    environment: {
      ...(existing.environment || {}),
      ...currentDigitalEnvironment(),
      ...(patch.environment || {}),
    },
  };
  if (phase) {
    state.digitalDebug.phase = phase;
  }
  renderDigitalDebug();
}

function renderDigitalDebug() {
  const badge = document.getElementById('dc-debug-badge');
  const panel = document.getElementById('dc-debug-panel');
  const debug = state.digitalDebug;
  if (!debug) {
    badge.className = 'badge info';
    badge.textContent = 'idle';
    panel.innerHTML = `
      <div class="empty-state">
        <div class="icon">⌁</div>
        <p>Generate a request to see browser and protocol diagnostics.</p>
      </div>
    `;
    return;
  }

  const phase = debug.phase || 'captured';
  badge.className = debug.lastError ? 'badge err' : 'badge info';
  badge.textContent = phase;

  const sections = [
    ['Environment', debug.environment],
    ['Session', debug.session],
    ['Selected Claims', debug.selection],
    ['Request Payload', debug.requestPayload],
    ['Last DC API Result', debug.lastResult],
    ['Last Error', debug.lastError],
  ].filter(([, value]) => value && (!(typeof value === 'object') || Object.keys(value).length));

  panel.innerHTML = sections.map(([title, value]) => `
    <div class="gap-sm" style="margin-bottom:14px">
      <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">${escHtml(title)}</div>
      <div class="uri-display" style="max-height:220px;overflow:auto;white-space:pre-wrap">${escHtml(safeJsonStringify(value))}</div>
    </div>
  `).join('') || `
    <div class="empty-state">
      <div class="icon">⌁</div>
      <p>No Digital Credentials diagnostics captured yet</p>
    </div>
  `;
}

async function apiJson(response, fallback) {
  const result = await response.json();
  if (!response.ok) {
    throw new Error(typeof result.detail === 'string' ? result.detail : fallback);
  }
  return result;
}

function authorization(session) {
  return { Authorization: `Bearer ${session.access_token}` };
}

async function launchDigitalRequest() {
  const session = state.session;
  if (!session?.request || state.digitalAbort) return;
  if (session.expires_at * 1000 <= Date.now()) {
    setWalletResponseState('error', 'This request expired. Generate a new request.');
    return;
  }
  const protocol = session.request.requests[0].protocol;
  if (!canUseDigitalCredentialsApi() || !allowsDigitalProtocol(protocol)) {
    setWalletResponseState('error', `This browser cannot launch ${protocol}. Use a supported browser over HTTPS.`);
    return;
  }

  const launch = document.getElementById('launch-dcapi-btn');
  const controller = new AbortController();
  state.digitalAbort = controller;
  launch.disabled = true;
  setWalletResponseState('waiting', 'Waiting for the wallet.');
  try {
    const credential = await navigator.credentials.get({
      mediation: 'required',
      digital: session.request,
      signal: controller.signal,
    });
    if (state.session !== session) return;
    if (credential?.protocol !== protocol || typeof credential.data?.response !== 'string') {
      throw new Error('The wallet returned an unexpected Digital Credentials response.');
    }
    setWalletResponseState('waiting', 'Verifying the wallet response.');
    const response = await fetch(`/dc/response/${session.session_id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authorization(session) },
      body: JSON.stringify({protocol: credential.protocol, data: {response: credential.data.response}}),
      signal: controller.signal,
    });
    const data = await apiJson(response, 'The verifier rejected the wallet response.');
    if (state.session !== session) return;
    const phase = data.validation?.issuer_auth === 'verified' ? 'verified' : 'inspected';
    updateDigitalDebug({lastError: null, lastResult: data.validation}, phase);
    showWalletResponse(data);
    document.getElementById('dc-launch-panel').hidden = true;
  } catch (error) {
    if (state.session !== session) return;
    setWalletResponseState('error', error.message || 'Wallet presentation was interrupted.');
    updateDigitalDebug({lastError: {name: error.name, message: error.message}}, 'error');
  } finally {
    if (state.session === session) {
      state.digitalAbort = null;
      launch.disabled = false;
    }
  }
}

async function generateRequest() {
  const button = document.getElementById('generate-btn');
  if (button.disabled) return;
  const protocolMode = document.getElementById('protocol-mode');
  const isDigital = state.activeProtocol !== 'mdoc';
  const isOpenId4Vp = state.activeProtocol === 'openid4vp';
  const originalLabel = button.textContent;
  const selectedType = document.getElementById('doc-type').value;
  const docType = selectedType === 'custom' ? document.getElementById('custom-doc-type').value.trim() : selectedType;
  const mdlSelected = docType === 'org.iso.18013.5.1.mDL';
  const includeMdl = !isDigital && document.getElementById('include-mdl').checked && !mdlSelected;
  const field = id => document.getElementById(id).value.trim();
  const config = {
    doc_type: docType,
    verifier_id: field('verifier-id'),
    include_mdl: includeMdl,
    photoid_elements: mdlSelected ? [] : Object.keys(getCheckedElements('photoid-elements')),
    mdl_elements: mdlSelected || includeMdl ? Object.keys(getCheckedElements('mdl-elements')) : [],
    custom_photoid_attributes: mdlSelected ? [] : parseCustomAttributes(field('custom-photoid-attributes')),
    custom_mdl_attributes: mdlSelected || includeMdl ? parseCustomAttributes(field('custom-mdl-attributes')) : [],
    custom_namespace: field('custom-namespace'),
    custom_namespace_attributes: parseCustomAttributes(field('custom-namespace-attributes')),
  };
  const requestedNamespaces = [
    {name: 'org.iso.23220.1', elements: [...config.photoid_elements, ...config.custom_photoid_attributes]},
    {name: 'org.iso.18013.5.1', elements: [...config.mdl_elements, ...config.custom_mdl_attributes]},
    {name: config.custom_namespace, elements: config.custom_namespace_attributes},
  ].filter(namespace => namespace.name && namespace.elements.length);

  button.disabled = true;
  protocolMode.disabled = true;
  button.textContent = 'Generating…';
  resetTransportPanel(isDigital);
  setStatus('Generating', 'var(--amber)');
  try {
    if (!docType || !requestedNamespaces.length) throw new Error('Choose a document type and at least one claim.');
    const response = await fetch(isDigital ? '/dc/session' : '/mdoc/session', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(isOpenId4Vp ? {...config, protocol: 'openid4vp-v1-unsigned'} : config),
    });
    const session = await apiJson(response, 'Could not create a verifier session.');
    state.session = session;
    const endpoint = isDigital ? session.response_url : session.request_url;
    switchTab('qr');
    document.getElementById('request-url').value = endpoint;

    const notes = [];
    if (session.issuer_inspection_mode) {
      notes.push('Test mode is active. Shared attributes will be labeled as unverified.');
    } else if (!session.issuer_trust_configured) {
      notes.push('Issuer trust is not configured. Obtain the issuer CA before verifying a response.');
    }
    if (isDigital) {
      const data = session.request.requests[0].data;
      if (!isOpenId4Vp) state.readerEngagementBytes = base64UrlToBytes(data.deviceRequest);
      state.transportValue = JSON.stringify(session.request, null, 2);
      document.getElementById('qr-container').hidden = false;
      document.getElementById('dc-launch-panel').hidden = false;
      if (isOpenId4Vp) {
        notes.push('OpenID4VP uses an unsigned request with an encrypted response. Use a wallet that accepts this profile.');
      } else if (!session.signed_request) {
        notes.push('Unsigned request. Wallets that require reader authentication need a configured reader certificate.');
      }
      updateDigitalDebug({
        session: {expiresAt: session.expires_at, signedRequest: session.signed_request},
        lastResult: {stage: 'session_created'},
      }, 'ready');
      setWalletResponseState('waiting', 'Open the wallet to present a credential.');
    } else {
      state.readerEngagementBytes = Uint8Array.from(session.reader_engagement_hex.match(/.{2}/g), hex => parseInt(hex, 16));
      state.mdocUri = session.mdoc_uri;
      state.transportValue = state.mdocUri;
      renderQR(state.mdocUri);
      document.getElementById('open-deeplink').href = state.mdocUri;
      document.getElementById('download-qr-btn').style.display = 'inline-flex';
      setWalletResponseState('waiting', 'Scan the QR code or open it in a wallet on this device.');
      pollQrSession(session);
    }

    document.getElementById('uri-display').textContent = state.transportValue;
    document.getElementById('mdoc-uri-panel').style.display = 'block';
    document.getElementById('copy-uri-btn').style.display = 'inline-flex';
    renderRequestSummary({
      docType, requestUrl: endpoint, verifierId: isOpenId4Vp ? null : config.verifier_id, requestedNamespaces,
      size: state.readerEngagementBytes?.length ?? new TextEncoder().encode(state.transportValue).length,
      sizeLabel: isOpenId4Vp ? 'OpenID4VP request JSON' : isDigital ? 'DeviceRequest' : 'ReaderEngagement',
      isDigital, expiresAt: session.expires_at, notes,
    });
    updateSessionTable({docType, endpoint, 'session id': session.session_id,
      ...(isDigital ? {'request nonce': session.request_nonce ?? session.request_nonce_hex} : {})});
    setStatus('Request ready', 'var(--green)');
    if (matchMedia('(max-width: 820px)').matches) {
      document.getElementById('presentment-card').scrollIntoView({block: 'start'});
    }
  } catch (error) {
    setStatus('Error', 'var(--red)');
    setWalletResponseState('error', error.message);
    log('err', error.message);
    switchTab('qr');
  } finally {
    button.textContent = originalLabel;
    button.disabled = false;
    protocolMode.disabled = false;
  }
}

// QR code
function renderQR(uri) {
  const box = document.getElementById('qr-box');
  box.innerHTML = '';
  const size = Math.min(280, Math.max(180, box.parentElement.offsetWidth - 52));
  new QRCode(box, {
    text: uri,
    width: size,
    height: size,
    colorDark: '#000000',
    colorLight: '#ffffff',
    correctLevel: QRCode.CorrectLevel.M,
  });
}

function downloadQR() {
  const canvas = document.querySelector('#qr-box canvas');
  if (!canvas) return;
  const a = document.createElement('a');
  a.download = 'mdoc-request-qr.png';
  a.href = canvas.toDataURL('image/png');
  a.click();
}

function openDeeplink(e) {
  if (!state.mdocUri) { e.preventDefault(); return; }
}

// ════════════════════════════════════════════════════════════
// Request summary renderer
// ════════════════════════════════════════════════════════════
function renderRequestSummary({docType, requestUrl, verifierId, requestedNamespaces, size, sizeLabel, isDigital, expiresAt, notes}) {
  document.getElementById('request-summary').innerHTML = `
    <table class="field-table">
      <tr><td>Document type</td><td>${escHtml(docType)}</td></tr>
      <tr><td>${isDigital ? 'Response URL' : 'Transfer URL'}</td><td>${escHtml(requestUrl)}</td></tr>
      ${verifierId === null ? '' : `<tr><td>Verifier ID</td><td>${escHtml(verifierId)}</td></tr>`}
      ${requestedNamespaces.map(({name, elements}) => `
        <tr><td>${escHtml(name)}</td><td>${elements.map(element => `<span class="badge info">${escHtml(element)}</span>`).join(' ')}</td></tr>
      `).join('')}
      <tr><td>${sizeLabel}</td><td>${size} bytes</td></tr>
      <tr><td>Expires</td><td>${escHtml(new Date(expiresAt * 1000).toLocaleTimeString())}</td></tr>
    </table>
    ${notes.map(note => `<p class="request-note">${escHtml(note)}</p>`).join('')}`;
}

// ════════════════════════════════════════════════════════════
// CBOR Inspector
// ════════════════════════════════════════════════════════════
function loadCurrentRequest() {
  if (!state.readerEngagementBytes) {
    log('warn', state.transportValue ? 'This request uses JSON. View it in Presentment.' : 'No request generated yet');
    return;
  }
  const hex = Array.from(state.readerEngagementBytes).map(b => b.toString(16).padStart(2,'0')).join('');
  document.getElementById('cbor-input').value = hex;
  decodeCbor();
  switchTab('cbor');
}

function clearCbor() {
  document.getElementById('cbor-input').value = '';
  document.getElementById('cbor-tree').innerHTML = '<span style="color:var(--text3)">—</span>';
  document.getElementById('cbor-json-out').value = '';
  document.getElementById('hex-dump-output').textContent = '—';
}

function parseInputBytes(raw) {
  raw = raw.trim().replace(/\s+/g,'');
  // Try hex first
  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0) {
    return Uint8Array.from(raw.match(/.{2}/g).map(h => parseInt(h, 16)));
  }
  // Try base64 / base64url
  try {
    const b64 = raw.replace(/-/g,'+').replace(/_/g,'/');
    const bin = atob(b64);
    return Uint8Array.from(bin.split('').map(c => c.charCodeAt(0)));
  } catch(e) {}
  throw new Error('Cannot parse input as hex or base64');
}

function decodeCbor() {
  const raw = document.getElementById('cbor-input').value;
  if (!raw.trim()) return;
  try {
    if (raw.length > 256 * 1024) throw new Error('CBOR input exceeds the inspector limit.');
    const bytes = parseInputBytes(raw);
    const decoded = CBOR.decode(bytes);
    document.getElementById('cbor-tree').innerHTML = renderCborTree(decoded);
    document.getElementById('cbor-json-out').value = JSON.stringify(cborToJson(decoded), null, 2);
    document.getElementById('hex-dump-output').textContent = hexDump(bytes);
    log('ok', `CBOR decoded: ${bytes.length} bytes`);
  } catch(e) {
    log('err', `CBOR decode error: ${e.message}`);
    document.getElementById('cbor-tree').innerHTML = `<span style="color:var(--red)">${escHtml(e.message)}</span>`;
  }
}

function encodeCborFromJson() {
  const json = document.getElementById('cbor-json-out').value;
  try {
    const obj = JSON.parse(json);
    const bytes = CBOR.encode(obj);
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
    document.getElementById('cbor-input').value = hex;
    document.getElementById('hex-dump-output').textContent = hexDump(bytes);
    log('ok', `JSON encoded to CBOR: ${bytes.length} bytes`);
  } catch(e) {
    log('err', `Encode error: ${e.message}`);
  }
}

function renderCborTree(val, indent = 0) {
  const pad = indent > 0 ? `<div class="cbor-indent">` : '';
  const close = indent > 0 ? `</div>` : '';
  if (val === null) return `<span class="cbor-bool">null</span>`;
  if (val === undefined) return `<span class="cbor-bool">undefined</span>`;
  if (typeof val === 'boolean') return `<span class="cbor-bool">${val}</span>`;
  if (typeof val === 'number') return `<span class="cbor-num">${val}</span>`;
  if (typeof val === 'bigint') return `<span class="cbor-num">${val}n</span>`;
  if (typeof val === 'string') return `<span class="cbor-str">"${escHtml(val)}"</span>`;
  if (val instanceof Uint8Array) {
    const hex = Array.from(val).map(b=>b.toString(16).padStart(2,'0')).join('');
    const preview = hex.length > 32 ? hex.slice(0,32)+'…' : hex;
    return `<span class="cbor-bytes">h'${preview}' <span class="cbor-tag">(${val.length}B)</span></span>`;
  }
  if (val && '_tag' in val) {
    return `<span class="cbor-tag">tag(${val._tag})</span> ${renderCborTree(val._val, indent)}`;
  }
  if (Array.isArray(val)) {
    if (val.length === 0) return '[]';
    return `[${pad}${val.map((v,i) => renderCborTree(v, indent+1)).join('<br>')}${close}]`;
  }
  if (val instanceof Map) {
    if (val.size === 0) return '{}';
    let rows = '';
    val.forEach((v, k) => {
      rows += `<span class="cbor-key">${typeof k === 'string' ? `"${escHtml(k)}"` : escHtml(String(k))}</span>: ${renderCborTree(v, indent+1)}<br>`;
    });
    return `{${pad}${rows}${close}}`;
  }
  if (typeof val === 'object') {
    const keys = Object.keys(val);
    if (!keys.length) return '{}';
    let rows = '';
    keys.forEach(k => {
      rows += `<span class="cbor-key">"${escHtml(k)}"</span>: ${renderCborTree(val[k], indent+1)}<br>`;
    });
    return `{${pad}${rows}${close}}`;
  }
  return escHtml(String(val));
}

function cborToJson(val) {
  if (val === null || val === undefined || typeof val === 'boolean' || typeof val === 'number' || typeof val === 'string') return val;
  if (typeof val === 'bigint') return Number(val);
  if (val instanceof Uint8Array) return Array.from(val).map(b=>b.toString(16).padStart(2,'0')).join('');
  if (val && '_tag' in val) return { '__cbor_tag': val._tag, value: cborToJson(val._val) };
  if (Array.isArray(val)) return val.map(cborToJson);
  if (val instanceof Map) {
    const out = {};
    val.forEach((v, k) => { out[typeof k === 'number' ? k : String(k)] = cborToJson(v); });
    return out;
  }
  if (typeof val === 'object') {
    const out = {};
    Object.keys(val).forEach(k => { out[k] = cborToJson(val[k]); });
    return out;
  }
  return val;
}

function hexDump(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i+16);
    const addr = i.toString(16).padStart(8,'0');
    const hex = Array.from(chunk).map(b=>b.toString(16).padStart(2,'0')).join(' ').padEnd(47);
    const ascii = Array.from(chunk).map(b => b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.').join('');
    out += `${addr}  ${hex}  ${ascii}\n`;
  }
  return out;
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function safeJsonStringify(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch (_err) {
    return String(value);
  }
}

function hexToBase64(hex) {
  const pairs = hex.match(/.{1,2}/g) || [];
  let binary = '';
  pairs.forEach(pair => {
    binary += String.fromCharCode(parseInt(pair, 16));
  });
  return btoa(binary);
}

function base64UrlToBytes(raw) {
  const b64 = raw.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
  const bin = atob(padded);
  return Uint8Array.from(bin.split('').map(c => c.charCodeAt(0)));
}

function detectImageMimeFromHex(hex) {
  const normalized = (hex || '').toLowerCase();
  if (normalized.startsWith('89504e470d0a1a0a')) return 'image/png';
  if (normalized.startsWith('ffd8ff')) return 'image/jpeg';
  if (normalized.startsWith('47494638')) return 'image/gif';
  if (normalized.startsWith('52494646') && normalized.slice(16, 24) === '57454250') return 'image/webp';
  return null;
}

function renderSharedAttributeValue(name, value) {
  if (value && typeof value === 'object' && value.type === 'bytes' && typeof value.hex === 'string') {
    const mime = detectImageMimeFromHex(value.hex);
    const looksLikePortrait = /portrait|image|photo/i.test(name);
    if (mime && looksLikePortrait) {
      const src = `data:${mime};base64,${hexToBase64(value.hex)}`;
      return `
        <div style="display:flex;flex-direction:column;gap:8px">
          <img src="${src}" alt="${escHtml(name)}" style="max-width:180px;max-height:220px;border-radius:10px;border:1px solid var(--border);background:var(--bg2);object-fit:contain">
        </div>
      `;
    }
  }
  return `<div style="font-family:var(--mono);font-size:11px;word-break:break-word">${escHtml(JSON.stringify(value))}</div>`;
}

function renderSharedAttributes(sharedAttributes) {
  const namespaces = Object.entries(sharedAttributes || {}).filter(([, values]) => Object.keys(values || {}).length);
  if (!namespaces.length) return '';

  return `
    <div class="gap-sm">
      <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">Shared attributes</div>
      <table class="field-table">
        ${namespaces.map(([namespace, values]) => `
          <tr><td colspan="2"><code style="font-family:var(--mono);font-size:11px">${escHtml(namespace)}</code></td></tr>
          ${Object.entries(values).map(([name, value]) => `
            <tr>
              <td>${escHtml(name)}</td>
              <td>${renderSharedAttributeValue(name, value)}</td>
            </tr>
          `).join('')}
        `).join('')}
      </table>
    </div>
  `;
}

function showWalletResponse(data) {
  const attributes = renderSharedAttributes(data.shared_attributes);
  if (data.validation?.issuer_auth !== 'verified') {
    setStatus('Unverified issuer', 'var(--amber)');
    setWalletResponseState('unverified', 'Test inspection only. Use these attributes for debugging.', attributes);
    return;
  }
  setStatus('Verified', 'var(--green)');
  setWalletResponseState('done', 'Issuer and device authentication passed.', attributes);
}

function setWalletResponseState(kind, message, extraHtml='') {
  const badge = document.getElementById('wallet-response-badge');
  const panel = document.getElementById('wallet-response-panel');
  const styles = {
    idle: ['badge info', 'idle'],
    waiting: ['badge warn', 'waiting'],
    connected: ['badge info', 'wallet connected'],
    received: ['badge ok', 'response received'],
    done: ['badge ok', 'verified'],
    unverified: ['badge warn', 'unverified issuer'],
    error: ['badge err', 'error'],
  };
  const [cls, label] = styles[kind] || styles.idle;
  badge.className = cls;
  badge.textContent = label;
  panel.innerHTML = `
    <div class="gap-sm">
      <div style="font-size:13px;color:var(--text)">${escHtml(message)}</div>
      ${extraHtml}
    </div>
  `;
}

function stopSessionPolling() {
  clearTimeout(state.sessionStatusTimer);
  state.sessionStatusTimer = null;
}

async function pollQrSession(session) {
  if (state.session !== session) return;
  try {
    const response = await fetch(`/mdoc/session/${session.session_id}`, {
      headers: authorization(session),
      signal: AbortSignal.timeout(8000),
    });
    if (state.session !== session) return;
    if (response.status === 404) {
      setWalletResponseState('error', 'This request expired. Generate a new request.');
      return;
    }
    const data = await apiJson(response, 'Could not fetch the wallet session.');
    if (state.session !== session) return;
    if (data.response_received) {
      showWalletResponse(data);
      return;
    }
    if (data.last_error) {
      setWalletResponseState('error', data.last_error);
      return;
    }
    if (data.stage === 1) {
      setWalletResponseState('connected', 'Wallet connected. Waiting for its response.');
    }
  } catch (error) {
    if (state.session !== session) return;
    setWalletResponseState('waiting', 'Connection interrupted. Retrying.');
  }
  state.sessionStatusTimer = setTimeout(() => pollQrSession(session), 2000);
}

async function testEndpoint() {
  const url = document.getElementById('endpoint-bar-url').value.trim();
  if (!url) return;
  const statusEl = document.getElementById('endpoint-status');
  const btn = document.getElementById('test-endpoint-btn');
  btn.textContent = 'Testing…'; btn.disabled = true;
  statusEl.textContent = '…'; statusEl.style.color = 'var(--text3)';
  log('info', `GET ${url}`);
  try {
    const res = await fetch(url, { method: 'GET', mode: 'cors', credentials: 'omit', signal: AbortSignal.timeout(5000) });
    const label = `${res.status} ${res.statusText || 'OK'}`;
    const ok = res.status < 400;
    statusEl.textContent = label;
    statusEl.style.color = ok ? 'var(--green)' : 'var(--amber)';
    log(ok ? 'ok' : 'warn', `Endpoint responded: ${label}`);
  } catch(e) {
    const msg = e.name === 'AbortError' ? 'timeout' : e.message.includes('NetworkError') || e.message.includes('Failed to fetch') ? 'unreachable / CORS' : e.message;
    statusEl.textContent = msg;
    statusEl.style.color = 'var(--red)';
    log('err', `Endpoint test failed: ${msg}`);
  }
  btn.textContent = 'Test endpoint'; btn.disabled = false;
}

// ════════════════════════════════════════════════════════════
// URI copy
// ════════════════════════════════════════════════════════════
async function copyCurrentTransportValue() {
  if (!state.transportValue) return;
  try {
    await navigator.clipboard.writeText(state.transportValue);
    log('ok', state.activeProtocol === 'mdoc' ? 'URI copied' : 'Request JSON copied');
  } catch {
    log('warn', 'Clipboard access failed. Select the request text to copy it manually.');
  }
}

// ════════════════════════════════════════════════════════════
// Tabs
// ════════════════════════════════════════════════════════════
function switchTab(name) {
  document.querySelectorAll('[data-tab]').forEach(tab => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-pressed', active);
  });
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
}

// ════════════════════════════════════════════════════════════
// Log
// ════════════════════════════════════════════════════════════
function log(level, msg) {
  const panel = document.getElementById('log-panel');
  const ts = new Date().toISOString().slice(11,23);
  const line = document.createElement('div');
  line.className = `log-line ${level}`;
  line.innerHTML = `<span class="ts">${ts}</span><span class="msg">${escHtml(msg)}</span>`;
  panel.appendChild(line);
  panel.scrollTop = panel.scrollHeight;
}

function clearLog() { document.getElementById('log-panel').innerHTML = ''; }

// ════════════════════════════════════════════════════════════
// Session table
// ════════════════════════════════════════════════════════════
function updateSessionTable(data) {
  const tbody = document.getElementById('session-tbody');
  if (!data) { tbody.innerHTML = '<tr><td colspan="2" style="color:var(--text3)">No session yet</td></tr>'; return; }
  tbody.innerHTML = Object.entries(data).map(([k,v]) =>
    `<tr><td>${escHtml(k)}</td><td style="font-family:var(--mono);font-size:11px;word-break:break-all">${escHtml(String(v))}</td></tr>`
  ).join('');
}

// ════════════════════════════════════════════════════════════
// Status indicator
// ════════════════════════════════════════════════════════════
function setStatus(label, color) {
  document.getElementById('status-label').textContent = label;
  document.getElementById('status-dot').style.background = color;
  document.getElementById('status-dot').style.boxShadow = `0 0 6px ${color}`;
}

// ════════════════════════════════════════════════════════════
// Boot
// ════════════════════════════════════════════════════════════
init();
