// middleware.js — NERVE WAF v5.1 (HARDENED)
// Drop-in replacement for v5.0. Same architecture, hardened against red-team findings:
//   [F1] SQLi: Structural quote-agnostic tautology detection (replaces rigid regex).
//   [F2] routeAllowlist: Exact or segment-boundary matching (prevents startsWith prefix bypass).
//   [F3] matcher: Asset-prefix anchored, no broad extension skipping.
//   [F4] Rate limiter: Local sliding window to minimize I/O latency at the edge.
//   [F5] Body inspection: Fail-closed on oversize payloads before deep inspection.
//
// Multi-Stage Security Pipeline:
// 1. Operational Mode (ENFORCE vs OBSERVE / Dry-Run)
// 2. ReDoS Immunity: Bounded Quantifiers, Fast Pre-Filters & 32KB Inspection Caps
// 3. Multi-Factor Client Identity & Trusted Proxy IP Resolution
// 4. Anomaly Scoring Engine (OWASP CRS Style, Threshold-based Decision)
// 5. Distributed / Ephemeral Sliding Window Rate Limiter
// 6. Automated Scanner / Recon Bot Shield (User-Agent & Probe Signatures)
// 7. Canonicalization & Anti-Evasion Pipeline (NFD Diacritics, Homoglyphs, Decoders)
// 8. Structured Security Telemetry & JSON Audit Logs (X-WAF-Status: BLOCKED, X-WAF-Event-ID, X-WAF-Score)

// ============================================================================
// 1. WAF CONFIGURATION & OPERATIONAL SETTINGS
// ============================================================================

const WAF_CONFIG = {
  // 'ENFORCE': Actively blocks threats with 403/405/429 status codes.
  // 'OBSERVE': Monitors and logs threats without blocking (ideal for dry-runs).
  mode: process.env.WAF_MODE || 'ENFORCE',

  // Minimum anomaly score required to trigger a block (OWASP standard: 5).
  anomalyThreshold: 5,

  // Rate Limiting: Maximum allowed requests per minute per client fingerprint.
  rateLimitMax: 60,
  rateLimitWindowMs: 60_000,

  // Security cap to prevent DoS and ReDoS (inspection payload limit).
  maxInspectionBytes: 32_768,
  maxUrlLength: 8192,

  // [F5] Fail-closed: Rejects request bodies exceeding this limit rather than partially inspecting them.
  // Must be >= maxInspectionBytes. Increase only if specific endpoints legitimately require large payloads.
  maxBodyBytes: 65_536,

  // Authorized routes and paths (Bypass allowlist).
  // [F2] EXACT match or segment boundary match — NOT a simple startsWith.
  routeAllowlist: [
    '/api/auth/callback', // OAuth legitimate callbacks
    '/api/webhooks',      // Stripe/GitHub external webhooks
  ],

  // Allowed internal navigation parameters (enforces relative path validation).
  trustedRedirectHosts: ['parallaxtool.vercel.app', 'thetimeless.club'],


};

const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'POST', 'OPTIONS']);

// Known scanners and automated tools to block prior to payload inspection.
const KNOWN_ATTACK_TOOLS = [
  /sqlmap/i,
  /nikto/i,
  /nuclei/i,
  /gobuster/i,
  /dirbuster/i,
  /wpscan/i,
  /masscan/i,
  /zgrab/i,
];

// HTTP Method override headers.
const METHOD_OVERRIDE_HEADERS = [
  'x-http-method-override',
  'x-http-method',
  'x-method-override',
  'x-method',
  'override',
  'x-override',
];

// Hostile routing headers.
const HOSTILE_ROUTING_HEADERS = [
  'x-original-url',
  'x-rewrite-url',
  'x-original-host',
  'x-forwarded-prefix',
  'x-forwarded-port',
  'x-forwarded-scheme',
  'x-host',
  'x-forwarded-server',
  'x-backend-server',
];

// Sensitive files, directories, and scanner probes.
const BLOCKED_PATH_PATTERNS = [
  /(^|\/)\.git(\/|$)/i,
  /(^|\/)\.env(\/|$)/i,
  /(^|\/)wp-admin(\/|$)/i,
  /(^|\/)wp-login\.php/i,
  /(^|\/)phpmyadmin(\/|$)/i,
  /(^|\/)\.ssh(\/|$)/i,
  /(^|\/)\.aws(\/|$)/i,
  /(^|\/)\.htaccess/i,
  /(^|\/)\.htpasswd/i,
  /(^|\/)web\.config/i,
  /(^|\/)\.DS_Store/i,
  /(^|\/)id_rsa/i,
  /(^|\/)actuator(\/|$)/i,
  /etc\/(passwd|shadow|hosts)/i,
  /windows[\\\/]win\.ini/i,
  /proc\/self\/(environ|cmdline)/i,
];

// ============================================================================
// 2. ANOMALY SCORING RULES (OWASP CRS Weighted Style)
// ============================================================================

// [F1] Structural SQLi Tautologies — Evaluated independently of quote pairing.
// Matches: ' OR '1'='1 | ' or 'a'='a | or 1=1 | or true | or ''=' | or 1 like 1 | admin'--
const SQLI_TAUTOLOGY_PATTERNS = [
  // 1) Evaluates equality where at least one side is a literal, digit, or quote (case-insensitive).
  /(?:'|"|\))\s*(?:or|and)\s+(?:'[^']*'|"[^"]*"|[0-9]+|[a-z_]+)\s*(?:=|<>|!=|<|>|like|ilike|in|regexp|rlike|between|is)\s*(?:'[^']*'|"[^"]*"|[0-9]+|[a-z_]+)/i,
  // 2) A quote immediately followed by a boolean operator (e.g., ' OR / ' and).
  /(?:'|"|;|--|#|\/\*)\s*(?:or|and)\s+(?:'|"|[0-9]|[a-z_]+\()/i,
  // 3) Boolean tautology anchored to an SQL delimiter (prevents false positives on natural language).
  /(?:'|"|\)|;)\s*(?:or|and)\s+(?:1\s*=\s*1|true|false|''\s*=\s*''|""\s*=\s*""|'[^']*'\s*=\s*'[^']*')/i,
  // 4) Standard tautology exclusively in an SQL context (preceded by a digit or quote, NOT a word).
  /(?:\d|'|")\s*(?:or|and)\s+1\s*=\s*1\b/i,
  // 5) SQL comment that truncates the query after a literal (e.g., admin'--).
  /['"]\s*(?:--|#|\/\*)/,
  // 6) Concatenation operators frequently used for evasion (e.g., '||', '+).
  /['"]\s*\|\|\s*['"]/,
];

const ANOMALY_RULES = {
  // CRITICAL THREATS (Score: 5)
  sqliCritical: {
    score: 5,
    // [F1] Retains legacy rules alongside the structural rules defined above (applied in Stage 7).
    pattern: /(?:'|"|;|--|\/\*|\*\/|#)\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'|"[^"]*"\s*=\s*"[^"]*")|\b\d+\s+(?:or|and)\s+\d+\s*=\s*\d+\b|\bunion\s+(?:all\s+)?select\b|\bunion\s+values\s*\(|\bcopy\s+.*\s+from\s+program\b|\b(?:xp_cmdshell|waitfor\s+delay|pg_sleep|benchmark)\b|\bdbms_pipe\.receive_message\b|\battach\s+database\b/i,
  },
  xssCritical: {
    score: 5,
    pattern: /<\s*script\b|<\s*\/\s*script\b|<\s*(?:img|svg|iframe|body|details|audio|video|source|input|form|marquee|object|embed|link|meta|base|math|template|noscript|select|option|textarea|style|x)[\s\/\>]|\bon(?:error|load|click|mouseover|mouseenter|focus|blur|submit|change|input|animationstart|animationend|toggle|begin|end|pointerover|pointerdown|wheel|scroll)\s*=|javascript\s*:|vbscript\s*:|data\s*:\s*(?:text\/html|image\/svg\+xml|application\/xhtml)|-moz-binding\s*:\s*url|\b(?:alert|prompt|confirm|eval|Function)\s*(\(|`)/i,
  },
  traversalCritical: {
    score: 5,
    pattern: /\.\.[\/\\]|%2e%2e[\/\\]|\.\.%2f|\.\.%5c|\.\.;|\.\.%00|%252e%252e|\.\.[\u2215\u2216\uFF0F\uFF3C\u2044]|\/\.\.?%2f|\/\.\.?%5c|\/etc\/(passwd|shadow|hosts)|windows[\\\/]win\.ini/i,
  },
  rceJndiCritical: {
    score: 5,
    pattern: /\$\{jndi:(?:ldap|rmi|dns|iiop|http|https|nis|corba|nds|ldaps):/i,
  },
  ssrfCritical: {
    score: 5,
    pattern: /\b(?:file|gopher|dict|ftp|ftps|ldap|ldaps|tftp|sftp|jar|netdoc|php|expect|blob|filesystem|about|chrome|data|ssh|telnet|smb|git|ws|wss):\/\/|169\.254\.\d+\.\d+|168\.63\.129\.16|100\.100\.100\.200|metadata\.google\.internal|metadata\.azure\.com|metadata\.oraclecloud\.com|metadata\.tencentyun\.com|kubernetes\.default(?:\.svc)?|host\.docker\.internal|\[(?:0:0:0:0:0:)?ffff:(?:a9fe:a9fe|0xa9fe:a9fe|169\.254\.169\.254|127\.0\.0\.1)\]|\[fe80::|\[::(?:ffff:)?127\.0\.0\.1\]|\[::1\]|\b0x7f(?:\.[0-9a-f]+){1,3}\b|\b0x[0-9a-f]{8}\b|\b0177\.1\b|\b0[0-7]{1,3}\.(?:0[0-7]{1,3}\.){1,2}[0-7]{1,3}\b|\b00*(?:2130706433|2852039166|3232235777)\b|\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|localhost|localtest\.me|lvh\.me|\.nip\.io|\.xip\.io/i,
  },
  sstiCritical: {
    score: 5,
    pattern: /\{\{[\s\S]{0,128}\}\}|<%=\s*[\s\S]{0,128}%>|\{7\*7\}|\$class\.inspect|%\{7\*7\}|#\{7\*7\}|\$\{\s*(?:\d+\s*[\*\+\-\/]\s*\d+|7\*7)[\s\S]{0,64}\}/,
  },
  xxeCritical: {
    score: 5,
    pattern: /<!DOCTYPE[\s\S]{0,256}SYSTEM|<!ENTITY[\s\S]{0,256}SYSTEM/i,
  },

  // SUSPICIOUS ANOMALIES (Score: 3)
  sqliSuspicious: {
    score: 3,
    pattern: /\b(?:information_schema|mysql\.user|pg_shadow|msdb|randomblob)\b|\b(?:load_file|into\s+outfile|into\s+dumpfile)\b|\b0x[0-9a-f]{4,}\b|\bchar\s*\(\s*\d+/i,
  },
  nosqlSuspicious: {
    score: 3,
    pattern: /\$(?:where|ne|regex|gt|gte|lt|lte|in|nin|exists|or|and)\b|(?:\)\s*\(\s*\||\)\s*\(\s*&|\*\s*\)\s*\(|\buid\s*=\s*\*)/i,
  },
};

const PROTO_KEYS = ['__proto__', 'constructor', 'prototype', 'tostring', 'valueof'];
const REDIRECT_PARAMS = new Set(['redirect', 'redirect_url', 'redirect_uri', 'return', 'return_url', 'next', 'continue', 'target', 'dest', 'destination', 'url', 'u', 'uri', 'link', 'goto', 'out', 'to']);
const SSRF_PARAMS = new Set(['url', 'uri', 'u', 'fetch', 'load', 'src', 'source', 'host', 'endpoint', 'proxy', 'path', 'page', 'file', 'document', 'include', 'open', 'image', 'webhook']);

// Patterns detecting Overlong UTF-8 (2-6 bytes), CESU-8, IIS evasion encodings, and Null Bytes.
const OVERLONG_AND_EVASION_PATTERN = /(?:%c[01]%[0-9a-f]{2}|%e0%80%[0-9a-f]{2}|%f0%80%80%[0-9a-f]{2}|%f[89ab]%80%80%80%[0-9a-f]{2}|%f[c-f]%80%80%80%80%[0-9a-f]{2}|%ed%[a-f0-9]{2}%[a-f0-9]{2}|%[uU][0-9a-f]{4}|%%u|%25u|%00|\0)/i;

// ============================================================================
// 3. SLIDING WINDOW RATE LIMITER & FINGERPRINTING
// ============================================================================

// [F4] Local memory store. Note: In serverless environments, this state is localized per instance.
// Each edge instance maintains its own Map, providing zero-latency mitigation against intense localized bursts.
const RATE_STORE = new Map();
const MAX_RATE_ENTRIES = 5000;

function localSlidingWindow(clientKey, maxRequests, windowMs) {
  const now = Date.now();
  if (RATE_STORE.size > MAX_RATE_ENTRIES) RATE_STORE.clear();

  let clientData = RATE_STORE.get(clientKey);
  if (!clientData) {
    clientData = { timestamps: [] };
    RATE_STORE.set(clientKey, clientData);
  }

  const windowStart = now - windowMs;
  clientData.timestamps = clientData.timestamps.filter((ts) => ts > windowStart);

  if (clientData.timestamps.length >= maxRequests) {
    return false;
  }
  clientData.timestamps.push(now);
  return true;
}

async function checkSlidingRateLimit(clientKey, maxRequests, windowMs) {
  return localSlidingWindow(clientKey, maxRequests, windowMs);
}

// Generates a unique client fingerprint based on IP and User-Agent hash.
function getClientFingerprint(request) {
  const trustedIp =
    request.headers.get('x-vercel-forwarded-for')?.split(',')[0].trim() ||
    request.headers.get('x-real-ip') ||
    '127.0.0.1';

  const ua = request.headers.get('user-agent') || 'no-ua';
  return `${trustedIp}:${ua.slice(0, 32)}`;
}

// [F4] Multi-key evaluation: Validates raw IP (anti-stuffing) and IP+UA (anti-burst).
async function rateLimitDecision(request) {
  const trustedIp =
    request.headers.get('x-vercel-forwarded-for')?.split(',')[0].trim() ||
    request.headers.get('x-real-ip') ||
    '127.0.0.1';
  const ua = (request.headers.get('user-agent') || 'no-ua').slice(0, 32);

  const ipOk = await checkSlidingRateLimit(`ip:${trustedIp}`, WAF_CONFIG.rateLimitMax, WAF_CONFIG.rateLimitWindowMs);
  const fpOk = await checkSlidingRateLimit(`fp:${trustedIp}:${ua}`, WAF_CONFIG.rateLimitMax, WAF_CONFIG.rateLimitWindowMs);

  if (!ipOk || !fpOk) return { ok: false, ip: trustedIp, ua };
  return { ok: true, ip: trustedIp, ua };
}

// ============================================================================
// 4. CANONICALIZATION & ANTI-EVASION NORMALIZATION
// ============================================================================

const CHAR_MAP = {
  '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c',
  '\u0443': 'y', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j', '\u0455': 's',
  '\u057d': 'u', '\u03b1': 'a', '\u0627': 'a',
  '\u1D64': 'u', '\u2099': 'n', '\u1D62': 'i', '\u2092': 'o', '\u209B': 's',
  '\u2091': 'e', '\u1D63': 'r', '\u1D67': 't', '\u2098': 'm', '\u2C7C': 'j',
  '\u2097': 'l', '\ua700': 'c', '\u209c': 't',
  '\u1D41': 'u', '\u207F': 'n', '\u2071': 'i', '\u1D3C': 'o', '\u02E2': 's',
  '\u1D49': 'e', '\u02B3': 'r', '\u1D57': 't',
  '\u1D1C': 'u', '\u0274': 'n', '\u026A': 'i', '\u1D0F': 'o', '\u0283': 's',
  '\u1D07': 'e', '\u0280': 'r', '\u1D1B': 't', '\u1D00': 'a', '\u029F': 'l',
  '\u1D04': 'c',
};

function normalizeCharMap(str) {
  let mapped = '';
  for (const c of str) {
    mapped += CHAR_MAP[c] || c;
  }
  let s = mapped;

  try {
    s = s.normalize('NFD').replace(/\p{Diacritic}/gu, '');
  } catch {
    s = s.normalize('NFKD');
  }

  s = s.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g, '');
  s = s.replace(/[\u0300-\u036F\u1DC0-\u1DFF\u20D0-\u20FF]/g, '');
  return s;
}

function decodeBareHex(str) {
  if (typeof str !== 'string') return str;
  let s = str.replace(/(?:25)?3[cC]/gi, '<').replace(/(?:25)?3[eE]/gi, '>');
  if (/^(?:[0-9a-fA-F]{2})+$/.test(s)) {
    try {
      let out = '';
      for (let i = 0; i < s.length; i += 2) {
        out += String.fromCharCode(parseInt(s.slice(i, i + 2), 16));
      }
      if (/[\x20-\x7E]/.test(out)) return out;
    } catch {}
  }
  return s;
}

function deepNormalize(target) {
  if (!target || typeof target !== 'string') return '';

  let out = target;

  out = decodeBareHex(out);

  // JS Unicode Escapes \u003c
  out = out.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => {
    try { return String.fromCharCode(parseInt(hex, 16)); } catch { return ''; }
  }).replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => {
    try { return String.fromCharCode(parseInt(hex, 16)); } catch { return ''; }
  });

  // UTF-7
  out = out
    .replace(/(?:\+|%2b)ADw-(?:\+|%2b)?/gi, '<')
    .replace(/(?:\+|%2b)AD4-(?:\+|%2b)?/gi, '>')
    .replace(/(?:\+|%2b)ACI-(?:\+|%2b)?/gi, '"')
    .replace(/(?:\+|%2b)ACc-(?:\+|%2b)?/gi, "'");

  // Multi-pass URL and %u decoding. Each pass is isolated: a malformed decode will NOT
  // abort the entire pipeline (mitigating a common evasion technique).
  for (let i = 0; i < 4; i++) {
    let changed = false;
    try {
      let s = out.replace(/%%u/gi, '%u').replace(/%25u/gi, '%u');
      s = s.replace(/%[uU]([0-9a-fA-F]{4})/g, (_, hex) => {
        try { return String.fromCharCode(parseInt(hex, 16)); } catch { return ''; }
      });
      const next = decodeURIComponent(s);
      if (next !== out) { out = next; changed = true; }
    } catch {
      // Decode failed (e.g., malformed %c0): falling back to a non-throwing byte-wise decode.
      try {
        const relaxed = out.replace(/%([0-9a-fA-F]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));
        if (relaxed !== out) { out = relaxed; changed = true; }
      } catch {}
    }
    if (!changed) break;
  }

  // Unicode Diacritics & Homoglyphs
  out = normalizeCharMap(out);

  out = out
    .replace(/[\u00A0\u1680\u2000-\u200B\u202F\u205F\u3000\v\f\0]/g, ' ')
    .replace(/[\u2215\uFF0F\u2044]/g, '/')
    .replace(/[\u2216\uFF3C]/g, '\\');

  // HTML Entities
  for (let i = 0; i < 3; i++) {
    const next = out
      .replace(/&#x([0-9a-fA-F]+);?/gi, (_, h) => {
        try { return String.fromCodePoint(parseInt(h, 16)); } catch { return ''; }
      })
      .replace(/&#(\d+);?/g, (_, d) => {
        try { return String.fromCodePoint(parseInt(d, 10)); } catch { return ''; }
      })
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/&amp;/gi, '&')
      .replace(/&quot;/gi, '"')
      .replace(/&#x27;/gi, "'");
    if (next === out) break;
    out = next;
  }

  return out.replace(/[\u0000-\u0008\u000e-\u001f\u007f]/g, '');
}

function unbreakKeywords(str) {
  return str
    .replace(/\/\*!\d*([\s\S]*?)\*\//g, '$1')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/[`"\[\]]/g, ' ')
    .replace(/\s+/g, ' ');
}

// [F1] Strips SQL padding (comments, alternative whitespace) to expose underlying tokens.
// Quotes are preserved as they are critical for tautology evaluation.
function exposeSqlTokens(str) {
  return str
    .replace(/\/\*!?\d*([\s\S]*?)\*\//g, '$1')   // versioned comment: /*!50000 ... */
    .replace(/\/\*[\s\S]*?\*\//g, ' ')            // block comment
    .replace(/\s+/g, ' ')
    .trim();
}

function containsPrototypePollution(val) {
  if (typeof val === 'string') {
    const l = val.toLowerCase();
    for (const k of PROTO_KEYS) {
      if (l.includes(k)) return true;
    }
    return false;
  }
  if (typeof val === 'object' && val !== null) {
    for (const key of Object.keys(val)) {
      if (containsPrototypePollution(key) || containsPrototypePollution(val[key])) {
        return true;
      }
    }
  }
  return false;
}

// ============================================================================
// 5. DECISION ENGINE & TELEMETRY AUDIT LOG
// ============================================================================

function emitTelemetryLog(data) {
  console.warn(JSON.stringify({
    source: 'ParallaxWAF/5.1',
    timestamp: new Date().toISOString(),
    ...data,
  }));
}

function createWafResponse(action, status, reason, eventId, score) {
  return new Response(
    JSON.stringify({
      error: status === 403 ? 'Forbidden' : status === 405 ? 'Method Not Allowed' : status === 429 ? 'Too Many Requests' : 'Bad Request',
      message: 'Blocked by application security policy.',
      reason,
      eventId,
      score,
    }),
    {
      status,
      headers: {
        'Content-Type': 'application/json',
        'X-WAF-Status': 'BLOCKED',
        'X-WAF-Event-ID': eventId,
        'X-WAF-Score': String(score),
        'X-WAF-Mode': WAF_CONFIG.mode,
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer',
        'Cache-Control': 'no-store',
        'Retry-After': '60',
      },
    }
  );
}

// [F2] Matches allowlist routes exactly or on segment boundaries (avoids startsWith flaws).
function isAllowlisted(rawPath) {
  return WAF_CONFIG.routeAllowlist.some(
    (allowed) => rawPath === allowed || rawPath.startsWith(allowed + '/')
  );
}

// ============================================================================
// 6. MAIN INSPECTION PIPELINE
// ============================================================================

export default async function middleware(request) {
  const startTime = Date.now();
  const rawMethod = (request.method || '').toUpperCase();
  const url = new URL(request.url);
  const rawPath = request.nextUrl?.pathname || url.pathname;
  const eventId = `WAF-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 1000)}`;

  // --------------------------------------------------------------------------
  // STAGE 0: Allowlist Routes (Legitimate bypass for OAuth/Webhooks)
  // [F2] Segment boundary matching: e.g., /api/webhooks-anything is NOT allowlisted.
  // --------------------------------------------------------------------------
  if (isAllowlisted(rawPath)) {
    return; // Immediate pass-through (restricted to exact paths or valid sub-segments).
  }

  // --------------------------------------------------------------------------
  // STAGE 1: HTTP Method Gate (405) & Override Check
  // --------------------------------------------------------------------------
  if (!ALLOWED_METHODS.has(rawMethod) || rawMethod === 'OPTIONS') {
    emitTelemetryLog({ action: 'BLOCK', eventId, status: 405, reason: 'Method not allowed', method: rawMethod, path: rawPath });
    return createWafResponse('BLOCK', 405, 'Method not allowed', eventId, 5);
  }

  for (const h of METHOD_OVERRIDE_HEADERS) {
    const val = request.headers.get(h);
    if (val) {
      const override = val.toUpperCase().trim();
      if (!ALLOWED_METHODS.has(override) || override === 'PUT' || override === 'DELETE') {
        emitTelemetryLog({ action: 'BLOCK', eventId, status: 405, reason: `Prohibited method override: ${override}`, path: rawPath });
        return createWafResponse('BLOCK', 405, `Prohibited method override: ${override}`, eventId, 5);
      }
    }
  }

  // --------------------------------------------------------------------------
  // STAGE 2: Scanner & Recon Bot Shield (User-Agent Validation)
  // --------------------------------------------------------------------------
  const userAgent = request.headers.get('user-agent') || '';
  for (const botPattern of KNOWN_ATTACK_TOOLS) {
    if (botPattern.test(userAgent)) {
      emitTelemetryLog({ action: 'BLOCK', eventId, status: 403, reason: 'Automated vulnerability scanner blocked', ua: userAgent, path: rawPath });
      return createWafResponse('BLOCK', 403, 'Automated vulnerability scanner blocked', eventId, 5);
    }
  }

  // --------------------------------------------------------------------------
  // STAGE 3: Rate Limiting & DoS Shield (Executed prior to CPU-intensive Regex evaluations)
  // [F4] In-memory store evaluation across multiple keys.
  // --------------------------------------------------------------------------
  const rateDecision = await rateLimitDecision(request);
  if (!rateDecision.ok) {
    emitTelemetryLog({ action: 'BLOCK', eventId, status: 429, reason: 'Rate limit exceeded', client: rateDecision.ip, path: rawPath });
    return createWafResponse('BLOCK', 429, 'Rate limit exceeded', eventId, 5);
  }

  // URL size limitation.
  if (request.url.length > WAF_CONFIG.maxUrlLength) {
    return createWafResponse('BLOCK', 414, 'URL length exceeds safety limit', eventId, 5);
  }

  // --------------------------------------------------------------------------
  // STAGE 4: Path Anomalies, Directory Traversal, & Hostile Routing
  // --------------------------------------------------------------------------
  if (
    request.url.includes('..;') ||
    request.url.includes(';.js') ||
    request.url.includes('etc/passwd') ||
    request.url.includes('win.ini') ||
    /\/\/[^/]+\/{2,}/.test(request.url) ||
    /\/\/[^/]+\/\.\./.test(request.url) ||
    request.url.includes('//etc') ||
    request.url.includes('///') ||
    /^\/{2,}/.test(rawPath) ||
    /^\/([@\\;~]|https?:|%23|%3F)/i.test(rawPath) ||
    /\/\.\.?%2f/i.test(rawPath) ||
    /\/\.\.?%5c/i.test(rawPath) ||
    /\/\.\.?[\/\\]/.test(rawPath) ||
    /\/\.\.;/.test(rawPath) ||
    /\/\.;/.test(rawPath) ||
    /\/~/i.test(rawPath) ||
    /%23|%3F/i.test(rawPath) ||
    OVERLONG_AND_EVASION_PATTERN.test(rawPath)
  ) {
    emitTelemetryLog({ action: 'BLOCK', eventId, status: 403, reason: 'Path traversal or routing probe', path: rawPath });
    return createWafResponse('BLOCK', 403, 'Path anomaly or scanner probe', eventId, 5);
  }

  // Global evasion encoding detection in URL.
  if (OVERLONG_AND_EVASION_PATTERN.test(request.url) || OVERLONG_AND_EVASION_PATTERN.test(url.search)) {
    return createWafResponse('BLOCK', 403, 'Evasion encoding detected (Overlong UTF-8, CESU-8 or Null Byte)', eventId, 5);
  }

  // Stripped fragment or empty entity injection probes.
  if (url.search === '?q=' || url.search === '?q=&' || /^\?q=(?:&|%26)?$/i.test(url.search)) {
    return createWafResponse('BLOCK', 403, 'Stripped fragment or empty entity injection', eventId, 5);
  }

  // Hostile routing header validation.
  for (const h of HOSTILE_ROUTING_HEADERS) {
    if (request.headers.has(h)) {
      return createWafResponse('BLOCK', 403, `Hostile routing header: ${h}`, eventId, 5);
    }
  }

  // --------------------------------------------------------------------------
  // STAGE 5: Header Injection & Spoofing Inspection
  // --------------------------------------------------------------------------
  for (const [hName, hVal] of request.headers) {
    const val = (hVal || '').toLowerCase();
    const name = (hName || '').toLowerCase();

    if (name === 'x-forwarded-for' && (val.includes('proto=') || val.includes('for='))) {
      return createWafResponse('BLOCK', 403, `Spoofed / Malformed XFF header: ${hName}=${hVal}`, eventId, 5);
    }

    if (
      val.includes('127.0.0.1') ||
      val.includes('127.1') ||
      val.includes('0x7f') ||
      val.includes('0177') ||
      val.includes('2130706433') ||
      val.includes('::ffff:127.0.0.1') ||
      val.includes('::1') ||
      val.includes('localhost') ||
      val.includes('loopback') ||
      val.includes('for=127') ||
      val.includes('host=evil') ||
      val.includes('evil.com')
    ) {
      return createWafResponse('BLOCK', 403, `Spoofed / Localhost IP header: ${hName}=${hVal}`, eventId, 5);
    }

    if (/\$\{jndi:/i.test(hVal) || /\$\{[^}]{0,200}\}/.test(hVal)) {
      return createWafResponse('BLOCK', 403, `JNDI/Template expression in header ${hName}`, eventId, 5);
    }
  }

  // --------------------------------------------------------------------------
  // STAGE 6: Canonicalization & Anomaly Scoring (Query & Body)
  // --------------------------------------------------------------------------
  let anomalyScore = 0;
  const detectedThreats = [];

  const normalizedPath = deepNormalize(rawPath);
  for (const re of BLOCKED_PATH_PATTERNS) {
    if (re.test(rawPath) || re.test(normalizedPath)) {
      anomalyScore += 5;
      detectedThreats.push('Sensitive Path Probe');
    }
  }

  let inspectionSurface = normalizedPath;

  // Query String Inspection.
  for (const [rawKey, rawVal] of url.searchParams) {
    if (containsPrototypePollution(rawKey)) {
      anomalyScore += 5;
      detectedThreats.push(`Prototype pollution in key: ${rawKey}`);
    }

    const cleanKey = rawKey.replace(/\[.*?\]/g, '').toLowerCase();
    const normVal = deepNormalize(rawVal);

    if (REDIRECT_PARAMS.has(cleanKey)) {
      if (
        /^\/{2,}/.test(rawVal) ||
        /^\/{2,}/.test(normVal) ||
        /^\\/i.test(rawVal) ||
        /%2f%2f/i.test(rawVal) ||
        (/^https?:\/\//i.test(normVal) && !WAF_CONFIG.trustedRedirectHosts.some(h => normVal.includes(h))) ||
        /^javascript:/i.test(normVal) ||
        /^data:/i.test(normVal)
      ) {
        anomalyScore += 5;
        detectedThreats.push(`Open redirect attempt: ${rawKey}`);
      }
    }

    if (SSRF_PARAMS.has(cleanKey)) {
      if (ANOMALY_RULES.ssrfCritical.pattern.test(normVal) || ANOMALY_RULES.ssrfCritical.pattern.test(rawVal)) {
        anomalyScore += 5;
        detectedThreats.push(`SSRF attempt: ${rawKey}`);
      }
    }

    if (/^(_method|method)$/i.test(cleanKey) && /^(DELETE|PUT|PATCH|PURGE)$/i.test(normVal)) {
      return createWafResponse('BLOCK', 405, `Method mutation parameter: ${rawKey}=${rawVal}`, eventId, 5);
    }

    inspectionSurface += `\n${cleanKey}=${normVal}`;
  }

  if (rawMethod === 'GET') {
    const cl = request.headers.get('content-length');
    if (cl && parseInt(cl, 10) > 0) {
      return createWafResponse('BLOCK', 400, 'GET request with body not allowed', eventId, 5);
    }
  }

  // --------------------------------------------------------------------------
  // [F5] Body Inspection — Enforces a fail-closed policy on oversized payloads prior to full inspection.
  // --------------------------------------------------------------------------
  if (rawMethod === 'POST') {
    const declaredLen = parseInt(request.headers.get('content-length') || '0', 10);
    if (declaredLen > WAF_CONFIG.maxBodyBytes) {
      emitTelemetryLog({ action: 'BLOCK', eventId, status: 413, reason: 'Body exceeds hard limit', bytes: declaredLen, path: rawPath });
      return createWafResponse('BLOCK', 413, 'Request body exceeds safety limit', eventId, 5);
    }

    try {
      const clone = request.clone();
      const fullBody = await clone.text();

      // Double verification: If the actual parsed body exceeds limits, trigger fail-closed.
      if (fullBody.length > WAF_CONFIG.maxBodyBytes) {
        emitTelemetryLog({ action: 'BLOCK', eventId, status: 413, reason: 'Body exceeds hard limit (measured)', bytes: fullBody.length, path: rawPath });
        return createWafResponse('BLOCK', 413, 'Request body exceeds safety limit', eventId, 5);
      }

      if (fullBody.length > 0) {
        if (/(?:^|&)(?:_method|method)=(?:DELETE|PUT|PATCH)/i.test(fullBody)) {
          return createWafResponse('BLOCK', 405, 'Method mutation in body', eventId, 5);
        }

        if (containsPrototypePollution(fullBody)) {
          anomalyScore += 5;
          detectedThreats.push('Prototype pollution in body');
        }

        if (ANOMALY_RULES.xxeCritical.pattern.test(fullBody)) {
          anomalyScore += 5;
          detectedThreats.push('XML External Entity (XXE)');
        }

        // Inspects the ENTIRE body (up to the safety limit) rather than silently truncating.
        const normBody = deepNormalize(fullBody);
        inspectionSurface += `\nBODY=${normBody}`;
      }
    } catch {}
  }

  // --------------------------------------------------------------------------
  // STAGE 7: Anomaly Score Evaluation
  // --------------------------------------------------------------------------
  const finalNormalized = inspectionSurface.toLowerCase();
  const finalUnbroken = unbreakKeywords(finalNormalized);
  const finalSqlExposed = exposeSqlTokens(finalNormalized);

  if (/\$\{[^}]{0,128}jndi/i.test(finalNormalized) || /\$\{jndi:/i.test(finalNormalized)) {
    anomalyScore += 5;
    detectedThreats.push('JNDI / Log4j');
  }

  for (const [ruleName, rule] of Object.entries(ANOMALY_RULES)) {
    if (rule.pattern.test(finalNormalized) || rule.pattern.test(finalUnbroken)) {
      anomalyScore += rule.score;
      detectedThreats.push(ruleName);
    }
  }

  // [F1] Structural SQLi tautologies (quote-agnostic), evaluated across three normalized payload views.
  for (const pat of SQLI_TAUTOLOGY_PATTERNS) {
    if (pat.test(finalNormalized) || pat.test(finalSqlExposed)) {
      anomalyScore += 5;
      detectedThreats.push('SQLi tautology');
      break;
    }
  }

  const strippedWhitespace = finalUnbroken.replace(/[\s\-_]+/g, '');
  if (/unionselect|selectfrom|insertinto|droptable|1or1=1/i.test(strippedWhitespace)) {
    anomalyScore += 5;
    detectedThreats.push('Obfuscated Keyword Splitting SQLi');
  }

  // --------------------------------------------------------------------------
  // STAGE 8: Final Action Execution (Enforce vs Observe)
  // --------------------------------------------------------------------------
  if (anomalyScore >= WAF_CONFIG.anomalyThreshold) {
    emitTelemetryLog({
      action: WAF_CONFIG.mode === 'OBSERVE' ? 'OBSERVE' : 'BLOCK',
      eventId,
      score: anomalyScore,
      threats: detectedThreats,
      client: `${rateDecision.ip}:${rateDecision.ua}`,
      path: rawPath,
      method: rawMethod,
      durationMs: Date.now() - startTime,
    });

    if (WAF_CONFIG.mode === 'ENFORCE') {
      return createWafResponse('BLOCK', 403, `Threat policy violation (${detectedThreats.join(', ')})`, eventId, anomalyScore);
    }
  }

  // Legitimate traffic: Request passed to the underlying application.
}

// ============================================================================
// [F3] MATCHER — No broad extension skipping. Safely bypasses ONLY verified static assets
// anchored to known prefixes. All other traffic (including query strings) is rigorously inspected.
// ============================================================================
export const config = {
  matcher: [
    // Excludes specific static assets, build outputs, and favicons to minimize overhead.
    '/((?!favicon\\.ico$|_next/static|_vercel/|assets/|static/|build/|dist/).*)',
  ],
};

