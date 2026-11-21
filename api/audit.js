const BRANDING = {
  developer: "NexGen Tech Zone || Dark Empire",
  owner: "Sardar Daud Arain",
  website: "https://nexgen-tech-pk.vercel.app"
};

const USER_AGENT =
  "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36";

const SECRET_PATTERNS = [
  { name: "Google / Firebase API Key", regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g, severity: "MEDIUM" },
  { name: "AWS Access Key ID", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: "HIGH" },
  { name: "Stripe Live Secret Key", regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/g, severity: "CRITICAL" },
  { name: "Stripe Publishable Key", regex: /\bpk_live_[0-9a-zA-Z]{24,}\b/g, severity: "LOW" },
  { name: "GitHub Personal Token", regex: /\bgh[pousr]_[A-Za-z0-9_]{36,}\b/g, severity: "CRITICAL" },
  { name: "Supabase / JWT Token", regex: /\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/g, severity: "MEDIUM" },
  { name: "OpenAI / Bearer Token", regex: /\bsk-[A-Za-z0-9]{32,}\b/g, severity: "HIGH" },
  { name: "Firebase Database URL", regex: /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi, severity: "LOW" },
  { name: "Supabase Project URL", regex: /https:\/\/[a-z0-9]+\.supabase\.co/gi, severity: "LOW" }
];

function maskSecret(str) {
  if (!str || str.length <= 10) return "****";
  if (str.startsWith("http")) return str;
  return `${str.slice(0, 6)}****${str.slice(-4)}`;
}

function escapeXml(unsafe) {
  return String(unsafe || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function normalizeTargetUrl(rawUrl) {
  let clean = String(rawUrl || "").trim();
  if (!/^https?:\/\//i.test(clean)) {
    clean = `https://${clean}`;
  }
  const parsed = new URL(clean);
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }
  const host = parsed.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "0.0.0.0" ||
    host.startsWith("192.168.") ||
    host.startsWith("10.")
  ) {
    throw new Error("Private or local network targets are not allowed.");
  }
  return parsed;
}

async function fetchWithTimeout(url, timeoutMs = 6000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/javascript,*/*;q=0.8"
      },
      redirect: "follow"
    });
    if (!res.ok) return { ok: false, status: res.status, text: "", headers: res.headers };
    const text = await res.text();
    return { ok: true, status: res.status, text, headers: res.headers, finalUrl: res.url };
  } catch {
    return { ok: false, status: 0, text: "", headers: null };
  } finally {
    clearTimeout(timer);
  }
}

function resolveFullUrl(baseOrigin, rawPath) {
  try {
    if (!rawPath || rawPath.length < 2 || rawPath.length > 250) return null;
    if (rawPath.startsWith("data:") || rawPath.startsWith("javascript:") || rawPath.startsWith("mailto:")) {
      return null;
    }
    const full = new URL(rawPath, baseOrigin);
    if (!["http:", "https:"].includes(full.protocol)) return null;
    full.hash = "";
    return full.href;
  } catch {
    return null;
  }
}

function extractScriptUrls(html, baseUrl) {
  const scripts = new Set();
  const scriptRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    const resolved = resolveFullUrl(baseUrl, match[1]);
    if (resolved) scripts.add(resolved);
  }
  return Array.from(scripts);
}

function extractInlineScripts(html) {
  const blocks = [];
  const inlineRegex = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
  let match;
  while ((match = inlineRegex.exec(html)) !== null) {
    if (match[1] && match[1].trim().length > 20) {
      blocks.push(match[1]);
    }
  }
  return blocks.join("\n");
}

function analyzeContent(codeText, baseOrigin, fileName, state) {
  for (const rule of SECRET_PATTERNS) {
    rule.regex.lastIndex = 0;
    const matches = codeText.match(rule.regex);
    if (matches) {
      const uniqueMatches = [...new Set(matches)];
      for (const val of uniqueMatches) {
        const masked = maskSecret(val);
        const key = `${rule.name}:${masked}`;
        if (!state.seenSecrets.has(key)) {
          state.seenSecrets.add(key);
          state.secrets.push({
            type: rule.name,
            file: fileName,
            masked_value: masked,
            severity: rule.severity
          });
        }
      }
    }
  }

  const mapMatch = codeText.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+\.map)/i);
  if (mapMatch) {
    const fullMapUrl = resolveFullUrl(baseOrigin, mapMatch[1]);
    if (fullMapUrl) state.candidateSourceMaps.add(fullMapUrl);
  }

  const relPathRegex = /["'`](\/[a-zA-Z0-9_\-\/\.]{2,120})["'`]/g;
  let pMatch;
  while ((pMatch = relPathRegex.exec(codeText)) !== null) {
    const path = pMatch[1];
    if (/\.(png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|eot|css|mp4|mp3)$/i.test(path)) continue;
    if (path.startsWith("//")) continue;

    const fullUrl = resolveFullUrl(baseOrigin, path);
    if (!fullUrl) continue;

    if (/\/(api|v1|v2|v3|graphql|rest|auth|webhook|trpc|rpc|oauth|token)\b/i.test(path)) {
      state.internalApis.add(fullUrl);
    } else if (!path.endsWith(".js") && path.split("/").length <= 5) {
      state.frontendRoutes.add(fullUrl);
    }
  }

  const fullUrlRegex = /["'`](https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:\/[a-zA-Z0-9_\-\/\.\?\=\&]*)?)["'`]/g;
  let uMatch;
  while ((uMatch = fullUrlRegex.exec(codeText)) !== null) {
    const raw = uMatch[1];
    if (/\.(png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|css|js)$/i.test(raw)) continue;
    if (/w3\.org|schema\.org|reactjs\.org|nextjs\.org|mozilla\.org|google\.com\/search/i.test(raw)) continue;

    try {
      const uObj = new URL(raw);
      uObj.hash = "";
      if (uObj.origin === baseOrigin) {
        if (/\/(api|v1|v2|v3|graphql|auth|webhook)\b/i.test(uObj.pathname)) {
          state.internalApis.add(uObj.href);
        } else {
          state.frontendRoutes.add(uObj.href);
        }
      } else {
        state.externalApis.add(uObj.href);
      }
    } catch {
      // Ignore malformed URLs
    }
  }
}

function calculateSecuritySummary(data) {
  let score = 100;
  const fixes = [];

  const criticalCount = data.secret_audit.filter((s) => s.severity === "CRITICAL").length;
  const highCount = data.secret_audit.filter((s) => s.severity === "HIGH").length;
  const mediumCount = data.secret_audit.filter((s) => s.severity === "MEDIUM").length;

  if (criticalCount > 0) {
    score -= criticalCount * 35;
    fixes.push("CRITICAL: Remove live secret keys from frontend JS immediately and rotate them.");
  }
  if (highCount > 0) {
    score -= highCount * 25;
    fixes.push("HIGH: Move private API keys to server-side environment variables (.env).");
  }
  if (mediumCount > 0) {
    score -= mediumCount * 10;
    fixes.push("MEDIUM: Restrict public Firebase/Supabase/Google API keys using HTTP referrer & RLS rules.");
  }
  if (data.source_maps.exposed) {
    score -= 15;
    fixes.push("Disable public JavaScript Source Maps (.js.map) in production builds.");
  }
  if (!data.security_headers.has_csp) {
    score -= 5;
    fixes.push("Add a Content-Security-Policy (CSP) header to harden frontend script execution.");
  }
  if (!data.security_headers.has_hsts) {
    score -= 5;
    fixes.push("Enable Strict-Transport-Security (HSTS) header for enforced HTTPS.");
  }

  score = Math.max(0, Math.min(100, score));

  let grade = "A+";
  if (score < 40) grade = "F";
  else if (score < 55) grade = "D";
  else if (score < 70) grade = "C";
  else if (score < 80) grade = "B";
  else if (score < 90) grade = "B+";
  else if (score < 96) grade = "A";

  if (fixes.length === 0) {
    fixes.push("No exposed private secrets or public source maps detected in scanned JS bundles.");
  }

  return { score, grade, fixes };
}

function generateFlowchartSvg(report) {
  const feList = report.frontend_routes.slice(0, 7);
  const beList = [
    ...report.backend_apis.internal.map((u) => `[INT] ${u}`),
    ...report.backend_apis.external.map((u) => `[EXT] ${u}`)
  ].slice(0, 7);

  const auditList = [
    `Audit Score: ${report.security_summary.score}/100 (${report.security_summary.grade})`,
    `JS Files Scanned: ${report.scanned_js_files}`,
    `Secrets Detected: ${report.secret_audit.length}`,
    `Source Maps: ${report.source_maps.exposed ? "EXPOSED (!)" : "SAFE (Hidden)"}`,
    `CSP Header: ${report.security_headers.has_csp ? "Present" : "Missing"}`,
    `HSTS Header: ${report.security_headers.has_hsts ? "Present" : "Missing"}`,
    ...report.secret_audit.slice(0, 2).map((s) => `Leak: ${s.type} (${s.masked_value})`)
  ].slice(0, 7);

  const formatLine = (txt, maxLen = 42) =>
    escapeXml(txt.length > maxLen ? `${txt.slice(0, maxLen - 3)}...` : txt);

  const renderRows = (items, startX, startY, color) => {
    if (!items || items.length === 0) {
      return `<text x="${startX}" y="${startY}" fill="#64748b" font-family="monospace" font-size="12">No public endpoints found</text>`;
    }
    return items
      .map(
        (item, idx) =>
          `<text x="${startX}" y="${startY + idx * 28}" fill="${color}" font-family="monospace" font-size="11.5">• ${formatLine(item, 44)}</text>`
      )
      .join("\n");
  };

  return `<?xml version="1.0" encoding="UTF-8"?>
<svg width="1200" height="680" viewBox="0 0 1200 680" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
      <path d="M 30 0 L 0 0 0 30" fill="none" stroke="#0f2922" stroke-width="1"/>
    </pattern>
    <linearGradient id="headerGrad" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#052e16"/>
      <stop offset="100%" stop-color="#064e3b"/>
    </linearGradient>
  </defs>

  <rect width="1200" height="680" fill="#050a0e"/>
  <rect width="1200" height="680" fill="url(#grid)"/>
  <rect x="14" y="14" width="1172" height="652" rx="14" fill="none" stroke="#10b981" stroke-width="2"/>

  <rect x="34" y="30" width="1132" height="58" rx="10" fill="url(#headerGrad)" stroke="#10b981" stroke-width="1.5"/>
  <text x="54" y="56" fill="#34d399" font-family="monospace" font-size="18" font-weight="bold">JS SECRET, ROUTE &amp; ARCHITECTURE FLOWCHART</text>
  <text x="54" y="76" fill="#a7f3d0" font-family="monospace" font-size="12">LIVE TARGET SCANNER // ZERO-TRUST STATIC BUNDLE AUDIT</text>
  <text x="1146" y="64" text-anchor="end" fill="#10b981" font-family="monospace" font-size="14" font-weight="bold">GRADE: ${escapeXml(report.security_summary.grade)} (${report.security_summary.score}/100)</text>

  <rect x="370" y="112" width="460" height="54" rx="10" fill="#0b161d" stroke="#38bdf8" stroke-width="2"/>
  <text x="600" y="135" text-anchor="middle" fill="#38bdf8" font-family="monospace" font-size="12" font-weight="bold">TARGET ROOT DOMAIN</text>
  <text x="600" y="155" text-anchor="middle" fill="#f8fafc" font-family="monospace" font-size="14">${formatLine(report.target, 48)}</text>

  <path d="M 600 166 L 600 198" stroke="#10b981" stroke-width="2"/>
  <path d="M 215 198 L 985 198" stroke="#10b981" stroke-width="2"/>
  <path d="M 215 198 L 215 226" stroke="#38bdf8" stroke-width="2"/>
  <path d="M 600 198 L 600 226" stroke="#10b981" stroke-width="2"/>
  <path d="M 985 198 L 985 226" stroke="#f59e0b" stroke-width="2"/>

  <rect x="34" y="226" width="362" height="360" rx="12" fill="#09131a" stroke="#38bdf8" stroke-width="1.8"/>
  <rect x="34" y="226" width="362" height="42" rx="12" fill="#0c2436"/>
  <text x="215" y="252" text-anchor="middle" fill="#38bdf8" font-family="monospace" font-size="14" font-weight="bold">1. FRONTEND ROUTES (${report.frontend_routes.length})</text>
  ${renderRows(feList, 50, 296, "#bae6fd")}

  <rect x="419" y="226" width="362" height="360" rx="12" fill="#091613" stroke="#10b981" stroke-width="1.8"/>
  <rect x="419" y="226" width="362" height="42" rx="12" fill="#063326"/>
  <text x="600" y="252" text-anchor="middle" fill="#34d399" font-family="monospace" font-size="14" font-weight="bold">2. BACKEND APIs (${report.backend_apis.internal.length + report.backend_apis.external.length})</text>
  ${renderRows(beList, 435, 296, "#a7f3d0")}

  <rect x="804" y="226" width="362" height="360" rx="12" fill="#14110a" stroke="#f59e0b" stroke-width="1.8"/>
  <rect x="804" y="226" width="362" height="42" rx="12" fill="#332308"/>
  <text x="985" y="252" text-anchor="middle" fill="#fbbf24" font-family="monospace" font-size="14" font-weight="bold">3. SECURITY &amp; AUDIT DETAILS</text>
  ${renderRows(auditList, 820, 296, "#fde68a")}

  <rect x="34" y="604" width="1132" height="44" rx="8" fill="#091318" stroke="#1e293b" stroke-width="1"/>
  <text x="54" y="631" fill="#10b981" font-family="monospace" font-size="13" font-weight="bold">Powered By ${escapeXml(BRANDING.developer)} || Owner ${escapeXml(BRANDING.owner)}</text>
  <text x="1146" y="631" text-anchor="end" fill="#94a3b8" font-family="monospace" font-size="12">${escapeXml(BRANDING.website)}</text>
</svg>`;
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    const parsedRequestUrl = new URL(req.url || "/", "http://localhost");
    const rawUrl = parsedRequestUrl.searchParams.get("url") || req.query?.url;
    const mode = (parsedRequestUrl.searchParams.get("mode") || req.query?.mode || "json").toLowerCase();

    if (!rawUrl) {
      return res.status(200).json({
        status: "online",
        api: "JS Secret, Route & Architecture Auditor API",
        usage: {
          json_audit: "/api/audit?url=https://example.com",
          flowchart_visual: "/api/audit?url=https://example.com&mode=flowchart"
        },
        branding: BRANDING
      });
    }

    let parsedTarget;
    try {
      parsedTarget = normalizeTargetUrl(rawUrl);
    } catch (err) {
      return res.status(400).json({
        status: "error",
        message: err.message,
        branding: BRANDING
      });
    }

    const startTime = Date.now();
    const pageRes = await fetchWithTimeout(parsedTarget.href, 7000);

    if (!pageRes.ok || !pageRes.text) {
      return res.status(502).json({
        status: "error",
        message: "Unable to fetch target website (site unreachable, blocked, or timed out).",
        http_status: pageRes.status,
        branding: BRANDING
      });
    }

    const finalTargetUrl = pageRes.finalUrl || parsedTarget.href;
    const baseOrigin = new URL(finalTargetUrl).origin;

    const state = {
      frontendRoutes: new Set(),
      internalApis: new Set(),
      externalApis: new Set(),
      secrets: [],
      seenSecrets: new Set(),
      candidateSourceMaps: new Set()
    };

    const inlineJs = extractInlineScripts(pageRes.text);
    analyzeContent(pageRes.text, baseOrigin, "index.html", state);
    if (inlineJs) {
      analyzeContent(inlineJs, baseOrigin, "inline-script", state);
    }

    const scriptUrls = extractScriptUrls(pageRes.text, finalTargetUrl).slice(0, 8);
    const jsResults = await Promise.allSettled(
      scriptUrls.map(async (jsUrl) => {
        const fileName = new URL(jsUrl).pathname.split("/").pop() || "bundle.js";
        const jsRes = await fetchWithTimeout(jsUrl, 5000);
        if (jsRes.ok && jsRes.text) {
          analyzeContent(jsRes.text, baseOrigin, fileName, state);
          return true;
        }
        return false;
      })
    );

    const scannedJsCount = jsResults.filter((r) => r.status === "fulfilled" && r.value).length;

    const exposedMaps = [];
    const mapsToVerify = Array.from(state.candidateSourceMaps).slice(0, 3);
    await Promise.allSettled(
      mapsToVerify.map(async (mapUrl) => {
        const mapRes = await fetchWithTimeout(mapUrl, 3500);
        if (mapRes.ok && mapRes.text && mapRes.text.includes('"mappings"')) {
          exposedMaps.push(mapUrl);
        }
      })
    );

    const securityHeaders = {
      has_csp: Boolean(pageRes.headers?.get("content-security-policy")),
      has_hsts: Boolean(pageRes.headers?.get("strict-transport-security")),
      has_x_frame: Boolean(pageRes.headers?.get("x-frame-options")),
      server: pageRes.headers?.get("server") || "hidden"
    };

    const report = {
      status: "success",
      target: finalTargetUrl,
      scan_time_ms: Date.now() - startTime,
      scanned_js_files: scannedJsCount,
      scanned_bundles: scriptUrls,
      frontend_routes: Array.from(state.frontendRoutes).sort(),
      backend_apis: {
        internal: Array.from(state.internalApis).sort(),
        external: Array.from(state.externalApis).sort()
      },
      secret_audit: state.secrets,
      source_maps: {
        exposed: exposedMaps.length > 0,
        exposed_files: exposedMaps
      },
      security_headers: securityHeaders,
      security_summary: null,
      flowchart_url: null,
      branding: BRANDING
    };

    report.security_summary = calculateSecuritySummary(report);

    const hostHeader = req.headers["x-forwarded-host"] || req.headers.host;
    const proto = req.headers["x-forwarded-proto"] || "https";
    if (hostHeader) {
      report.flowchart_url = `${proto}://${hostHeader}/api/audit?url=${encodeURIComponent(finalTargetUrl)}&mode=flowchart`;
    }

    if (mode === "flowchart") {
      const svg = generateFlowchartSvg(report);
      res.setHeader("Content-Type", "image/svg+xml; charset=utf-8");
      res.setHeader("Cache-Control", "s-maxage=120, stale-while-revalidate");
      return res.status(200).send(svg);
    }

    res.setHeader("Cache-Control", "s-maxage=120, stale-while-revalidate");
    return res.status(200).json(report);
  } catch (err) {
    return res.status(500).json({
      status: "error",
      message: err?.message || "Unexpected runtime error inside /api/audit",
      branding: BRANDING
    });
  }
}
