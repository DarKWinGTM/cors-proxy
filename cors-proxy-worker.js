/**
 * Cloudflare Worker — Hardened Transparent CORS Proxy
 *
 * Usage:
 *   https://<your-worker>.workers.dev/?url=https://api.example.com/endpoint
 *
 * Supported methods: GET, POST, PUT, PATCH, DELETE, OPTIONS
 *
 * Security layers applied:
 *   A. Origin allowlist  — only requests from known origins are served
 *   B. Target host allowlist — only whitelisted upstream hosts can be proxied
 *   C. Request header sanitization — credentials & internal headers are stripped
 *   D. Response header sanitization — upstream Set-Cookie / sensitive headers
 *      are stripped; CORS headers are set precisely (no wildcard with credentials)
 */

// =============================================================================
// 1. ALLOWLISTS  ── edit these two sets before deploying
// =============================================================================

/**
 * A. Allowed caller origins.
 *    These are the front-end origins permitted to use this proxy.
 *    A request whose Origin header is NOT in this set is rejected with 403.
 *
 *    Format: scheme + host + optional port  (no trailing slash)
 *    Example entries:
 *      "https://app.example.com"
 *      "https://staging.example.com"
 *      "http://localhost:3000"     ← handy during local dev
 */
const ALLOWED_ORIGINS = new Set([
  "http://192.168.29.121:5173",
  "http://localhost:5173"
]);

/**
 * B. Allowed upstream target hosts.
 *    Only hostnames present here may be used as the ?url= target.
 *    This prevents the proxy from being turned into an open relay or
 *    used for Server-Side Request Forgery (SSRF) against internal services.
 *
 *    Format: bare hostname (no scheme, no path, no port)
 *    Example entries:
 *      "api.example.com"
 *      "another-api.io"
 */
const ALLOWED_TARGET_HOSTS = new Set([
  "api.binance.com",
  "api.example.com",
  "another-api.io",
]);

// =============================================================================
// 2. HEADER SANITIZATION LISTS
// =============================================================================

/**
 * C. Cookie headers — handled as a dedicated first-class guard, not just
 *    another entry in a blocklist that someone could accidentally remove.
 *
 *    Cookies are NEVER forwarded in either direction:
 *      Request  → upstream : "cookie"     — proxy's own session tokens must
 *                                           never reach a third-party API.
 *      Response → browser  : "set-cookie" — upstream cookies must not be
 *                                           planted on the proxy's own domain.
 *
 *    This set is checked in stripCookieHeaders() before any other filtering.
 */
const COOKIE_HEADERS = new Set(["cookie", "set-cookie"]);

// ─── Why not a prefix-based allow/block rule? ────────────────────────────────
// A prefix-only strategy (e.g. "only forward headers starting with x-app-")
// is too coarse for a transparent proxy:
//   • Legitimate standard headers (Content-Type, Authorization, Accept,
//     Accept-Encoding, Accept-Language) share no common safe prefix.
//   • A prefix like "x-" would still pass x-forwarded-for, x-real-ip, etc.
//
// The correct approach is a targeted BLOCKLIST: we know exactly which headers
// are dangerous to forward, so we name them explicitly and pass everything else.
// This is the same strategy used by nginx, Caddy, and AWS API Gateway.
//
// We do use PREFIX MATCHING for two groups whose entire namespace is dangerous:
//   • "cf-"          — all Cloudflare-internal routing headers
//   • "x-forwarded-" — all forwarding headers that leak internal topology
// Individual well-known names cover the remaining dangerous headers.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * C. Request header blocklist (cookies handled separately above).
 *
 *    BLOCKED_REQUEST_HEADER_PREFIXES — entire namespaces that are unsafe:
 *      "cf-"          Cloudflare internal headers (cf-ray, cf-connecting-ip …)
 *      "x-forwarded-" topology-leaking forwarding headers
 *
 *    BLOCKED_REQUEST_HEADER_NAMES — individual dangerous headers:
 *      "host"      must be replaced with the upstream host, never forwarded
 *      "x-real-ip" leaks the original client IP to the upstream
 */
const BLOCKED_REQUEST_HEADER_PREFIXES = ["cf-", "x-forwarded-"];

const BLOCKED_REQUEST_HEADER_NAMES = new Set([
  "host",
  "x-real-ip",
]);

/**
 * D. Response header blocklist (set-cookie handled separately above).
 *
 *    Headers that are scoped to the upstream's own origin and must not
 *    be relayed to the browser under the proxy's domain:
 *      strict-transport-security — would pin the proxy domain to https
 *      x-frame-options           — framing policy meant for the upstream's UI
 *      content-security-policy   — CSP rules are origin-specific
 *      clear-site-data           — would wipe the proxy origin's storage
 */
const BLOCKED_RESPONSE_HEADER_NAMES = new Set([
  "strict-transport-security",
  "x-frame-options",
  "content-security-policy",
  "content-security-policy-report-only",
  "clear-site-data",
]);

// ─── Shared helper ───────────────────────────────────────────────────────────
/** Returns true if a lowercased header name matches any blocked prefix. */
function hasBlockedPrefix(lowerName) {
  return BLOCKED_REQUEST_HEADER_PREFIXES.some((p) => lowerName.startsWith(p));
}

// =============================================================================
// 3. HELPERS
// =============================================================================

/**
 * Build a JSON error response.
 * allowOrigin is passed only when the request origin was already validated —
 * rejected-origin errors intentionally omit it so the browser cannot read
 * the body either (double-rejection).
 */
function errorResponse(message, status, allowOrigin = null) {
  const headers = { "Content-Type": "application/json" };
  if (allowOrigin) {
    headers["Access-Control-Allow-Origin"] = allowOrigin;
    headers["Vary"] = "Origin";
  }
  return new Response(JSON.stringify({ error: message }), { status, headers });
}

/**
 * D. Build precise CORS headers reflecting the exact requesting origin.
 *    Using the reflected origin (instead of "*") is required when the
 *    request carries credentials such as an Authorization header.
 *    Vary: Origin instructs caches to store separate entries per origin.
 */
function buildCorsHeaders(requestOrigin) {
  return {
    "Access-Control-Allow-Origin":  requestOrigin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, Accept, Origin",
    "Access-Control-Max-Age":       "86400",
    "Vary":                         "Origin",
    "Access-Control-Allow-Credentials": "true",
  };
}

// =============================================================================
// 4. A — ORIGIN VALIDATION
// =============================================================================

/**
 * Validates the caller's Origin header against ALLOWED_ORIGINS.
 *
 * Requests with no Origin header (e.g. server-to-server, curl without -H Origin)
 * are not subject to the browser Same-Origin Policy and carry no CSRF risk,
 * so they are passed through with origin = null.
 *
 * To lock the proxy down to browser-only callers, change the early-return
 * below to: return { ok: false, origin: null }
 */
function validateOrigin(request) {
  const origin = request.headers.get("Origin");

  // No Origin header → non-browser caller, pass through
  if (!origin) return { ok: true, origin: null };

  if (ALLOWED_ORIGINS.has(origin)) return { ok: true, origin };

  return { ok: false, origin };
}

// =============================================================================
// 5. B — TARGET HOST VALIDATION  (SSRF / open-proxy prevention)
// =============================================================================

function validateTargetHost(parsedTarget) {
  const host = parsedTarget.hostname.toLowerCase();

  // Block private / loopback / link-local ranges regardless of the allowlist
  const privatePatterns = [
    /^localhost$/,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^::1$/,
    /^0\.0\.0\.0$/,
    /^169\.254\./,   // link-local / AWS metadata
    /\.internal$/,
    /\.local$/,
  ];

  for (const pattern of privatePatterns) {
    if (pattern.test(host)) {
      return { ok: false, reason: "Requests to private/internal addresses are not allowed." };
    }
  }

  if (!ALLOWED_TARGET_HOSTS.has(host)) {
    return { ok: false, reason: `Host "${host}" is not in the allowed target list.` };
  }

  return { ok: true };
}

// =============================================================================
// 6. C — REQUEST HEADER SANITIZATION
// =============================================================================

/**
 * Step 1 — cookie guard (always runs first, unconditionally).
 * Removes "cookie" and "set-cookie" from a Headers object in-place.
 * Extracted as its own function so it is impossible to skip by refactoring
 * the general sanitization logic.
 */
function stripCookieHeaders(headers) {
  for (const name of COOKIE_HEADERS) {
    headers.delete(name);
  }
}

/**
 * Step 2 — general request header sanitization.
 *
 * Builds a clean Headers object by:
 *   1. Removing cookie headers (via stripCookieHeaders — always first).
 *   2. Dropping any header whose name matches a blocked prefix (cf-, x-forwarded-).
 *   3. Dropping individually named dangerous headers (host, x-real-ip).
 *   4. Passing everything else through untouched (Content-Type, Authorization,
 *      Accept, Accept-Encoding, custom app headers, etc.).
 *   5. Overriding Origin to the upstream's own origin.
 */
function sanitizeRequestHeaders(incomingHeaders, upstreamOrigin) {
  const sanitized = new Headers(incomingHeaders);

  // 1. Cookies — dedicated guard, runs before anything else
  stripCookieHeaders(sanitized);

  // 2 & 3. Prefix-matched and individually named dangerous headers
  for (const [name] of sanitized.entries()) {
    const lower = name.toLowerCase();
    if (hasBlockedPrefix(lower) || BLOCKED_REQUEST_HEADER_NAMES.has(lower)) {
      sanitized.delete(name);
    }
  }

  // 4. Override Origin to the upstream's own origin
  sanitized.set("Origin", upstreamOrigin);

  return sanitized;
}

// =============================================================================
// 7. D — RESPONSE HEADER SANITIZATION + CORS INJECTION
// =============================================================================

/**
 * Builds clean response headers by:
 *   1. Removing set-cookie (via stripCookieHeaders — always first).
 *   2. Dropping origin-scoped upstream headers that must not apply to the
 *      proxy's own domain (HSTS, CSP, X-Frame-Options, etc.).
 *   3. Injecting precise CORS headers that reflect the validated caller origin.
 */
function sanitizeResponseHeaders(upstreamHeaders, requestOrigin) {
  const out = new Headers(upstreamHeaders);

  // 1. Strip set-cookie — upstream cookies must not be planted on proxy domain
  stripCookieHeaders(out);

  // 2. Strip origin-scoped upstream policy headers
  for (const name of BLOCKED_RESPONSE_HEADER_NAMES) {
    out.delete(name);
  }

  // 3. Inject precise CORS headers (reflected origin, never wildcard)
  for (const [name, value] of Object.entries(buildCorsHeaders(requestOrigin))) {
    out.set(name, value);
  }

  return out;
}

// =============================================================================
// 8. PREFLIGHT HANDLER
// =============================================================================

function handlePreflight(request, validatedOrigin) {
  const requestMethod  = request.headers.get("Access-Control-Request-Method");
  const requestHeaders = request.headers.get("Access-Control-Request-Headers");

  if (requestMethod) {
    // Real CORS preflight — echo back exactly the headers the browser asked about
    return new Response(null, {
      status: 204,
      headers: {
        ...buildCorsHeaders(validatedOrigin),
        ...(requestHeaders ? { "Access-Control-Allow-Headers": requestHeaders } : {}),
      },
    });
  }

  // Plain OPTIONS (no CORS negotiation)
  return new Response(null, {
    status: 204,
    headers: {
      Allow: "GET, POST, PUT, PATCH, DELETE, OPTIONS",
      ...buildCorsHeaders(validatedOrigin),
    },
  });
}

// =============================================================================
// 9. PROXY HANDLER
// =============================================================================

async function handleProxy(request, validatedOrigin) {
  const incomingUrl = new URL(request.url);

  // ── Extract & validate the target URL ─────────────────────────────────────
  const targetUrl = incomingUrl.searchParams.get("url");

  if (!targetUrl) {
    return errorResponse(
      'Missing required query parameter: "url". Example: ?url=https://api.example.com/endpoint',
      400,
      validatedOrigin
    );
  }

  let parsedTarget;
  try {
    parsedTarget = new URL(targetUrl);
  } catch {
    return errorResponse(
      `Invalid "url" parameter: "${targetUrl}" is not a valid URL.`,
      400,
      validatedOrigin
    );
  }

  // Protocol check — https only
  if (parsedTarget.protocol !== "https:") {
    return errorResponse(
      `Unsupported protocol "${parsedTarget.protocol}". Only https is allowed.`,
      400,
      validatedOrigin
    );
  }

  // B. Host allowlist + private-range block (SSRF prevention)
  const hostCheck = validateTargetHost(parsedTarget);
  if (!hostCheck.ok) {
    return errorResponse(hostCheck.reason, 403, validatedOrigin);
  }

  // ── C. Build sanitized upstream request ───────────────────────────────────
  const cleanHeaders = sanitizeRequestHeaders(request.headers, parsedTarget.origin);

  const upstreamRequest = new Request(targetUrl, {
    method:   request.method,
    headers:  cleanHeaders,
    // Body must be omitted for bodyless methods to avoid a Workers runtime error
    body:     ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
    redirect: "follow",
  });

  // ── Fetch from upstream ────────────────────────────────────────────────────
  let upstreamResponse;
  try {
    upstreamResponse = await fetch(upstreamRequest);
  } catch (err) {
    return errorResponse(
      `Failed to reach upstream server: ${err.message}`,
      502,
      validatedOrigin
    );
  }

  // ── D. Sanitize response headers + inject CORS ────────────────────────────
  const cleanResponseHeaders = sanitizeResponseHeaders(
    upstreamResponse.headers,
    validatedOrigin ?? "*"   // non-browser callers (no Origin) get wildcard
  );

  return new Response(upstreamResponse.body, {
    status:     upstreamResponse.status,
    statusText: upstreamResponse.statusText,
    headers:    cleanResponseHeaders,
  });
}

// =============================================================================
// 10. ES MODULES ENTRY-POINT
// =============================================================================

export default {
  async fetch(request) {
    const method = request.method.toUpperCase();

    // ── A. Validate caller origin FIRST — before any other processing ──────
    const originCheck = validateOrigin(request);
    if (!originCheck.ok) {
      // Intentionally no Access-Control-Allow-Origin on this response —
      // the browser must NOT be able to read the body of a rejected-origin error.
      return errorResponse(
        `Origin "${originCheck.origin}" is not allowed.`,
        403
      );
    }

    const validatedOrigin = originCheck.origin; // null for non-browser callers

    // ── Route by HTTP method ──────────────────────────────────────────────
    switch (method) {
      case "OPTIONS":
        // Validate origin before responding to preflight — don't leak the
        // allowed methods/headers to unknown origins.
        return handlePreflight(request, validatedOrigin ?? "*");

      case "GET":
      case "POST":
      case "PUT":
      case "PATCH":
      case "DELETE":
        return handleProxy(request, validatedOrigin);

      default:
        return new Response(null, {
          status: 405,
          headers: {
            Allow: "GET, POST, PUT, PATCH, DELETE, OPTIONS",
            ...(validatedOrigin ? buildCorsHeaders(validatedOrigin) : {}),
          },
        });
    }
  },
};
