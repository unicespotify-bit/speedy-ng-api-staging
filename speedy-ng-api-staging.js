/*
 * Speedy.ng Cloudflare Worker — candidate build
 * Includes customer authentication/email verification, NGN/USD wallets,
 * wallet conversion, admin authentication/settings, pricing rules, and
 * Flutterwave V4 NGN dynamic virtual-account deposits with verified webhooks.
 *
 * IMPORTANT: This is a corrected core Worker candidate, not a launch-ready
 * full Speedy.ng backend. Test against a D1 preview database and Flutterwave
 * sandbox before replacing the live Worker. Includes YoungPG Visual Numbers
 * rentals with SMS polling and confirmed cancellation/expiry refunds, plus
 * guarded Social Logs purchases and delivery history. Nexar Social Boost catalogue diagnostics are included; live purchases remain disabled pending verified credentials and price-currency mapping. Automatic Social Logs refunds are not enabled.
 */
const ALLOWED_ORIGINS = new Set([
  "https://speedy-ng-admin.pages.dev",
  "https://speedy-ng-admin-staging.pages.dev",
  "https://speedy-ng.pages.dev",
  "https://speedy-blue.unicespotify.workers.dev"
]);

function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Credentials": "true"
  };
  if (ALLOWED_ORIGINS.has(origin)) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

function respond(data, status = 200, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders(request)
  });
}

function jsonError(message, status, request) {
  return respond({ error: message }, status, request);
}

async function hash(value) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function token() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// New password hashes use the agreed PBKDF2 work factor: 100,000 iterations.
async function passwordHash(password, salt, iterations = 100000) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt: new TextEncoder().encode(salt),
    iterations,
    hash: "SHA-256"
  }, key, 256);
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyPassword(password, salt, storedHash, allowedIterations = [100000]) {
  if (!salt || !storedHash) return null;
  for (const iterations of allowedIterations) {
    const candidate = await passwordHash(password, salt, iterations);
    if (candidate === storedHash) return iterations;
  }
  return null;
}

async function readBody(request) {
  try { return await request.json(); } catch { return null; }
}

let customerSchemaReady;
async function ensureCustomerSchema(env) {
  if (!customerSchemaReady) {
    customerSchemaReady = (async () => {
      const columns = await env.DB.prepare("PRAGMA table_info(customers)").all();
      const names = new Set((columns.results || []).map(row => row.name));
      if (!names.has("password_hash")) {
        try { await env.DB.prepare("ALTER TABLE customers ADD COLUMN password_hash TEXT").run(); }
        catch (e) { if (!String(e.message).toLowerCase().includes("duplicate column")) throw e; }
      }
      if (!names.has("password_salt")) {
        try { await env.DB.prepare("ALTER TABLE customers ADD COLUMN password_salt TEXT").run(); }
        catch (e) { if (!String(e.message).toLowerCase().includes("duplicate column")) throw e; }
      }
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS customer_sessions (
          id TEXT PRIMARY KEY,
          customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
          token_hash TEXT NOT NULL UNIQUE,
          expires_at TEXT NOT NULL,
          created_at TEXT NOT NULL
        )
      `).run();
      await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_customer_sessions_customer ON customer_sessions(customer_id)").run();
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS wallets (
          id TEXT PRIMARY KEY,
          customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
          currency TEXT NOT NULL CHECK (currency IN ('NGN','USD')),
          balance_minor INTEGER NOT NULL DEFAULT 0 CHECK (balance_minor >= 0),
          updated_at TEXT NOT NULL,
          UNIQUE(customer_id, currency)
        )
      `).run();
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS transactions (
          id TEXT PRIMARY KEY,
          customer_id TEXT NOT NULL REFERENCES customers(id),
          type TEXT NOT NULL,
          currency TEXT NOT NULL CHECK (currency IN ('NGN','USD')),
          amount_minor INTEGER NOT NULL,
          status TEXT NOT NULL,
          reference TEXT UNIQUE,
          description TEXT,
          created_at TEXT NOT NULL
        )
      `).run();
      await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_transactions_customer_created ON transactions(customer_id, created_at DESC)").run();
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS customer_email_verifications (
          id TEXT PRIMARY KEY,
          customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
          code_hash TEXT NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0,
          expires_at TEXT NOT NULL,
          created_at TEXT NOT NULL,
          consumed_at TEXT
        )
      `).run();
      await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_email_verifications_customer_created ON customer_email_verifications(customer_id, created_at DESC)").run();
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS auth_rate_limits (
          bucket_key TEXT PRIMARY KEY,
          hit_count INTEGER NOT NULL DEFAULT 0,
          window_started_at TEXT NOT NULL
        )
      `).run();
    })().catch(error => {
      customerSchemaReady = null;
      throw error;
    });
  }
  return customerSchemaReady;
}

async function getAdmin(request, env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  const suppliedToken = header.slice(7);
  if (!/^[a-f0-9]{64}$/i.test(suppliedToken)) return null;
  const tokenHash = await hash(suppliedToken);
  return env.DB.prepare(`
    SELECT a.id, a.email, a.role
    FROM admin_sessions s
    JOIN admin_users a ON a.id = s.admin_id
    WHERE s.token_hash = ? AND s.expires_at > ? AND a.active = 1
  `).bind(tokenHash, new Date().toISOString()).first();
}

async function getCustomer(request, env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Bearer ")) return null;
  const suppliedToken = header.slice(7);
  if (!/^[a-f0-9]{64}$/i.test(suppliedToken)) return null;
  const tokenHash = await hash(suppliedToken);
  return env.DB.prepare(`
    SELECT c.id, c.email, c.email_verified, c.status
    FROM customer_sessions s
    JOIN customers c ON c.id = s.customer_id
    WHERE s.token_hash = ? AND s.expires_at > ? AND c.status = 'active' AND c.email_verified = 1
  `).bind(tokenHash, new Date().toISOString()).first();
}

async function ensureCustomerWallets(env, customerId) {
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare(`INSERT OR IGNORE INTO wallets (id, customer_id, currency, balance_minor, updated_at) VALUES (?, ?, 'NGN', 0, ?)`)
      .bind(crypto.randomUUID(), customerId, now),
    env.DB.prepare(`INSERT OR IGNORE INTO wallets (id, customer_id, currency, balance_minor, updated_at) VALUES (?, ?, 'USD', 0, ?)`)
      .bind(crypto.randomUUID(), customerId, now)
  ]);
}

async function allowAuthAttempt(env, request, route, identity, maxHits, windowMs) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const key = `${route}:${await hash(ip)}:${await hash(String(identity || "").toLowerCase())}`;
  const now = new Date();
  const nowIso = now.toISOString();
  const cutoffIso = new Date(now.getTime() - windowMs).toISOString();
  await env.DB.prepare(`
    INSERT INTO auth_rate_limits (bucket_key, hit_count, window_started_at)
    VALUES (?, 1, ?)
    ON CONFLICT(bucket_key) DO UPDATE SET
      hit_count = CASE
        WHEN auth_rate_limits.window_started_at <= ? THEN 1
        ELSE auth_rate_limits.hit_count + 1
      END,
      window_started_at = CASE
        WHEN auth_rate_limits.window_started_at <= ? THEN excluded.window_started_at
        ELSE auth_rate_limits.window_started_at
      END
  `).bind(key, nowIso, cutoffIso, cutoffIso).run();
  const row = await env.DB.prepare("SELECT hit_count FROM auth_rate_limits WHERE bucket_key = ?")
    .bind(key).first();
  // Opportunistic cleanup keeps this small table bounded without a Cron trigger.
  await env.DB.prepare("DELETE FROM auth_rate_limits WHERE window_started_at < ?")
    .bind(new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString()).run();
  return Number(row?.hit_count || 0) <= maxHits;
}

function flwBaseUrl(env) {
  const configured = String(env.FLW_BASE_URL || "").trim();
  if (configured) return configured.replace(/\/$/, "");
  // Flutterwave V4 production uses f4bexperience.flutterwave.com.
  // Sandbox uses developersandbox-api.flutterwave.com.
  return String(env.FLW_ENVIRONMENT || "production").toLowerCase() === "sandbox"
    ? "https://developersandbox-api.flutterwave.com"
    : "https://f4bexperience.flutterwave.com";
}

async function flutterwaveAccessToken(env) {
  if (!env.FLW_CLIENT_ID || !env.FLW_CLIENT_SECRET) {
    throw new Error("Flutterwave V4 Client ID and Client Secret are not configured.");
  }
  const form = new URLSearchParams({
    client_id: String(env.FLW_CLIENT_ID),
    client_secret: String(env.FLW_CLIENT_SECRET),
    grant_type: "client_credentials"
  });
  const response = await fetch("https://idp.flutterwave.com/realms/flutterwave/protocol/openid-connect/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString()
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) {
    console.error("Flutterwave OAuth failed:", response.status, JSON.stringify(data).slice(0, 500));
    throw new Error("Flutterwave authentication failed. Check the V4 credentials and environment.");
  }
  return data.access_token;
}

async function flwV4Request(env, accessToken, path, options = {}) {
  const method = options.method || "GET";
  const traceId = crypto.randomUUID();
  const headers = {
    "Authorization": `Bearer ${accessToken}`,
    "Content-Type": "application/json",
    "Accept": "application/json",
    "X-Trace-Id": traceId
  };
  if (method !== "GET") headers["X-Idempotency-Key"] = options.idempotencyKey || crypto.randomUUID();
  const response = await fetch(`${flwBaseUrl(env)}${path}`, {
    method,
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data.status === "failed" || data.status === "error") {
    console.error("Flutterwave API request failed:", method, path, response.status, JSON.stringify(data).slice(0, 700));
    throw new Error("Flutterwave could not complete the payment request. No wallet credit was made.");
  }
  return data;
}

async function getOrCreateFlutterwaveCustomer(env, customer, accessToken) {
  const existing = await env.DB.prepare(
    "SELECT flutterwave_customer_id FROM flutterwave_customers WHERE customer_id = ?"
  ).bind(customer.id).first();
  if (existing?.flutterwave_customer_id) return existing.flutterwave_customer_id;
  const created = await flwV4Request(env, accessToken, "/customers", {
    method: "POST",
    idempotencyKey: `spd-customer-${customer.id}`.slice(0, 120),
    body: { email: customer.email }
  });
  const providerId = created?.data?.id;
  if (!providerId) throw new Error("Flutterwave did not return a customer ID.");
  const now = new Date().toISOString();
  await env.DB.prepare(`
    INSERT INTO flutterwave_customers (customer_id, flutterwave_customer_id, created_at, updated_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(customer_id) DO UPDATE SET
      flutterwave_customer_id = excluded.flutterwave_customer_id,
      updated_at = excluded.updated_at
  `).bind(customer.id, providerId, now, now).run();
  return providerId;
}

async function hmacSha256Base64(secret, rawBody) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody));
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function processFlutterwaveWebhook(request, env) {
  if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const secret = env.FLW_WEBHOOK_SECRET || env.FLW_SECRET_HASH;
  if (!secret) return new Response("Webhook secret is not configured", { status: 503 });

  const rawBody = await request.text();
  const supplied = request.headers.get("flutterwave-signature") || "";
  const expected = await hmacSha256Base64(String(secret), rawBody);
  if (!supplied || !safeStringEqual(supplied, expected)) {
    return new Response("Invalid signature", { status: 401 });
  }

  let payload;
  try { payload = JSON.parse(rawBody); }
  catch { return new Response("Invalid JSON", { status: 400 }); }

  const data = payload?.data || {};
  const webhookId = String(payload.id || payload.webhook_id || `evt-${await hash(rawBody)}`).slice(0, 200);
  const eventType = String(payload.type || payload.event_type || "unknown").slice(0, 100);
  const reference = String(data.reference || data.tx_ref || data.meta?.reference || "").slice(0, 100);
  const chargeId = String(data.id || "").slice(0, 100);
  const now = new Date().toISOString();

  await env.DB.prepare(`
    INSERT OR IGNORE INTO flutterwave_webhook_events
      (webhook_id, event_type, provider_reference, provider_charge_id, processing_status, payload_json, received_at)
    VALUES (?, ?, ?, ?, 'received', ?, ?)
  `).bind(webhookId, eventType, reference || null, chargeId || null, rawBody.slice(0, 100000), now).run();

  if (!reference || !chargeId || !/charge\.completed/i.test(eventType)) {
    await env.DB.prepare("UPDATE flutterwave_webhook_events SET processing_status='ignored', processed_at=? WHERE webhook_id=?")
      .bind(now, webhookId).run();
    return new Response("OK", { status: 200 });
  }

  const deposit = await env.DB.prepare(
    "SELECT * FROM wallet_deposits WHERE provider_reference = ? AND provider = 'flutterwave' LIMIT 1"
  ).bind(reference).first();
  if (!deposit) {
    await env.DB.prepare("UPDATE flutterwave_webhook_events SET processing_status='ignored', processed_at=?, last_error='No matching deposit' WHERE webhook_id=?")
      .bind(now, webhookId).run();
    return new Response("OK", { status: 200 });
  }

  const ledgerReference = `FLW-${reference}`;
  const priorLedger = await env.DB.prepare("SELECT id FROM transactions WHERE reference = ? LIMIT 1")
    .bind(ledgerReference).first();
  if (priorLedger) {
    await env.DB.prepare("UPDATE flutterwave_webhook_events SET processing_status='processed', processed_at=?, last_error=NULL WHERE webhook_id=?")
      .bind(now, webhookId).run();
    return new Response("OK", { status: 200 });
  }

  try {
    const accessToken = await flutterwaveAccessToken(env);
    const verified = await flwV4Request(env, accessToken, `/charges/${encodeURIComponent(chargeId)}`);
    const charge = verified?.data || {};
    const paidAmount = Number(charge.amount);
    const paidMinor = Math.round(paidAmount * 100);
    const expectedMinor = Number(deposit.expected_amount_minor);
    const verifiedReference = String(charge.reference || charge.tx_ref || "");
    const verifiedCurrency = String(charge.currency || "").toUpperCase();
    const verifiedStatus = String(charge.status || "").toLowerCase();

    if (
      !["succeeded", "successful"].includes(verifiedStatus) ||
      verifiedReference !== reference ||
      verifiedCurrency !== String(deposit.currency).toUpperCase() ||
      !Number.isFinite(paidAmount) ||
      !Number.isSafeInteger(paidMinor) ||
      Math.abs(paidAmount * 100 - paidMinor) > 1e-7 ||
      paidMinor !== expectedMinor
    ) {
      await env.DB.prepare(`UPDATE wallet_deposits
        SET status='review', provider_charge_id=?, received_amount_minor=?,
            provider_payload_json=?, failure_reason=?, updated_at=?
        WHERE id=? AND credited_at IS NULL`)
        .bind(chargeId, Number.isSafeInteger(paidMinor) ? paidMinor : null,
          JSON.stringify(verified).slice(0, 100000),
          "Payment details did not exactly match the pending deposit; manual review required.",
          now, deposit.id).run();
      await env.DB.prepare("UPDATE flutterwave_webhook_events SET processing_status='ignored', processed_at=?, last_error='Payment verification mismatch' WHERE webhook_id=?")
        .bind(now, webhookId).run();
      return new Response("OK", { status: 200 });
    }

    // Every step is in one D1 batch. NOT NULL guards force the batch to roll
    // back if the deposit or wallet update did not affect exactly one row.
    await env.DB.batch([
      env.DB.prepare(`UPDATE wallet_deposits
        SET status='processing', provider_charge_id=?, received_amount_minor=?,
            provider_payload_json=?, paid_at=COALESCE(paid_at, ?), updated_at=?
        WHERE id=? AND status IN ('pending','processing','review') AND credited_at IS NULL
          AND expected_amount_minor=?`)
        .bind(chargeId, paidMinor, JSON.stringify(verified).slice(0, 100000), now, now, deposit.id, expectedMinor),
      env.DB.prepare(`UPDATE wallets
        SET balance_minor = balance_minor + ?, updated_at=?
        WHERE customer_id=? AND currency=?
          AND EXISTS (SELECT 1 FROM wallet_deposits WHERE id=? AND status='processing' AND credited_at IS NULL)
          AND NOT EXISTS (SELECT 1 FROM transactions WHERE reference=?)`)
        .bind(paidMinor, now, deposit.customer_id, deposit.currency, deposit.id, ledgerReference),
      env.DB.prepare(`INSERT INTO transactions
        (id, customer_id, type, currency, amount_minor, status, reference, description, created_at)
        SELECT ?, CASE WHEN changes()=1 THEN customer_id ELSE NULL END,
               'deposit', currency, ?, 'successful', ?, 'Flutterwave wallet deposit', ?
        FROM wallet_deposits WHERE id=? AND status='processing' AND credited_at IS NULL`)
        .bind(crypto.randomUUID(), paidMinor, ledgerReference, now, deposit.id),
      env.DB.prepare(`UPDATE wallet_deposits
        SET status='successful', credited_amount_minor=?, credited_at=?, updated_at=?, failure_reason=NULL
        WHERE id=? AND status='processing'
          AND EXISTS (SELECT 1 FROM transactions WHERE reference=?)`)
        .bind(paidMinor, now, now, deposit.id, ledgerReference),
      env.DB.prepare(`UPDATE flutterwave_webhook_events
        SET processing_status='processed', processed_at=?, last_error=NULL
        WHERE webhook_id=? AND EXISTS (
          SELECT 1 FROM wallet_deposits WHERE id=? AND status='successful' AND credited_at=?
        )`)
        .bind(now, webhookId, deposit.id, now)
    ]);
  } catch (error) {
    console.error("Flutterwave webhook processing failed:", error?.message || error);
    await env.DB.prepare("UPDATE flutterwave_webhook_events SET processing_status='failed', processed_at=?, last_error=? WHERE webhook_id=?")
      .bind(new Date().toISOString(), String(error?.message || error).slice(0, 500), webhookId).run().catch(() => {});
    return new Response("Processing failed", { status: 500 });
  }

  return new Response("OK", { status: 200 });
}

function safeStringEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function sendVerificationEmail(env, customer) {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) {
    return { sent: false, reason: "Email delivery is not configured." };
  }
  const pepper = env.EMAIL_VERIFICATION_PEPPER || env.ENCRYPTION_KEY;
  if (!pepper) return { sent: false, reason: "Email verification security is not configured." };

  const recent = await env.DB.prepare(`
    SELECT COUNT(*) AS total, MAX(created_at) AS latest
    FROM customer_email_verifications
    WHERE customer_id = ? AND created_at > ?
  `).bind(customer.id, new Date(Date.now() - 60 * 60 * 1000).toISOString()).first();
  if (Number(recent?.total || 0) >= 5) return { sent: false, reason: "Verification email limit reached. Try again later." };
  if (recent?.latest && Date.now() - new Date(recent.latest).getTime() < 60 * 1000) {
    return { sent: false, reason: "Please wait one minute before requesting another code." };
  }

  const digits = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  const code = String(digits).padStart(6, "0");
  const now = new Date();
  const nowIso = now.toISOString();
  const expires = new Date(now.getTime() + 10 * 60 * 1000);
  const codeHash = await hash(`${customer.id}:${code}:${pepper}`);
  const verificationId = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare("UPDATE customer_email_verifications SET consumed_at = ? WHERE customer_id = ? AND consumed_at IS NULL")
      .bind(nowIso, customer.id),
    env.DB.prepare(`INSERT INTO customer_email_verifications (id, customer_id, code_hash, attempts, expires_at, created_at) VALUES (?, ?, ?, 0, ?, ?)`)
      .bind(verificationId, customer.id, codeHash, expires.toISOString(), nowIso)
  ]);

  const html = `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;color:#14213d"><h2>Verify your Speedy.ng email</h2><p>Use this verification code to confirm your email address:</p><div style="font-size:32px;font-weight:bold;letter-spacing:8px;padding:18px;background:#eef3ff;border-radius:10px;text-align:center">${code}</div><p>This code expires in exactly 10 minutes. If you did not create a Speedy.ng account, you can ignore this email.</p><p>Speedy.ng Team</p></div>`;
  let response;
  try {
    response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: env.EMAIL_FROM, to: [customer.email], subject: "Verify your Speedy.ng email address", html })
    });
  } catch (error) {
    await env.DB.prepare("UPDATE customer_email_verifications SET consumed_at=? WHERE id=? AND consumed_at IS NULL")
      .bind(new Date().toISOString(), verificationId).run();
    console.error("Verification email request failed:", String(error?.message || error).slice(0, 300));
    return { sent: false, reason: "The verification email could not be sent. Please try again later." };
  }
  if (!response.ok) {
    const detail = await response.text();
    await env.DB.prepare("UPDATE customer_email_verifications SET consumed_at=? WHERE id=? AND consumed_at IS NULL")
      .bind(new Date().toISOString(), verificationId).run();
    console.error("Verification email delivery failed:", detail.slice(0, 500));
    return { sent: false, reason: "The verification email could not be sent. Please try again later." };
  }
  return { sent: true, expiresAt: expires.toISOString() };
}

async function customerRoutes(request, env, path, method) {
  if (!["/api/customer/register", "/api/customer/login", "/api/customer/verify-email", "/api/customer/resend-verification", "/api/customer/logout", "/api/customer/me", "/api/customer/wallets", "/api/customer/wallet", "/api/customer/wallet/transactions", "/api/customer/wallet/deposit", "/api/customer/wallet/convert", "/api/customer/transactions"].includes(path)) return null;
  await ensureCustomerSchema(env);

  if (method === "POST" && path === "/api/customer/register") {
    const body = await readBody(request);
    if (!body) return jsonError("Invalid JSON.", 400, request);
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return jsonError("Enter a valid email address.", 400, request);
    if (!env.RESEND_API_KEY || !env.EMAIL_FROM || !(env.EMAIL_VERIFICATION_PEPPER || env.ENCRYPTION_KEY)) {
      return jsonError("Email verification is not configured yet. Please try again later.", 503, request);
    }
    if (!(await allowAuthAttempt(env, request, "register", email, 5, 60 * 60 * 1000))) {
      return jsonError("Too many registration attempts. Please try again later.", 429, request);
    }
    if (password.length < 12) return jsonError("Password must be at least 12 characters.", 400, request);
    if (password.length > 200) return jsonError("Password is too long.", 400, request);
    const existing = await env.DB.prepare("SELECT id FROM customers WHERE email = ? COLLATE NOCASE").bind(email).first();
    if (existing) return jsonError("An account with this email already exists.", 409, request);
    const id = crypto.randomUUID();
    const salt = token();
    const storedHash = await passwordHash(password, salt);
    const now = new Date().toISOString();
    try {
      await env.DB.prepare(`INSERT INTO customers (id, email, email_verified, status, created_at, password_hash, password_salt) VALUES (?, ?, 0, 'active', ?, ?, ?)`)
        .bind(id, email, now, storedHash, salt).run();
      await ensureCustomerWallets(env, id);
    } catch (error) {
      if (String(error.message).toLowerCase().includes("unique")) return jsonError("An account with this email already exists.", 409, request);
      throw error;
    }
    const verification = await sendVerificationEmail(env, { id, email });
    return respond({ ok: true, message: verification.sent ? "Account created. Check your email for the 10-minute verification code." : "Account created, but email verification could not be sent yet.", verification_email_sent: verification.sent, verification_message: verification.reason || null, customer: { id, email, email_verified: false }, wallets: [{ currency: "NGN", balance_minor: 0 }, { currency: "USD", balance_minor: 0 }] }, 201, request);
  }

  if (method === "POST" && path === "/api/customer/verify-email") {
    const body = await readBody(request);
    if (!body) return jsonError("Invalid JSON.", 400, request);
    const email = String(body.email || "").trim().toLowerCase();
    const code = String(body.code || "").trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{6}$/.test(code)) return jsonError("Enter your email address and the 6-digit verification code.", 400, request);
    if (!(await allowAuthAttempt(env, request, "verify-email", email, 10, 10 * 60 * 1000))) {
      return jsonError("Too many verification attempts. Request a new code later.", 429, request);
    }
    const customer = await env.DB.prepare("SELECT id, email, email_verified FROM customers WHERE email = ? COLLATE NOCASE").bind(email).first();
    if (!customer) return jsonError("Invalid or expired verification code.", 400, request);
    if (Number(customer.email_verified) === 1) return respond({ ok: true, message: "Email is already verified." }, 200, request);
    const record = await env.DB.prepare(`SELECT id, code_hash, attempts, expires_at FROM customer_email_verifications WHERE customer_id = ? AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1`).bind(customer.id).first();
    if (!record || new Date(record.expires_at).getTime() <= Date.now() || Number(record.attempts) >= 5) return jsonError("Verification code is invalid or expired. Request a new code.", 400, request);
    const pepper = env.EMAIL_VERIFICATION_PEPPER || env.ENCRYPTION_KEY;
    if (!pepper) return jsonError("Email verification security is not configured.", 503, request);
    const suppliedHash = await hash(`${customer.id}:${code}:${pepper}`);
    if (!safeStringEqual(suppliedHash, record.code_hash)) {
      await env.DB.prepare("UPDATE customer_email_verifications SET attempts = attempts + 1 WHERE id = ? AND attempts < 5").bind(record.id).run();
      return jsonError("Incorrect verification code.", 400, request);
    }
    const now = new Date().toISOString();
    const consumeMarker = `${now}:${crypto.randomUUID()}`;
    const results = await env.DB.batch([
      env.DB.prepare(`UPDATE customer_email_verifications
        SET consumed_at=?
        WHERE id=? AND consumed_at IS NULL AND expires_at>? AND attempts<5`)
        .bind(consumeMarker, record.id, now),
      env.DB.prepare(`UPDATE customers SET email_verified=1
        WHERE id=? AND EXISTS (
          SELECT 1 FROM customer_email_verifications WHERE id=? AND consumed_at=?
        )`)
        .bind(customer.id, record.id, consumeMarker)
    ]);
    if (Number(results[0]?.meta?.changes || 0) !== 1 || Number(results[1]?.meta?.changes || 0) !== 1) {
      return jsonError("Verification code is invalid, expired, or already used. Request a new code.", 400, request);
    }
    return respond({ ok: true, message: "Email verified successfully. You can now sign in." }, 200, request);
  }

  if (method === "POST" && path === "/api/customer/resend-verification") {
    const body = await readBody(request);
    if (!body) return jsonError("Invalid JSON.", 400, request);
    const email = String(body.email || "").trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return jsonError("Enter a valid email address.", 400, request);
    if (!(await allowAuthAttempt(env, request, "resend-verification", email, 5, 60 * 60 * 1000))) {
      return jsonError("Too many requests. Please try again later.", 429, request);
    }
    const customer = await env.DB.prepare("SELECT id, email, email_verified FROM customers WHERE email = ? COLLATE NOCASE").bind(email).first();
    if (!customer) return respond({ ok: true, message: "If the account exists and needs verification, a code will be sent." }, 200, request);
    if (Number(customer.email_verified) === 1) return respond({ ok: true, message: "This email is already verified." }, 200, request);
    const verification = await sendVerificationEmail(env, customer);
    return respond({ ok: true, message: verification.sent ? "A new verification code has been sent." : (verification.reason || "Could not send a verification code."), verification_email_sent: verification.sent }, verification.sent ? 200 : 429, request);
  }

  if (method === "POST" && path === "/api/customer/login") {
    const body = await readBody(request);
    if (!body) return jsonError("Invalid JSON.", 400, request);
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!(await allowAuthAttempt(env, request, "customer-login", email, 10, 15 * 60 * 1000))) {
      return jsonError("Too many login attempts. Please wait and try again.", 429, request);
    }
    const customer = await env.DB.prepare(`SELECT id, email, password_hash, password_salt, email_verified, status FROM customers WHERE email = ? COLLATE NOCASE`).bind(email).first();
    if (!customer || customer.status !== "active" || !customer.password_hash || !customer.password_salt) return jsonError("Invalid email or password.", 401, request);
    if (Number(customer.email_verified) !== 1) return jsonError("Please verify your email address before signing in. You can request a new code if needed.", 403, request);
    const verifiedIterations = await verifyPassword(password, customer.password_salt, customer.password_hash, [100000, 210000]);
    if (!verifiedIterations) return jsonError("Invalid email or password.", 401, request);
    await ensureCustomerWallets(env, customer.id);
    const sessionToken = token();
    const now = new Date();
    const expiry = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    await env.DB.prepare(`INSERT INTO customer_sessions (id, customer_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`)
      .bind(crypto.randomUUID(), customer.id, await hash(sessionToken), expiry.toISOString(), now.toISOString()).run();
    return respond({ ok: true, token: sessionToken, expiresAt: expiry.toISOString(), customer: { id: customer.id, email: customer.email, email_verified: Boolean(customer.email_verified) } }, 200, request);
  }

  const customer = await getCustomer(request, env);
  if (!customer) return jsonError("Customer login required.", 401, request);

  if (method === "POST" && path === "/api/customer/logout") {
    const suppliedToken = (request.headers.get("Authorization") || "").slice(7);
    await env.DB.prepare("DELETE FROM customer_sessions WHERE token_hash = ?").bind(await hash(suppliedToken)).run();
    return respond({ ok: true }, 200, request);
  }

  if (method === "GET" && path === "/api/customer/me") {
    return respond({ ok: true, customer: { id: customer.id, email: customer.email, email_verified: Boolean(customer.email_verified), status: customer.status } }, 200, request);
  }

  if (method === "GET" && path === "/api/customer/wallets") {
    await ensureCustomerWallets(env, customer.id);
    const result = await env.DB.prepare(`SELECT currency, balance_minor, updated_at FROM wallets WHERE customer_id = ? ORDER BY CASE currency WHEN 'NGN' THEN 1 ELSE 2 END`).bind(customer.id).all();
    const setting = await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key = 'usd_ngn_rate'").first();
    const rate = Number(setting?.setting_value || 1500);
    return respond({ ok: true, wallets: result.results, exchange_rate_ngn_per_usd: rate, units: { NGN: "kobo", USD: "cents" } }, 200, request);
  }

  if (method === "GET" && path === "/api/customer/wallet") {
    await ensureCustomerWallets(env, customer.id);
    const result = await env.DB.prepare("SELECT currency, balance_minor, updated_at FROM wallets WHERE customer_id=? ORDER BY currency")
      .bind(customer.id).all();
    const setting = await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key='usd_ngn_rate'").first();
    const minor = { NGN: 0, USD: 0 };
    for (const row of result.results || []) minor[row.currency] = Number(row.balance_minor || 0);
    return respond({
      ok: true,
      // Major-unit balances preserve the simple wallet response contract.
      balances: { NGN: minor.NGN / 100, USD: minor.USD / 100 },
      balances_minor: minor,
      wallets: result.results || [],
      rate: Number(setting?.setting_value || 1500),
      units: { NGN: "kobo", USD: "cents" }
    }, 200, request);
  }

  if (method === "GET" && path === "/api/customer/wallet/transactions") {
    const result = await env.DB.prepare(`SELECT type, currency, amount_minor, status, reference, description, created_at
      FROM transactions WHERE customer_id=? ORDER BY created_at DESC LIMIT 100`).bind(customer.id).all();
    return respond({ ok: true, transactions: result.results || [] }, 200, request);
  }

  if (method === "POST" && path === "/api/customer/wallet/deposit") {
    const body = await readBody(request);
    const rawAmount = body?.amount;
    const amount = Number(rawAmount);
    // Wallet deposits are NGN major units; reject fractions smaller than one kobo
    // instead of silently rounding the amount sent to Flutterwave.
    if (!Number.isFinite(amount) || amount < 100 || amount > 5000000 ||
        !Number.isSafeInteger(Math.round(amount * 100)) ||
        Math.abs(amount * 100 - Math.round(amount * 100)) > 1e-7) {
      return jsonError("Deposit must be between ₦100 and ₦5,000,000, with no more than 2 decimal places.", 400, request);
    }
    if (!env.FLW_CLIENT_ID || !env.FLW_CLIENT_SECRET) {
      return jsonError("Flutterwave V4 production credentials are not configured. No deposit was created.", 503, request);
    }
    const amountMinor = Math.round(amount * 100);
    if (!Number.isSafeInteger(amountMinor)) return jsonError("Invalid deposit amount.", 400, request);
    await ensureCustomerWallets(env, customer.id);
    const reference = `SPD-${Date.now()}-${token().slice(0, 12)}`;
    const now = new Date().toISOString();
    await env.DB.prepare(`INSERT INTO wallet_deposits
      (id, customer_id, provider, provider_reference, currency, expected_amount_minor, status, created_at, updated_at)
      VALUES (?, ?, 'flutterwave', ?, 'NGN', ?, 'pending', ?, ?)`)
      .bind(crypto.randomUUID(), customer.id, reference, amountMinor, now, now).run();
    try {
      const accessToken = await flutterwaveAccessToken(env);
      const flwCustomerId = await getOrCreateFlutterwaveCustomer(env, customer, accessToken);
      const accountResponse = await flwV4Request(env, accessToken, "/virtual-accounts", {
        method: "POST",
        idempotencyKey: `spd-deposit-${reference}`,
        body: {
          reference,
          customer_id: flwCustomerId,
          amount,
          expiry: 1800,
          currency: "NGN",
          account_type: "dynamic",
          bank_code: "090567",
          narration: "Speedy.ng wallet funding"
        }
      });
      const account = accountResponse?.data || {};
      if (!account.account_number || !account.account_bank_name) {
        throw new Error("Flutterwave did not return complete virtual account details.");
      }
      const savedAccount = await env.DB.prepare(`UPDATE wallet_deposits
        SET virtual_account_number=?, virtual_account_bank=?,
            virtual_account_expires_at=?, payment_method='bank_transfer', provider_payload_json=?, updated_at=?
        WHERE provider_reference=? AND customer_id=? AND status='pending'`)
        .bind(String(account.account_number), String(account.account_bank_name), account.account_expiration_datetime || null,
          JSON.stringify(accountResponse).slice(0, 100000), new Date().toISOString(), reference, customer.id).run();
      if (Number(savedAccount?.meta?.changes || 0) !== 1) {
        throw new Error("Virtual-account details could not be saved to the deposit record.");
      }
      return respond({ ok: true, reference, amount, currency: "NGN", status: "pending",
        paymentInstructions: {
          accountNumber: String(account.account_number),
          bankName: String(account.account_bank_name),
          accountName: account.narration || "Speedy.ng",
          expiresAt: account.account_expiration_datetime || null,
          note: account.note || "Transfer the exact amount shown to this temporary account. Your wallet will be credited after Flutterwave confirms payment."
        }
      }, 201, request);
    } catch (error) {
      // Keep an ambiguous provider/network outcome in review instead of marking
      // it failed: Flutterwave may have created the virtual account before the
      // connection failed. A later valid webhook can still be reconciled.
      await env.DB.prepare("UPDATE wallet_deposits SET status='review', failure_reason=?, updated_at=? WHERE provider_reference=? AND credited_at IS NULL")
        .bind(String(error?.message || error).slice(0, 500), new Date().toISOString(), reference).run();
      return jsonError("Flutterwave could not confirm the bank-account creation. The deposit is held for reconciliation; do not transfer unless account details are displayed.", 502, request);
    }
  }

  if (method === "POST" && path === "/api/customer/wallet/convert") {
    const body = await readBody(request);
    if (!body) return jsonError("Invalid JSON.", 400, request);
    const from = String(body.from || "").toUpperCase();
    const to = String(body.to || "").toUpperCase();
    const amountMinor = Number(body.amount_minor);
    if (!((from === "NGN" && to === "USD") || (from === "USD" && to === "NGN"))) {
      return jsonError("Choose NGN to USD or USD to NGN.", 400, request);
    }
    if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) {
      return jsonError("Enter a valid amount in minor units.", 400, request);
    }
    const setting = await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key = 'usd_ngn_rate'").first();
    const rate = Number(setting?.setting_value || 1500);
    if (!Number.isFinite(rate) || rate <= 0) return jsonError("The exchange rate is not configured correctly.", 503, request);
    const convertedMinor = from === "NGN" ? Math.round(amountMinor / rate) : Math.round(amountMinor * rate);
    if (!Number.isSafeInteger(convertedMinor) || convertedMinor <= 0) return jsonError("The converted amount is too small.", 400, request);

    await ensureCustomerWallets(env, customer.id);
    const now = new Date().toISOString();
    const debitRef = `CONV-${crypto.randomUUID()}`;
    const creditRef = `CONV-${crypto.randomUUID()}`;
    const update = env.DB.prepare(`
      UPDATE wallets
      SET balance_minor = CASE
            WHEN currency = ? THEN balance_minor - ?
            WHEN currency = ? THEN balance_minor + ?
          END,
          updated_at = ?
      WHERE customer_id = ?
        AND currency IN (?, ?)
        AND (SELECT COUNT(*) FROM wallets WHERE customer_id=? AND currency IN (?, ?)) = 2
        AND EXISTS (
          SELECT 1 FROM wallets source
          WHERE source.customer_id=? AND source.currency=? AND source.balance_minor>=?
        )
    `).bind(
      from, amountMinor, to, convertedMinor, now, customer.id,
      from, to, customer.id, from, to, customer.id, from, amountMinor
    );
    const log = env.DB.prepare(`
      INSERT INTO transactions
        (id, customer_id, type, currency, amount_minor, status, reference, description, created_at)
      SELECT ?, CASE WHEN changes()=2 THEN ? ELSE NULL END,
             'conversion_debit', ?, ?, 'successful', ?, ?, ?
      UNION ALL
      SELECT ?, CASE WHEN changes()=2 THEN ? ELSE NULL END,
             'conversion_credit', ?, ?, 'successful', ?, ?, ?
    `).bind(
      crypto.randomUUID(), customer.id, from, -amountMinor, debitRef, `Wallet conversion ${from} to ${to}`, now,
      crypto.randomUUID(), customer.id, to, convertedMinor, creditRef, `Wallet conversion ${from} to ${to}`, now
    );

    try {
      const results = await env.DB.batch([update, log]);
      if (Number(results[0]?.meta?.changes || 0) !== 2 || Number(results[1]?.meta?.changes || 0) !== 2) {
        return jsonError(`Conversion could not be completed. Check your ${from} wallet balance and try again.`, 409, request);
      }
    } catch (error) {
      console.error("Wallet conversion rolled back:", error?.message || error);
      return jsonError(`Conversion could not be completed. Check your ${from} wallet balance and try again.`, 409, request);
    }

    const balances = await env.DB.prepare("SELECT currency, balance_minor FROM wallets WHERE customer_id = ? ORDER BY currency").bind(customer.id).all();
    return respond({ ok: true, conversion: { from, to, amount_minor: amountMinor, received_minor: convertedMinor, rate_ngn_per_usd: rate }, wallets: balances.results }, 200, request);
  }

  if (method === "GET" && path === "/api/customer/transactions") {
    const result = await env.DB.prepare(`SELECT type, currency, amount_minor, status, reference, description, created_at FROM transactions WHERE customer_id = ? ORDER BY created_at DESC LIMIT 100`).bind(customer.id).all();
    return respond({ ok: true, transactions: result.results }, 200, request);
  }
  return jsonError("Endpoint not found.", 404, request);
}


// YoungPG read-only provider adapters. Purchase mutations are intentionally
// excluded from this phase until each live account's catalogue is verified.
async function providerFetch(url, init = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    const text = await response.text();
    let data = text;
    try { data = JSON.parse(text); } catch {}
    if (!response.ok) {
      const retryAfter = response.headers.get('Retry-After');
      const error = new Error(`Provider returned HTTP ${response.status}`);
      error.status = response.status;
      error.retryAfter = retryAfter;
      error.providerBody = typeof data === 'string' ? data.slice(0, 500) : JSON.stringify(data).slice(0, 500);
      throw error;
    }
    return { data, status: response.status, retryAfter: response.headers.get('Retry-After') };
  } finally { clearTimeout(timer); }
}

function providerErrorMessage(error) {
  if (error?.name === 'AbortError') return 'Provider request timed out. No purchase was attempted.';
  if (error?.status === 429) return `Provider rate limit reached${error.retryAfter ? `. Retry after ${error.retryAfter} seconds` : ''}.`;
  return error?.message || 'Provider request failed.';
}

async function youngpgVirtualCall(env, action, params = {}) {
  if (!env.YOUNGPG_VIRTUAL_API_KEY) throw new Error('YoungPG Virtual API key is not configured.');
  if (!/^ypv_[a-f0-9]{64}$/i.test(env.YOUNGPG_VIRTUAL_API_KEY)) throw new Error('YoungPG Virtual API key format is invalid.');
  const url = new URL('https://youngpgvirtual.com/stubs/handler_api.php');
  url.searchParams.set('api_key', env.YOUNGPG_VIRTUAL_API_KEY);
  url.searchParams.set('action', action);
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== null && value !== '') url.searchParams.set(key, String(value));
  return providerFetch(url.toString());
}

async function youngpgMediaCall(env, endpoint, params = {}) {
  if (!env.YOUNGPG_MEDIA_API_KEY) throw new Error('YoungPG Media API key is not configured.');
  if (!/^ypg_[a-f0-9]{48}$/i.test(env.YOUNGPG_MEDIA_API_KEY)) throw new Error('YoungPG Media API key format is invalid.');
  const url = new URL(endpoint.replace(/^\//, ''), 'https://youngpgmedia.com.ng/api/v1/');
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== null && value !== '') url.searchParams.set(key, String(value));
  return providerFetch(url.toString(), { headers: { 'X-API-Key': env.YOUNGPG_MEDIA_API_KEY, 'Accept': 'application/json' } });
}

function providerEnvelope(data) {
  if (data && typeof data === 'object' && 'success' in data && data.success === false) {
    const error = new Error(String(data.message || 'Provider rejected the request.'));
    error.providerRejected = true;
    throw error;
  }
  return data && typeof data === 'object' && 'data' in data ? data.data : data;
}

async function recordProviderCheck(env, provider, product, ok, message) {
  const now = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO provider_configs
    (id, provider, product, base_url, api_key_enc, extra_enc, enabled, verification_status, last_test_at, last_test_message, updated_at)
    VALUES (?, ?, ?, ?, '', '', ?, ?, ?, ?, ?)
    ON CONFLICT(provider, product) DO UPDATE SET
      base_url=excluded.base_url, enabled=excluded.enabled,
      verification_status=excluded.verification_status,
      last_test_at=excluded.last_test_at, last_test_message=excluded.last_test_message,
      updated_at=excluded.updated_at`)
    .bind(crypto.randomUUID(), provider, product,
      provider === 'youngpg_virtual' ? 'https://youngpgvirtual.com/stubs/handler_api.php' : 'https://youngpgmedia.com.ng/api/v1/',
      ok ? 1 : 0, ok ? 'connected' : 'error', now, String(message).slice(0, 500), now).run();
}

let socialLogOrderSchemaReady;
async function ensureSocialLogOrderSchema(env) {
  if (!socialLogOrderSchemaReady) {
    socialLogOrderSchemaReady = (async () => {
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
        category TEXT NOT NULL, service TEXT, country TEXT, amount_minor INTEGER NOT NULL DEFAULT 0,
        currency TEXT NOT NULL DEFAULT 'USD', status TEXT NOT NULL DEFAULT 'pending',
        provider TEXT, provider_order_id TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
      )`).run();
      const info = await env.DB.prepare('PRAGMA table_info(orders)').all();
      const columns = new Set((info.results || []).map(row => row.name));
      const additions = [
        ['quantity', 'INTEGER NOT NULL DEFAULT 1'],
        ['unit_amount_minor', 'INTEGER NOT NULL DEFAULT 0'],
        ['provider_cost_ngn_minor', 'INTEGER NOT NULL DEFAULT 0'],
        ['provider_response_json', 'TEXT'],
        ['delivery_json', 'TEXT'],
        ['failure_reason', 'TEXT'],
        ['idempotency_key', 'TEXT']
      ];
      for (const [name, definition] of additions) {
        if (!columns.has(name)) {
          try { await env.DB.prepare(`ALTER TABLE orders ADD COLUMN ${name} ${definition}`).run(); }
          catch (error) { if (!String(error.message).toLowerCase().includes('duplicate column')) throw error; }
        }
      }
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS customer_order_requests (
        customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
        idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
        order_id TEXT NOT NULL REFERENCES orders(id), created_at TEXT NOT NULL,
        PRIMARY KEY(customer_id, idempotency_key)
      )`).run();
      await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_customer_created ON orders(customer_id, created_at DESC)').run();
    })().catch(error => { socialLogOrderSchemaReady = null; throw error; });
  }
  return socialLogOrderSchemaReady;
}

function unwrapListing(value) {
  if (!value || typeof value !== 'object') return null;
  if (value.listing && typeof value.listing === 'object') return value.listing;
  if (value.item && typeof value.item === 'object') return value.item;
  return value;
}

async function socialLogMarkup(env, listing) {
  const country = String(listing?.country_code || listing?.country || '*').trim().slice(0, 80) || '*';
  const service = String(listing?.service || listing?.category_slug || listing?.category || '*').trim().slice(0, 100) || '*';
  const result = await env.DB.prepare(`SELECT provider, product, country, service, markup_type, markup_value
    FROM pricing_rules WHERE active=1
      AND provider IN ('youngpg_media','*') AND product IN ('social_logs','*')
      AND country IN (?, '*') AND service IN (?, '*')
    ORDER BY CASE WHEN provider='youngpg_media' THEN 0 ELSE 1 END,
             CASE WHEN product='social_logs' THEN 0 ELSE 1 END,
             CASE WHEN country=? THEN 0 ELSE 1 END,
             CASE WHEN service=? THEN 0 ELSE 1 END LIMIT 1`).bind(country, service, country, service).first();
  return result || { markup_type: 'percent', markup_value: 0 };
}

async function getSocialLogOrder(env, customerId, orderId) {
  return env.DB.prepare(`SELECT id, category, service, country, quantity, amount_minor,
      unit_amount_minor, currency, status, failure_reason, created_at, updated_at, delivery_json
    FROM orders WHERE id=? AND customer_id=? AND category IN ('social_logs','social_boosting')`).bind(orderId, customerId).first();
}


async function refundLocalSocialLogOrder(env, customerId, orderId, amountMinor, reason) {
  const now = new Date().toISOString();
  const ref = `SL-REFUND-${orderId}`;
  const results = await env.DB.batch([
    env.DB.prepare(`UPDATE orders SET status='failed', failure_reason=?, updated_at=?
      WHERE id=? AND customer_id=? AND category='social_logs' AND status='processing'`)
      .bind(String(reason).slice(0, 500), now, orderId, customerId),
    env.DB.prepare(`UPDATE wallets SET balance_minor=balance_minor+?, updated_at=?
      WHERE customer_id=? AND currency='USD' AND changes()=1`)
      .bind(amountMinor, now, customerId),
    env.DB.prepare(`INSERT OR IGNORE INTO transactions
      (id, customer_id, type, currency, amount_minor, status, reference, description, created_at)
      SELECT ?, ?, 'social_log_purchase_refund', 'USD', ?, 'successful', ?, ?, ?
      WHERE changes()=1`)
      .bind(crypto.randomUUID(), customerId, amountMinor, ref, `Refund for unsuccessful Social Logs order ${orderId}`, now)
  ]);
  return Number(results[0]?.meta?.changes || 0) === 1;
}

async function socialLogOrderRoutes(request, env, url, path, method) {
  const orderPrefix = '/api/customer/orders/';
  const isOrderPath = path === '/api/customer/orders' || path.startsWith(orderPrefix);
  const isPurchasePath = path === '/api/customer/social-logs/purchase';
  if (!isOrderPath && !isPurchasePath) return null;
  const customer = await getCustomer(request, env);
  if (!customer) return jsonError('A verified customer login is required.', 401, request);
  await ensureCustomerWallets(env, customer.id);
  await ensureSocialLogOrderSchema(env);

  if (method === 'GET' && path === '/api/customer/orders') {
    await ensureVisualOrderSchema(env);
    const result = await env.DB.prepare(`SELECT id, category, service, country, quantity,
  amount_minor, currency, status, expires_at, created_at, updated_at
  FROM orders WHERE customer_id=? ORDER BY created_at DESC LIMIT 100`).bind(customer.id).all();
    return respond({ ok: true, orders: result.results || [] }, 200, request);
  }
  if (method === 'GET' && path.startsWith(orderPrefix)) {
    let orderId;
    try { orderId = decodeURIComponent(path.slice(orderPrefix.length)); } catch { return jsonError('Invalid order ID.', 400, request); }
    if (!orderId || orderId.includes('/')) return jsonError('Invalid order ID.', 400, request);
    const order = await getSocialLogOrder(env, customer.id, orderId);
    if (!order) return jsonError('Order not found.', 404, request);
    let delivery = null;
    try { delivery = order.delivery_json ? JSON.parse(order.delivery_json) : null; } catch {}
    delete order.delivery_json;
    return respond({ ok: true, order, delivery }, 200, request);
  }
  if (method !== 'POST' || !isPurchasePath) return jsonError('Method not allowed.', 405, request);

  const body = await readBody(request);
  if (!body) return jsonError('Invalid JSON.', 400, request);
  const slug = String(body.slug || '').trim();
  const quantity = Number(body.quantity || 1);
  const idempotencyKey = String(request.headers.get('Idempotency-Key') || body.idempotency_key || '').trim();
  if (!/^[a-zA-Z0-9_-]{3,120}$/.test(slug)) return jsonError('Choose a valid Social Logs listing.', 400, request);
  if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 10) return jsonError('Quantity must be between 1 and 10.', 400, request);
  if (!/^[a-zA-Z0-9._:-]{16,120}$/.test(idempotencyKey)) return jsonError('A unique Idempotency-Key is required for each purchase.', 400, request);
  const requestHash = await hash(`${slug}:${quantity}`);
  const prior = await env.DB.prepare(`SELECT r.request_hash, o.id FROM customer_order_requests r
    JOIN orders o ON o.id=r.order_id WHERE r.customer_id=? AND r.idempotency_key=?`)
    .bind(customer.id, idempotencyKey).first();
  if (prior) {
    if (prior.request_hash !== requestHash) return jsonError('This purchase key was already used for a different request.', 409, request);
    const existing = await getSocialLogOrder(env, customer.id, prior.id);
    let delivery = null;
    try { delivery = existing?.delivery_json ? JSON.parse(existing.delivery_json) : null; } catch {}
    if (existing) delete existing.delivery_json;
    return respond({ ok: true, duplicate_request: true, order: existing, delivery }, 200, request);
  }

  try {
    // Fetch authoritative listing price and stock before reserving customer funds.
    const detailResponse = await youngpgMediaCall(env, `listings/${encodeURIComponent(slug)}`);
    const listing = unwrapListing(providerEnvelope(detailResponse.data));
    const priceNgn = Number(listing?.price_ngn);
    const stock = Number(listing?.available_stock);
    if (!listing || !Number.isFinite(priceNgn) || priceNgn <= 0) return jsonError('The listing price could not be verified. No funds were taken.', 502, request);
    if (Number.isFinite(stock) && stock < quantity) return jsonError('There is not enough stock for this quantity. No funds were taken.', 409, request);

    const settings = await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key='usd_ngn_rate'").first();
    const rate = Number(settings?.setting_value || 1500);
    if (!Number.isFinite(rate) || rate <= 0) return jsonError('The NGN/USD exchange rate is not configured.', 503, request);
    const markup = await socialLogMarkup(env, listing);
    const baseUsd = priceNgn / rate;
    const markupValue = Number(markup.markup_value || 0);
    const unitUsd = markup.markup_type === 'fixed' ? baseUsd + markupValue : baseUsd * (1 + markupValue / 100);
    const unitMinor = Math.round(unitUsd * 100);
    const totalMinor = unitMinor * quantity;
    const costNgnMinor = Math.round(priceNgn * quantity * 100);
    if (!Number.isSafeInteger(totalMinor) || totalMinor <= 0 || !Number.isSafeInteger(costNgnMinor)) return jsonError('The listing price is invalid. No funds were taken.', 502, request);

    const orderId = crypto.randomUUID();
    const now = new Date().toISOString();
    const category = String(listing.category_name || listing.category || 'Social Logs').slice(0, 100);
    const orderService = String(listing.title || listing.name || slug).slice(0, 160);
    const reserve = await env.DB.batch([
      env.DB.prepare(`INSERT INTO orders
        (id, customer_id, category, service, country, amount_minor, currency, status, provider,
         created_at, updated_at, quantity, unit_amount_minor, provider_cost_ngn_minor, idempotency_key)
        VALUES (?, ?, 'social_logs', ?, NULL, ?, 'USD', 'processing', 'youngpg_media', ?, ?, ?, ?, ?, ?)`)
        .bind(orderId, customer.id, orderService, totalMinor, now, now, quantity, unitMinor, costNgnMinor, idempotencyKey),
      env.DB.prepare(`UPDATE wallets SET balance_minor=balance_minor-?, updated_at=?
        WHERE customer_id=? AND currency='USD' AND balance_minor>=?
          AND EXISTS (SELECT 1 FROM orders WHERE id=? AND customer_id=? AND status='processing')`)
        .bind(totalMinor, now, customer.id, totalMinor, orderId, customer.id),
      env.DB.prepare(`DELETE FROM orders WHERE id=? AND customer_id=? AND changes()=0`)
        .bind(orderId, customer.id),
      env.DB.prepare(`INSERT INTO transactions
        (id, customer_id, type, currency, amount_minor, status, reference, description, created_at)
        SELECT ?, ?, 'social_log_purchase', 'USD', ?, 'pending', ?, ?, ?
        WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND customer_id=? AND status='processing')`)
        .bind(crypto.randomUUID(), customer.id, -totalMinor, `SL-${orderId}`, `Social Logs purchase: ${orderService}`, now, orderId, customer.id),
      env.DB.prepare(`INSERT INTO customer_order_requests (customer_id, idempotency_key, request_hash, order_id, created_at)
        SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND customer_id=?)`)
        .bind(customer.id, idempotencyKey, requestHash, orderId, now, orderId, customer.id)
    ]);
    if (Number(reserve[1]?.meta?.changes || 0) !== 1) {
      return jsonError('Your USD wallet balance is not enough for this order.', 409, request);
    }

    let purchaseResult;
    try {
      purchaseResult = await providerFetch('https://youngpgmedia.com.ng/api/v1/purchase', {
        method: 'POST',
        headers: { 'X-API-Key': env.YOUNGPG_MEDIA_API_KEY, 'Accept': 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify({ slug, quantity })
      });
    } catch (error) {
      if (error.providerRejected || (Number(error.status) >= 400 && Number(error.status) < 500)) {
        await refundLocalSocialLogOrder(env, customer.id, orderId, totalMinor, providerErrorMessage(error));
        await env.DB.prepare("UPDATE transactions SET status='failed' WHERE reference=? AND status='pending'").bind(`SL-${orderId}`).run();
        return jsonError(`The listing provider declined the order. Your USD wallet has been restored. ${providerErrorMessage(error)}`, 502, request);
      }
      await env.DB.prepare(`UPDATE orders SET status='review', failure_reason=?, updated_at=? WHERE id=? AND status='processing'`)
        .bind('Provider purchase outcome is uncertain. The request was not retried to prevent a duplicate order.', new Date().toISOString(), orderId).run();
      return respond({ ok: false, order_id: orderId, status: 'review', message: 'The purchase response was uncertain. Your funds are held safely while the order is checked. Do not submit another purchase.' }, 202, request);
    }

    const raw = purchaseResult.data;
    let data;
    try { data = providerEnvelope(raw); }
    catch (error) {
      await refundLocalSocialLogOrder(env, customer.id, orderId, totalMinor, error.message);
      await env.DB.prepare("UPDATE transactions SET status='failed' WHERE reference=? AND status='pending'").bind(`SL-${orderId}`).run();
      return jsonError(`The listing provider rejected the order. Your USD wallet has been restored. ${error.message}`, 502, request);
    }
    const providerOrderId = data?.order_id == null ? null : String(data.order_id);
    const accounts = Array.isArray(data?.accounts) ? data.accounts : null;
    if (!providerOrderId || !accounts || accounts.length !== quantity) {
      await env.DB.prepare(`UPDATE orders SET status='review', provider_order_id=?, provider_response_json=?,
        failure_reason=?, updated_at=? WHERE id=? AND status='processing'`)
        .bind(providerOrderId, JSON.stringify(raw).slice(0, 100000), 'Provider accepted or may have accepted the purchase, but its delivery response was incomplete. Manual reconciliation is required.', new Date().toISOString(), orderId).run();
      return respond({ ok: false, order_id: orderId, status: 'review', message: 'The provider response needs a manual delivery check. Your funds remain reserved; do not retry this order.' }, 202, request);
    }

    const completedAt = new Date().toISOString();
    const delivery = { accounts };
    await env.DB.batch([
      env.DB.prepare(`UPDATE orders SET status='completed', provider_order_id=?, provider_response_json=?,
        delivery_json=?, updated_at=? WHERE id=? AND customer_id=? AND status='processing'`)
        .bind(providerOrderId, JSON.stringify(raw).slice(0, 100000), JSON.stringify(delivery).slice(0, 100000), completedAt, orderId, customer.id),
      env.DB.prepare("UPDATE transactions SET status='successful' WHERE reference=? AND status='pending'")
        .bind(`SL-${orderId}`)
    ]);
    const order = await getSocialLogOrder(env, customer.id, orderId);
    if (order) delete order.delivery_json;
    return respond({ ok: true, order, delivery }, 201, request);
  } catch (error) {
    console.error('Social Logs purchase flow failed:', error?.message || error);
    return jsonError(`The Social Logs order could not be prepared. ${providerErrorMessage(error)}`, error?.status === 429 ? 429 : 502, request);
  }
}

let visualOrderSchemaReady;
async function ensureVisualOrderSchema(env) {
  if (!visualOrderSchemaReady) {
    visualOrderSchemaReady = (async () => {
      await ensureSocialLogOrderSchema(env);
      const info = await env.DB.prepare('PRAGMA table_info(orders)').all();
      const columns = new Set((info.results || []).map(row => row.name));
      const additions = [
        ['provider_phone', 'TEXT'], ['provider_service_code', 'TEXT'],
        ['provider_country_code', 'TEXT'], ['provider_status', 'TEXT'], ['expires_at', 'TEXT'],
        ['provider_cancel_at', 'TEXT'], ['provider_refund_confirmed', 'INTEGER NOT NULL DEFAULT 0'],
        ['provider_refund_at', 'TEXT']
      ];
      for (const [name, definition] of additions) {
        if (!columns.has(name)) {
          try { await env.DB.prepare(`ALTER TABLE orders ADD COLUMN ${name} ${definition}`).run(); }
          catch (error) { if (!String(error.message).toLowerCase().includes('duplicate column')) throw error; }
        }
      }
      await env.DB.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_visual_provider_id ON orders(provider, provider_order_id) WHERE provider_order_id IS NOT NULL').run();
    })().catch(error => { visualOrderSchemaReady = null; throw error; });
  }
  return visualOrderSchemaReady;
}

function parseProviderJson(value) {
  if (typeof value === 'string') { try { return JSON.parse(value); } catch { return value; } }
  return value;
}
function visualPriceEntry(raw, country, service) {
  const data = parseProviderJson(raw);
  if (!data || typeof data !== 'object') return null;
  const root = providerEnvelope(data);
  const candidates = [];
  const add = value => { if (value && typeof value === 'object') candidates.push(value); };
  const countryNode = root[country] ?? root[String(country)];
  if (countryNode && typeof countryNode === 'object') {
    add(countryNode[service] ?? countryNode[String(service)]);
    add(countryNode.services?.[service]);
  }
  add(root[service]?.[country]);
  add(root[service]);
  if (Array.isArray(root)) {
    for (const item of root) {
      if (!item || typeof item !== 'object') continue;
      const c = String(item.country ?? item.country_id ?? item.country_code ?? '');
      const s = String(item.service ?? item.service_code ?? item.code ?? '');
      if (c === String(country) && s === String(service)) add(item);
    }
  }
  for (const candidate of candidates) {
    const costRaw = candidate.cost ?? candidate.price_ngn ?? candidate.price ?? candidate.amount ?? candidate.retail_price;
    const cost = Number(costRaw);
    if (Number.isFinite(cost) && cost > 0) {
      const stockRaw = candidate.count ?? candidate.stock ?? candidate.available ?? candidate.quantity;
      const stock = stockRaw == null ? null : Number(stockRaw);
      return { cost_ngn: cost, stock: Number.isFinite(stock) ? stock : null };
    }
    for (const [key, value] of Object.entries(candidate)) {
      if (String(key) === String(service) && value && typeof value === 'object') {
        const nested = visualPriceEntry({ [country]: { [service]: value } }, country, service);
        if (nested) return nested;
      }
    }
  }
  return null;
}

async function visualMarkup(env, country, service) {
  const result = await env.DB.prepare(`SELECT markup_type, markup_value FROM pricing_rules WHERE active=1
    AND provider IN ('youngpg_virtual','*') AND product IN ('visual_numbers','*')
    AND country IN (?, '*') AND service IN (?, '*')
    ORDER BY CASE WHEN provider='youngpg_virtual' THEN 0 ELSE 1 END,
      CASE WHEN product='visual_numbers' THEN 0 ELSE 1 END,
      CASE WHEN country=? THEN 0 ELSE 1 END,
      CASE WHEN service=? THEN 0 ELSE 1 END LIMIT 1`).bind(String(country), String(service), String(country), String(service)).first();
  return result || { markup_type: 'percent', markup_value: 0 };
}

async function getVisualOrder(env, customerId, orderId) {
  return env.DB.prepare(`SELECT id, category, service, country, quantity, amount_minor, unit_amount_minor,
    currency, status, provider, provider_order_id, provider_phone, provider_service_code,
    provider_country_code, provider_status, expires_at, provider_cancel_at, provider_refund_confirmed, provider_refund_at, failure_reason, created_at, updated_at, delivery_json
    FROM orders WHERE id=? AND customer_id=? AND category='visual_numbers'`).bind(orderId, customerId).first();
}

async function confirmVisualProviderRefund(env, orderId, providerStatus, reason) {
  const now = new Date().toISOString();
  const result = await env.DB.prepare(`UPDATE orders SET provider_refund_confirmed=1, provider_refund_at=?,
    provider_status=?, failure_reason=?, updated_at=?
    WHERE id=? AND category='visual_numbers' AND status IN ('processing','review')
      AND COALESCE(provider_refund_confirmed,0)=0`)
    .bind(now, String(providerStatus || 'STATUS_CANCEL').slice(0, 120), String(reason || 'Provider cancellation confirmed.').slice(0, 500), now, orderId).run();
  return Number(result?.meta?.changes || 0) === 1;
}

async function refundVisualOrder(env, customerId, orderId, reason) {
  const order = await getVisualOrder(env, customerId, orderId);
  if (!order || !['processing', 'review'].includes(order.status)) return false;
  if (Number(order.provider_refund_confirmed || 0) !== 1) return false;
  if (!order.expires_at || Date.now() < Date.parse(order.expires_at)) return false;
  const now = new Date().toISOString();
  const ref = `VN-REFUND-${orderId}`;
  const result = await env.DB.batch([
    env.DB.prepare(`UPDATE orders SET status='failed', failure_reason=?, updated_at=?
      WHERE id=? AND customer_id=? AND category='visual_numbers' AND status IN ('processing','review')
        AND provider_refund_confirmed=1 AND expires_at<=?`)
      .bind(String(reason).slice(0, 500), now, orderId, customerId, now),
    env.DB.prepare(`UPDATE wallets SET balance_minor=balance_minor+?, updated_at=?
      WHERE customer_id=? AND currency='USD' AND changes()=1`)
      .bind(Number(order.amount_minor), now, customerId),
    env.DB.prepare(`INSERT OR IGNORE INTO transactions
      (id, customer_id, type, currency, amount_minor, status, reference, description, created_at)
      SELECT ?, ?, 'visual_number_refund', 'USD', ?, 'successful', ?, ?, ? WHERE changes()=1`)
      .bind(crypto.randomUUID(), customerId, Number(order.amount_minor), ref, `Refund for Visual Numbers order ${orderId}`, now)
  ]);
  const changed = Number(result[0]?.meta?.changes || 0) === 1;
  if (changed) await env.DB.prepare("UPDATE transactions SET status='failed' WHERE reference=? AND status='pending'").bind(`VN-${orderId}`).run();
  return changed;
}

async function attemptVisualProviderCancellation(env, order) {
  if (!order?.provider_order_id || !order.id) return { confirmed: false, reason: 'missing_provider_reference' };
  const now = Date.now();
  if (Number(order.provider_refund_confirmed || 0) === 1) return { confirmed: true, reason: 'already_confirmed' };
  // Poll for a code throughout the rental, not only near expiry. A delivered code always wins over cancellation.
  const statusResponse = await youngpgVirtualCall(env, 'getStatus', { id: order.provider_order_id });
  const token = String(statusResponse.data || '').trim();
  const codeMatch = token.match(/^STATUS_OK:(.+)$/);
  if (codeMatch && /^[a-zA-Z0-9-]{3,80}$/.test(codeMatch[1].trim())) {
    const delivery = { phone_number: order.provider_phone, sms_code: codeMatch[1].trim() };
    const changed = await env.DB.prepare(`UPDATE orders SET status='completed', provider_status=?, delivery_json=?, updated_at=?
      WHERE id=? AND status IN ('processing','review')`).bind(token, JSON.stringify(delivery), new Date().toISOString(), order.id).run();
    if (Number(changed?.meta?.changes || 0) === 1) {
      await env.DB.prepare("UPDATE transactions SET status='successful' WHERE reference=? AND status='pending'").bind(`VN-${order.id}`).run();
      try { await youngpgVirtualCall(env, 'setStatus', { id: order.provider_order_id, status: 6 }); } catch {}
    }
    return { confirmed: false, completed: true, reason: 'sms_received' };
  }
  if (token === 'STATUS_CANCEL') {
    await confirmVisualProviderRefund(env, order.id, token, 'Provider reports this rental has been cancelled.');
    return { confirmed: true, reason: 'provider_cancelled' };
  }
  if (token !== 'STATUS_WAIT_CODE') return { confirmed: false, reason: token || 'unknown_provider_status' };
  const cancelAt = order.provider_cancel_at ? Date.parse(order.provider_cancel_at)
    : (order.expires_at ? Date.parse(order.expires_at) - 15000 : now);
  if (Number.isFinite(cancelAt) && now < cancelAt) return { confirmed: false, reason: 'not_due' };
  const cancelResponse = await youngpgVirtualCall(env, 'setStatus', { id: order.provider_order_id, status: 8 });
  const cancelToken = String(cancelResponse.data || '').trim();
  if (cancelToken.startsWith('ACCESS_') || cancelToken === 'STATUS_CANCEL') {
    // Close the race where an SMS arrives between the first status check and
    // the provider cancellation request. Never unlock a refund if a code won.
    const finalStatusResponse = await youngpgVirtualCall(env, 'getStatus', { id: order.provider_order_id });
    const finalToken = String(finalStatusResponse.data || '').trim();
    const finalCode = finalToken.match(/^STATUS_OK:(.+)$/);
    if (finalCode && /^[a-zA-Z0-9-]{3,80}$/.test(finalCode[1].trim())) {
      const delivery = { phone_number: order.provider_phone, sms_code: finalCode[1].trim() };
      const completed = await env.DB.prepare(`UPDATE orders SET status='completed', provider_status=?, delivery_json=?, updated_at=?
        WHERE id=? AND status IN ('processing','review')`)
        .bind(finalToken, JSON.stringify(delivery), new Date().toISOString(), order.id).run();
      if (Number(completed?.meta?.changes || 0) === 1) {
        await env.DB.prepare("UPDATE transactions SET status='successful' WHERE reference=? AND status='pending'").bind(`VN-${order.id}`).run();
        try { await youngpgVirtualCall(env, 'setStatus', { id: order.provider_order_id, status: 6 }); } catch {}
      }
      return { confirmed: false, completed: true, reason: 'sms_received_during_cancellation' };
    }
    if (finalToken === 'STATUS_CANCEL') {
      await confirmVisualProviderRefund(env, order.id, finalToken, 'Provider cancellation was confirmed. Customer refund is available after the countdown ends.');
      return { confirmed: true, reason: 'provider_cancel_confirmed' };
    }
    // ACCESS_CANCEL from setStatus is not enough on its own for customer
    // credit: wait for getStatus to independently report STATUS_CANCEL.
    await env.DB.prepare(`UPDATE orders SET provider_status=?, failure_reason=?, updated_at=? WHERE id=? AND status IN ('processing','review')`)
      .bind(finalToken.slice(0, 120), 'Cancellation was requested, but the provider has not yet independently confirmed the cancelled status. Customer funds remain protected.', new Date().toISOString(), order.id).run();
    return { confirmed: false, reason: 'awaiting_provider_cancellation_confirmation' };
  }
  await env.DB.prepare('UPDATE orders SET provider_status=?, failure_reason=?, updated_at=? WHERE id=? AND status IN (\'processing\',\'review\')')
    .bind(cancelToken.slice(0, 120), 'Provider cancellation is not confirmed yet. Customer funds remain reserved.', new Date().toISOString(), order.id).run();
  return { confirmed: false, reason: cancelToken || 'provider_not_confirmed' };
}

async function visualRefundTimerDates(env, baseTime = Date.now()) {
  const customerSetting = await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key='visual_number_customer_refund_seconds'").first();
  const supplierSetting = await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key='visual_number_supplier_cancel_seconds'").first();
  const customerSeconds = Math.min(3600, Math.max(30, Number(customerSetting?.setting_value || 270)));
  const supplierSeconds = Math.min(customerSeconds, Math.max(0, Number(supplierSetting?.setting_value || 255)));
  return {
    providerCancelAt: new Date(baseTime + supplierSeconds * 1000).toISOString(),
    customerRefundAt: new Date(baseTime + customerSeconds * 1000).toISOString()
  };
}

async function visualNumberOrderRoutes(request, env, url, path, method) {
  const base = '/api/customer/visual-numbers';
  const isPurchase = path === `${base}/purchase`;
  const isOrders = path === `${base}/orders` || path.startsWith(`${base}/orders/`);
  const isQuote = path === `${base}/quote`;
  if (!isPurchase && !isOrders && !isQuote) return null;
  const customer = await getCustomer(request, env);
  if (!customer) return jsonError('A verified customer login is required.', 401, request);
  await ensureCustomerWallets(env, customer.id);
  await ensureVisualOrderSchema(env);

  if (isQuote && method === 'GET') {
    const country = String(url.searchParams.get('country') || '').trim();
    const service = String(url.searchParams.get('service') || '').trim();
    if (!/^[a-zA-Z0-9_-]{1,40}$/.test(country) || !/^[a-zA-Z0-9_-]{1,40}$/.test(service)) return jsonError('Choose a valid country and service.', 400, request);
    let result;
    try { result = await youngpgVirtualCall(env, 'getPrices', { country, service }); }
    catch (error) { return jsonError(providerErrorMessage(error), error?.status === 429 ? 429 : 502, request); }
    const price = visualPriceEntry(result.data, country, service);
    if (!price) return jsonError('The provider price format could not be verified. No purchase is available for this selection yet.', 502, request);
    const setting = await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key='usd_ngn_rate'").first();
    const rate = Number(setting?.setting_value || 1500);
    if (!Number.isFinite(rate) || rate <= 0) return jsonError('The NGN/USD exchange rate is not configured.', 503, request);
    const markup = await visualMarkup(env, country, service);
    const baseUsd = price.cost_ngn / rate;
    const value = Number(markup.markup_value || 0);
    const unitUsd = markup.markup_type === 'fixed' ? baseUsd + value : baseUsd * (1 + value / 100);
    const unitMinor = Math.round(unitUsd * 100);
    if (!Number.isSafeInteger(unitMinor) || unitMinor <= 0) return jsonError('The calculated price is invalid.', 502, request);
    return respond({
  ok: true,
  quote: {
    country,
    service,
    stock: price.stock,
    exchange_rate_ngn_per_usd: rate,
    customer_price_minor: unitMinor,
    currency: 'USD'
  }
}, 200, request);
  }

  if (isOrders && path.startsWith(`${base}/orders/`)) {
    const suffix = path.slice(`${base}/orders/`.length);
    const parts = suffix.split('/');
    let orderId;
    try { orderId = decodeURIComponent(parts[0]); } catch { return jsonError('Invalid order ID.', 400, request); }
    if (!orderId || orderId.includes('/')) return jsonError('Invalid order ID.', 400, request);
    const order = await getVisualOrder(env, customer.id, orderId);
    if (!order) return jsonError('Order not found.', 404, request);
    if (method === 'GET' && parts.length === 1) {
      let delivery = null; try { delivery = order.delivery_json ? JSON.parse(order.delivery_json) : null; } catch {}
      delete order.delivery_json;
      return respond({ ok: true, order: customerSafeOrder(order), delivery }, 200, request);
    }
    if (method !== 'POST' || parts.length !== 2 || !['check','cancel'].includes(parts[1])) return jsonError('Method not allowed.', 405, request);
    if (!order.provider_order_id) return respond({ ok: false, status: order.status, message: 'This order has no confirmed provider rental ID and needs reconciliation. Do not place it again.' }, 202, request);
    if (order.status === 'completed' || order.status === 'failed') {
      let delivery = null; try { delivery = order.delivery_json ? JSON.parse(order.delivery_json) : null; } catch {}
      return respond({ ok: true, order: { ...order, delivery_json: undefined }, delivery }, 200, request);
    }
    if (parts[1] === 'cancel') {
      if (!order.expires_at || Date.now() < Date.parse(order.expires_at)) {
        return respond({ ok: false, status: order.status, refund_available_at: order.expires_at, message: 'Your refund button becomes available when the countdown reaches zero.' }, 409, request);
      }
      if (Number(order.provider_refund_confirmed || 0) !== 1) {
        try { await attemptVisualProviderCancellation(env, order); } catch (error) { console.error('Provider cancellation check deferred:', error?.message || error); }
        const latest = await getVisualOrder(env, customer.id, orderId);
        if (latest?.status === 'completed') return respond({ ok: true, order: latest, refunded: false, message: 'Your SMS code arrived. This order is successful and cannot be refunded.' }, 200, request);
        if (Number(latest?.provider_refund_confirmed || 0) !== 1) return respond({ ok: false, status: latest?.status || order.status, message: 'We are still waiting for the provider to confirm the cancellation. Your money remains protected.' }, 409, request);
      }
      const refunded = await refundVisualOrder(env, customer.id, orderId, 'Customer requested refund after provider confirmation and countdown completion.');
      const updated = await getVisualOrder(env, customer.id, orderId);
      return respond({ ok: true, order: customerSafeOrder(updated), refunded, message: refunded ? 'Your refund has been added to your USD wallet.' : 'This order has already changed state or been refunded.' }, 200, request);
    }
    const statusResult = await youngpgVirtualCall(env, 'getStatus', { id: order.provider_order_id });
    const token = String(statusResult.data || '').trim();
    if (token === 'STATUS_WAIT_CODE') {
      await env.DB.prepare("UPDATE orders SET provider_status=?, updated_at=? WHERE id=? AND customer_id=? AND status IN ('processing','review')")
        .bind(token, new Date().toISOString(), orderId, customer.id).run();
      if (order.provider_cancel_at && Date.now() >= Date.parse(order.provider_cancel_at)) {
        try { const result = await attemptVisualProviderCancellation(env, order); const latest = await getVisualOrder(env, customer.id, orderId);
          if (result.completed || latest?.status === 'completed') return respond({ ok: true, status: 'completed', order: customerSafeOrder(latest), message: 'Your SMS code arrived. This order is successful.' }, 200, request);
          return respond({ ok: true, status: 'waiting', provider_refund_confirmed: Number(latest?.provider_refund_confirmed || 0) === 1, refund_available: Boolean(latest?.expires_at && Date.now() >= Date.parse(latest.expires_at) && Number(latest?.provider_refund_confirmed || 0) === 1), order: customerSafeOrder(latest), message: Number(latest?.provider_refund_confirmed || 0) === 1 ? 'Provider cancellation confirmed. Refund unlocks when the countdown reaches zero.' : 'The provider cancellation is being checked.' }, 200, request);
        } catch (error) { console.error('Scheduled provider cancellation check failed:', error?.message || error); }
      }
      return respond({ ok: true, status: 'waiting', provider_status: token, order_id: orderId, refund_available: false }, 200, request);
    }
    if (token === 'STATUS_CANCEL') {
      await confirmVisualProviderRefund(env, orderId, token, 'Provider confirmed that the rental is cancelled. Customer refund becomes available when the countdown reaches zero.');
      const updated = await getVisualOrder(env, customer.id, orderId);
      const refundReady = Boolean(updated && Number(updated.provider_refund_confirmed) === 1 && updated.expires_at && Date.now() >= Date.parse(updated.expires_at));
      return respond({ ok: true, status: updated?.status || 'processing', order: customerSafeOrder(updated), refund_available: refundReady,
        message: refundReady ? 'Provider cancellation confirmed. Your refund is ready.' : 'Provider cancellation confirmed. Your refund becomes available when the countdown reaches zero.' }, 200, request);
    }
    const match = token.match(/^STATUS_OK:(.+)$/);
    if (match) {
      const code = match[1].trim();
      if (!/^[a-zA-Z0-9-]{3,80}$/.test(code)) return respond({ ok: false, status: 'review', message: 'The provider returned an unexpected code format. Your order is retained for review.' }, 202, request);
      // The code is saved before acknowledging completion, so a transient completion call cannot lose it.
      const delivery = { phone_number: order.provider_phone, sms_code: code };
      await env.DB.batch([
        env.DB.prepare(`UPDATE orders SET status='completed', provider_status=?, delivery_json=?, updated_at=?
          WHERE id=? AND customer_id=? AND category='visual_numbers' AND status IN ('processing','review')`)
          .bind(token, JSON.stringify(delivery), new Date().toISOString(), orderId, customer.id),
        env.DB.prepare("UPDATE transactions SET status='successful' WHERE reference=? AND status='pending' AND EXISTS (SELECT 1 FROM orders WHERE id=? AND status='completed')").bind(`VN-${orderId}`, orderId)
      ]);
      try { await youngpgVirtualCall(env, 'setStatus', { id: order.provider_order_id, status: 6 }); } catch (error) { console.error('YoungPG completion acknowledgement pending:', error?.message || error); }
      const updated = await getVisualOrder(env, customer.id, orderId);
     return respond({ ok: true, status: 'completed', order: customerSafeOrder(updated), delivery }, 200, request); 
    }
    return respond({ ok: false, status: 'review', provider_status: token.slice(0, 120), message: 'The provider returned an unrecognised status. Your funds remain reserved.' }, 202, request);
  }

  if (method !== 'POST' || !isPurchase) return jsonError('Method not allowed.', 405, request);
  const body = await readBody(request);
  if (!body) return jsonError('Invalid JSON.', 400, request);
  const country = String(body.country || '').trim();
  const service = String(body.service || '').trim();
  const idempotencyKey = String(request.headers.get('Idempotency-Key') || body.idempotency_key || '').trim();
  if (!/^[a-zA-Z0-9_-]{1,40}$/.test(country) || !/^[a-zA-Z0-9_-]{1,40}$/.test(service)) return jsonError('Choose a valid country and service.', 400, request);
  if (!/^[a-zA-Z0-9._:-]{16,120}$/.test(idempotencyKey)) return jsonError('A unique Idempotency-Key is required for each rental.', 400, request);
  const requestHash = await hash(`${country}:${service}`);
  const prior = await env.DB.prepare(`SELECT r.request_hash, o.id FROM customer_order_requests r JOIN orders o ON o.id=r.order_id
    WHERE r.customer_id=? AND r.idempotency_key=?`).bind(customer.id, idempotencyKey).first();
  if (prior) {
    if (prior.request_hash !== requestHash) return jsonError('This purchase key was already used for a different rental.', 409, request);
    const existing = await getVisualOrder(env, customer.id, prior.id);
    let delivery = null; try { delivery = existing?.delivery_json ? JSON.parse(existing.delivery_json) : null; } catch {}
    if (existing) delete existing.delivery_json;
    return respond({ ok: true, duplicate_request: true, order: customerSafeOrder(existing), delivery }, 200, request);
  }

  let quoteResponse;
  try { quoteResponse = await youngpgVirtualCall(env, 'getPrices', { country, service }); }
  catch (error) { return jsonError(providerErrorMessage(error), error?.status === 429 ? 429 : 502, request); }
  const price = visualPriceEntry(quoteResponse.data, country, service);
  if (!price) return jsonError('The live provider price could not be verified. No funds were taken.', 502, request);
  if (price.stock !== null && price.stock < 1) return jsonError('This service is currently out of stock. No funds were taken.', 409, request);
  const setting = await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key='usd_ngn_rate'").first();
  const rate = Number(setting?.setting_value || 1500);
  if (!Number.isFinite(rate) || rate <= 0) return jsonError('The NGN/USD exchange rate is not configured.', 503, request);
  const markup = await visualMarkup(env, country, service);
  const baseUsd = price.cost_ngn / rate;
  const markupValue = Number(markup.markup_value || 0);
  const totalMinor = Math.round((markup.markup_type === 'fixed' ? baseUsd + markupValue : baseUsd * (1 + markupValue / 100)) * 100);
  if (!Number.isSafeInteger(totalMinor) || totalMinor <= 0) return jsonError('The calculated price is invalid. No funds were taken.', 502, request);

  const orderId = crypto.randomUUID();
  const now = new Date().toISOString();
  const reserved = await env.DB.batch([
    env.DB.prepare(`INSERT INTO orders (id, customer_id, category, service, country, amount_minor, currency, status, provider,
      created_at, updated_at, quantity, unit_amount_minor, provider_cost_ngn_minor, provider_service_code, provider_country_code, idempotency_key, expires_at, provider_cancel_at, provider_refund_confirmed)
      VALUES (?, ?, 'visual_numbers', ?, ?, ?, 'USD', 'processing', 'youngpg_virtual', ?, ?, 1, ?, ?, ?, ?, ?, NULL, NULL, 0)`)
      .bind(orderId, customer.id, service, country, totalMinor, now, now, totalMinor, Math.round(price.cost_ngn * 100), service, country, idempotencyKey),
    env.DB.prepare(`UPDATE wallets SET balance_minor=balance_minor-?, updated_at=? WHERE customer_id=? AND currency='USD' AND balance_minor>=?
      AND EXISTS (SELECT 1 FROM orders WHERE id=? AND customer_id=? AND status='processing')`)
      .bind(totalMinor, now, customer.id, totalMinor, orderId, customer.id),
    env.DB.prepare('DELETE FROM orders WHERE id=? AND customer_id=? AND changes()=0').bind(orderId, customer.id),
    env.DB.prepare(`INSERT INTO transactions (id, customer_id, type, currency, amount_minor, status, reference, description, created_at)
      SELECT ?, ?, 'visual_number_purchase', 'USD', ?, 'pending', ?, ?, ? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND customer_id=?)`)
      .bind(crypto.randomUUID(), customer.id, -totalMinor, `VN-${orderId}`, `Visual Numbers rental: ${service}/${country}`, now, orderId, customer.id),
    env.DB.prepare(`INSERT INTO customer_order_requests (customer_id, idempotency_key, request_hash, order_id, created_at)
      SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND customer_id=?)`)
      .bind(customer.id, idempotencyKey, requestHash, orderId, now, orderId, customer.id)
  ]);
  if (Number(reserved[1]?.meta?.changes || 0) !== 1) return jsonError('Your USD wallet balance is not enough for this rental.', 409, request);

  let rented;
  try { rented = await youngpgVirtualCall(env, 'getNumber', { country, service }); }
  catch (error) {
    if (error.status === 429) {
      await env.DB.prepare("UPDATE orders SET status='review', failure_reason=?, updated_at=? WHERE id=? AND status='processing'")
        .bind('Provider rate limit interrupted the rental request; check provider status before any retry.', new Date().toISOString(), orderId).run();
      return respond({ ok: false, order_id: orderId, status: 'review', message: 'The rental result is uncertain. Your funds are held safely while it is checked. Do not submit another rental.' }, 202, request);
    }
    await env.DB.prepare("UPDATE orders SET status='review', failure_reason=?, updated_at=? WHERE id=? AND status='processing'")
      .bind('The provider request timed out or failed after dispatch. The rental may have been created; reconciliation is required before any refund or retry.', new Date().toISOString(), orderId).run();
    return respond({ ok: false, order_id: orderId, status: 'review', message: 'The rental result is uncertain. Your funds are held safely while it is checked. Do not submit another rental.' }, 202, request);
  }
  const token = String(rented.data || '').trim();
  const match = token.match(/^ACCESS_NUMBER:([^:]+):(.+)$/);
  if (!match) {
    const knownFailure = ['NO_NUMBERS','NO_BALANCE','BAD_SERVICE','BAD_COUNTRY','BAD_KEY','BAD_ACTION','TOO_MANY_REQUESTS'].includes(token);
    if (knownFailure) {
      const declinedAt = new Date().toISOString();
      await env.DB.prepare("UPDATE orders SET provider_refund_confirmed=1, provider_refund_at=?, expires_at=?, failure_reason=? WHERE id=? AND status='processing'")
        .bind(declinedAt, declinedAt, `Provider declined rental: ${token}`, orderId).run();
      await refundVisualOrder(env, customer.id, orderId, `Provider declined rental: ${token}`);
      return jsonError('We could not complete your number rental. Your USD wallet has been restored.', 502, request);
    }
    await env.DB.prepare("UPDATE orders SET status='review', provider_status=?, failure_reason=?, updated_at=? WHERE id=? AND status='processing'")
      .bind(token.slice(0, 120), 'Provider returned an unrecognised rental response. Funds remain reserved pending reconciliation.', new Date().toISOString(), orderId).run();
    return respond({ ok: false, order_id: orderId, status: 'review', message: 'The provider response needs checking. Your funds remain reserved; do not retry.' }, 202, request);
  }
  const providerId = match[1].trim();
  const phone = match[2].trim();
  const issuedAt = Date.now();
  const timerDates = await visualRefundTimerDates(env, issuedAt);
  await env.DB.prepare(`UPDATE orders SET provider_order_id=?, provider_phone=?, provider_status='STATUS_WAIT_CODE',
    provider_cancel_at=?, expires_at=?, updated_at=? WHERE id=? AND customer_id=? AND status='processing'`)
    .bind(providerId, phone, timerDates.providerCancelAt, timerDates.customerRefundAt, new Date(issuedAt).toISOString(), orderId, customer.id).run();
  const order = await getVisualOrder(env, customer.id, orderId);
  if (order) delete order.delivery_json;
  return respond({ ok: true, order: customerSafeOrder(order), message: 'Your number is ready. Check this order for incoming SMS codes.' }, 201, request);
}

async function youngpgCustomerRoutes(request, env, url, path, method) {
  const visualPrefix = '/api/customer/visual-numbers/';
  const logsPrefix = '/api/customer/social-logs/';
  if (!path.startsWith(visualPrefix) && !path.startsWith(logsPrefix)) return null;
  if (!['GET'].includes(method)) return jsonError('This catalogue endpoint is read-only in the current setup phase.', 405, request);
  const customer = await getCustomer(request, env);
  if (!customer) return jsonError('A verified customer login is required.', 401, request);
  try {
    if (path === logsPrefix + 'listing') {
      const slug = String(url.searchParams.get('slug') || '').trim();
      if (!/^[a-zA-Z0-9_-]{3,120}$/.test(slug)) return jsonError('A valid listing slug is required.', 400, request);
      const result = await youngpgMediaCall(env, `listings/${encodeURIComponent(slug)}`);
      return respond({ ok: true, listing: providerEnvelope(result.data) }, 200, request);
    }
    if (path === visualPrefix + 'countries') {
      const result = await youngpgVirtualCall(env, 'getCountries');
      let countries = result.data;
      if (typeof countries === 'string') { try { countries = JSON.parse(countries); } catch {} }
      return respond({ ok: true, countries }, 200, request);
    }
    if (path === visualPrefix + 'services') {
      const result = await youngpgVirtualCall(env, 'getServicesList');
      let services = result.data;
      if (typeof services === 'string') { try { services = JSON.parse(services); } catch {} }
      return respond({ ok: true, services, country: url.searchParams.get('country') || null }, 200, request);
    }
    if (path === visualPrefix + 'catalogue') {
      const country = url.searchParams.get('country');
      const service = url.searchParams.get('service');
      if (!country || !service) return jsonError('Country and service are required.', 400, request);
      const result = await youngpgVirtualCall(env, 'getPrices', { country, service });
      let prices = result.data;
      if (typeof prices === 'string') { try { prices = JSON.parse(prices); } catch {} }
      return respond({ ok: true, country, service, prices }, 200, request);
    }
    if (path === visualPrefix + 'balance') {
      const result = await youngpgVirtualCall(env, 'getBalance');
      return respond({ ok: true, balance: result.data }, 200, request);
    }
    if (path === logsPrefix + 'categories') {
      const result = await youngpgMediaCall(env, 'categories');
      return respond({ ok: true, categories: providerEnvelope(result.data) }, 200, request);
    }
    if (path === logsPrefix + 'listings') {
      const params = {
        search: url.searchParams.get('search') || undefined,
        category_id: url.searchParams.get('category_id') || undefined,
        subcategory_id: url.searchParams.get('subcategory_id') || undefined,
        sort: url.searchParams.get('sort') || undefined,
        direction: url.searchParams.get('direction') || undefined,
        per_page: Math.min(100, Math.max(1, Number(url.searchParams.get('per_page') || 50))),
        page: Math.max(1, Number(url.searchParams.get('page') || 1))
      };
      const result = await youngpgMediaCall(env, 'listings', params);
      const rawListings = providerEnvelope(result.data);
      const settings = await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key='usd_ngn_rate'").first();
      const rate = Number(settings?.setting_value || 1500);
      if (!Number.isFinite(rate) || rate <= 0) return jsonError('The NGN/USD exchange rate is not configured.', 503, request);
      const priceListing = async (item) => {
        if (!item || typeof item !== 'object') return item;
        const priceNgn = Number(item.price_ngn ?? item.price ?? item.amount_ngn);
        if (!Number.isFinite(priceNgn) || priceNgn <= 0) return { ...item, currency: 'USD', customer_price_minor: null, price_available: false };
        const markup = await socialLogMarkup(env, item);
        const baseUsd = priceNgn / rate;
        const value = Number(markup.markup_value || 0);
        const customerUsd = markup.markup_type === 'fixed' ? baseUsd + value : baseUsd * (1 + value / 100);
        const customerPriceMinor = Math.round(customerUsd * 100);
        return { ...item, currency: 'USD', customer_price_minor: Number.isSafeInteger(customerPriceMinor) && customerPriceMinor > 0 ? customerPriceMinor : null, price_available: Number.isSafeInteger(customerPriceMinor) && customerPriceMinor > 0 };
      };
      let pricedListings = rawListings;
      if (Array.isArray(rawListings)) pricedListings = await Promise.all(rawListings.map(priceListing));
      else if (rawListings && typeof rawListings === 'object' && Array.isArray(rawListings.data)) pricedListings = { ...rawListings, data: await Promise.all(rawListings.data.map(priceListing)) };
      else if (rawListings && typeof rawListings === 'object' && Array.isArray(rawListings.listings)) pricedListings = { ...rawListings, listings: await Promise.all(rawListings.listings.map(priceListing)) };
      return respond({ ok: true, listings: pricedListings, meta: result.data?.meta || null }, 200, request);
    }
    return jsonError('Endpoint not found.', 404, request);
  } catch (error) {
    console.error('YoungPG catalogue request failed:', error?.message || error);
    return jsonError(providerErrorMessage(error), error?.status === 429 ? 429 : 502, request);
  }
}

async function youngpgAdminRoutes(request, env, path, method) {
  if (method !== 'POST' || path !== '/api/admin/providers/test') return null;
  const admin = await getAdmin(request, env);
  if (!admin) return jsonError('Administrator login required.', 401, request);
  const body = await readBody(request);
  const product = String(body?.product || '').toLowerCase();
  if (!['visual_numbers', 'social_logs'].includes(product)) return jsonError('Choose visual_numbers or social_logs.', 400, request);
  const provider = product === 'visual_numbers' ? 'youngpg_virtual' : 'youngpg_media';
  try {
    let message;
    if (product === 'visual_numbers') {
      const result = await youngpgVirtualCall(env, 'getBalance');
      if (typeof result.data !== 'string' || !result.data.startsWith('ACCESS_BALANCE:')) throw new Error(`Unexpected balance response: ${String(result.data).slice(0, 160)}`);
      message = `Connected. ${result.data}`;
    } else {
      const result = await youngpgMediaCall(env, 'user/balance');
      const data = providerEnvelope(result.data);
      message = `Connected. Balance response received: ${JSON.stringify(data).slice(0, 300)}`;
    }
    await recordProviderCheck(env, provider, product, true, message);
    await env.DB.prepare('INSERT INTO audit_logs (admin_id, action, detail, created_at) VALUES (?, ?, ?, ?)')
      .bind(admin.id, 'provider.connection_test', JSON.stringify({ provider, product, result: 'connected' }), new Date().toISOString()).run();
    return respond({ ok: true, provider, product, status: 'connected', message }, 200, request);
  } catch (error) {
    const message = providerErrorMessage(error);
    try { await recordProviderCheck(env, provider, product, false, message); } catch (dbError) { console.error('Could not save provider test status:', dbError?.message || dbError); }
    return jsonError(message, error?.status === 429 ? 429 : 502, request);
  }
}


// Nexar Prime Social Boost catalogue and connection diagnostics.
async function nexarCall(env, endpoint, { method = 'GET', params = {}, body, idempotencyKey } = {}) {
  if (!env.NEXAR_API_KEY) throw new Error('Nexar Prime API key is not configured.');
  if (!/^nx_live_[A-Za-z0-9_-]{16,}$/.test(env.NEXAR_API_KEY)) throw new Error('Nexar API key format is invalid.');
  const url = new URL(endpoint.replace(/^\//, ''), 'https://resellers.nexarhq.com/api/v1/reseller/');
  for (const [k,v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));
  const headers = { 'X-API-Key': env.NEXAR_API_KEY, 'Accept': 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
  return providerFetch(url.toString(), { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
}

function nexarMoneyFromService(service) {
  // Fail closed unless Nexar explicitly identifies a per-unit amount; do not guess whether a rate is per 1,000.
  const value = service?.unit_price ?? service?.price_per_unit;
  const currency = String((value && typeof value === 'object' ? value.currency : null) || service?.price_currency || service?.currency || '').toUpperCase();
  const amount = value && typeof value === 'object'
    ? Number(value.whole ?? value.value ?? value.amount_decimal)
    : Number(value);
  if (!['USD','NGN'].includes(currency) || !Number.isFinite(amount) || amount <= 0) return null;
  return { currency, amount };
}

async function nexarBoostMarkup(env, driver, service) {
  const country = driver === 'nigerian' ? 'NG' : 'GLOBAL';
  const serviceKey = String(service.id ?? service.service_id ?? service.name ?? '*').slice(0,100);
  return (await env.DB.prepare(`SELECT markup_type, markup_value FROM pricing_rules WHERE active=1
    AND provider IN ('nexar','*') AND product IN ('social_boosting','*')
    AND country IN (?, '*') AND service IN (?, '*')
    ORDER BY CASE WHEN provider='nexar' THEN 0 ELSE 1 END,
      CASE WHEN product='social_boosting' THEN 0 ELSE 1 END,
      CASE WHEN country=? THEN 0 ELSE 1 END,
      CASE WHEN service=? THEN 0 ELSE 1 END LIMIT 1`).bind(country,serviceKey,country,serviceKey).first()) || { markup_type:'percent', markup_value:0 };
}

async function refundNexarBoostOrder(env, customerId, orderId, amountMinor, reason) {
  const now = new Date().toISOString();
  const ref = `SB-REFUND-${orderId}`;
  const result = await env.DB.batch([
    env.DB.prepare(`UPDATE orders SET status='failed', failure_reason=?, updated_at=? WHERE id=? AND customer_id=? AND category='social_boosting' AND status IN ('processing','review')`)
      .bind(String(reason).slice(0,500), now, orderId, customerId),
    env.DB.prepare(`UPDATE wallets SET balance_minor=balance_minor+?, updated_at=? WHERE customer_id=? AND currency='USD' AND changes()=1`)
      .bind(amountMinor, now, customerId),
    env.DB.prepare(`INSERT OR IGNORE INTO transactions (id, customer_id, type, currency, amount_minor, status, reference, description, created_at) SELECT ?, ?, 'social_boost_purchase_refund', 'USD', ?, 'successful', ?, ?, ? WHERE changes()=1`)
      .bind(crypto.randomUUID(), customerId, amountMinor, ref, `Refund for rejected Social Boosting order ${orderId}`, now)
  ]);
  return Number(result[0]?.meta?.changes || 0) === 1;
}
function customerSafeOrder(order) {
  if (!order) return order;

  const {
    provider,
    provider_order_id,
    provider_phone,
    provider_status,
    provider_service_code,
    provider_country_code,
    provider_cancel_at,
    provider_refund_confirmed,
    provider_refund_at,
    provider_response_json,
    ...safeOrder
  } = order;

  return safeOrder;
}
async function nexarSocialBoostPurchase(request, env, url) {
  const customer = await getCustomer(request, env);
  if (!customer) return jsonError('A verified customer login is required.', 401, request);
  await ensureCustomerWallets(env, customer.id);
  await ensureSocialLogOrderSchema(env);
  const body = await readBody(request);
  if (!body) return jsonError('Invalid JSON.', 400, request);
  const driver = body.driver === 'nigerian' ? 'nigerian' : 'global';
  const serviceId = Number(body.service);
  const quantity = Number(body.quantity);
  const link = String(body.link || '').trim();
  const comments = typeof body.comments === 'string' ? body.comments.trim() : '';
  const key = String(request.headers.get('Idempotency-Key') || body.idempotency_key || '').trim();
  if (!Number.isSafeInteger(serviceId) || serviceId <= 0) return jsonError('Choose a valid service.', 400, request);
  if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 100000000) return jsonError('Enter a valid quantity.', 400, request);
  if (!/^https:\/\//i.test(link) || link.length > 2048) return jsonError('Enter a valid public HTTPS profile or post link.', 400, request);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{7,119}$/.test(key)) return jsonError('A unique order key is required.', 400, request);
  const requestHash = await hash(JSON.stringify({ driver, serviceId, quantity, link, comments }));
  const prior = await env.DB.prepare(`SELECT r.request_hash, o.id FROM customer_order_requests r JOIN orders o ON o.id=r.order_id WHERE r.customer_id=? AND r.idempotency_key=?`).bind(customer.id, key).first();
  if (prior) {
    if (prior.request_hash !== requestHash) return jsonError('This order key was already used for different details.', 409, request);
    const existing = await env.DB.prepare("SELECT id, category, service, amount_minor, currency, status, provider_order_id, created_at, updated_at FROM orders WHERE id=? AND customer_id=?").bind(prior.id, customer.id).first();
    return respond({ ok: true, duplicate_request: true, order: customerSafeOrder(existing) }, 200, request);
  }
  try {
    const catalogueResponse = await nexarCall(env, 'social-boost/services', { params: { driver } });
    const catalogue = providerEnvelope(catalogueResponse.data);
    const services = Array.isArray(catalogue) ? catalogue : (catalogue?.services || catalogue?.data || []);
    const service = services.find(x => Number(x.id ?? x.service_id) === serviceId);
    if (!service) return jsonError('This service is no longer available. Refresh the catalogue.', 409, request);
    const min = Number(service.min_quantity ?? service.min ?? 1);
    const max = Number(service.max_quantity ?? service.max ?? Number.MAX_SAFE_INTEGER);
    if (quantity < min || quantity > max) return jsonError(`Quantity must be between ${min} and ${max}.`, 400, request);
    const money = nexarMoneyFromService(service);
    if (!money) return jsonError('The live service price or currency could not be verified. No funds were taken.', 502, request);
    const settings = await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key='usd_ngn_rate'").first();
    const rate = Number(settings?.setting_value || 1500);
    if (!Number.isFinite(rate) || rate <= 0) return jsonError('The NGN/USD exchange rate is not configured.', 503, request);
    const baseUnitUsd = money.currency === 'NGN' ? money.amount / rate : money.amount;
    const markup = await nexarBoostMarkup(env, driver, service);
    const markupValue = Number(markup.markup_value || 0);
    const customerUnitUsd = markup.markup_type === 'fixed' ? baseUnitUsd + markupValue : baseUnitUsd * (1 + markupValue / 100);
    const totalUsdMinor = Math.round(customerUnitUsd * quantity * 100);
    if (!Number.isSafeInteger(totalUsdMinor) || totalUsdMinor <= 0) return jsonError('The service price is invalid. No funds were taken.', 502, request);
    const orderId = crypto.randomUUID();
    const now = new Date().toISOString();
    const serviceName = String(service.name || service.title || service.service_name || `Social service ${serviceId}`).slice(0,160);
    const reservation = await env.DB.batch([
      env.DB.prepare(`INSERT INTO orders (id, customer_id, category, service, country, amount_minor, currency, status, provider, created_at, updated_at, quantity, unit_amount_minor, provider_response_json, idempotency_key) VALUES (?, ?, 'social_boosting', ?, ?, ?, 'USD', 'processing', 'nexar', ?, ?, ?, ?, ?, ?)`)
        .bind(orderId, customer.id, serviceName, driver, totalUsdMinor, now, now, quantity, Math.round(totalUsdMinor/quantity), JSON.stringify({ driver, service_id: serviceId, provider_cost_currency: money.currency, provider_unit_price: money.amount, markup_type: markup.markup_type, markup_value: markupValue }).slice(0,10000), key),
      env.DB.prepare(`UPDATE wallets SET balance_minor=balance_minor-?, updated_at=? WHERE customer_id=? AND currency='USD' AND balance_minor>=? AND EXISTS (SELECT 1 FROM orders WHERE id=? AND customer_id=? AND status='processing')`)
        .bind(totalUsdMinor, now, customer.id, totalUsdMinor, orderId, customer.id),
      env.DB.prepare('DELETE FROM orders WHERE id=? AND customer_id=? AND changes()=0').bind(orderId, customer.id),
      env.DB.prepare(`INSERT INTO transactions (id, customer_id, type, currency, amount_minor, status, reference, description, created_at) SELECT ?, ?, 'social_boost_purchase', 'USD', ?, 'pending', ?, ?, ? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND customer_id=? AND status='processing')`)
        .bind(crypto.randomUUID(), customer.id, -totalUsdMinor, `SB-${orderId}`, `Social Boosting: ${serviceName}`, now, orderId, customer.id),
      env.DB.prepare(`INSERT INTO customer_order_requests (customer_id, idempotency_key, request_hash, order_id, created_at) SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM orders WHERE id=? AND customer_id=? AND status='processing')`)
        .bind(customer.id, key, requestHash, orderId, now, orderId, customer.id)
    ]);
    if (Number(reservation[1]?.meta?.changes || 0) !== 1) return jsonError('Your USD wallet balance is not enough for this order.', 409, request);
    let providerResult;
    try {
      providerResult = await nexarCall(env, 'social-boost/orders', { method: 'POST', params: { driver }, idempotencyKey: key, body: { service: serviceId, quantity, link, ...(comments ? { comments } : {}), wallet_currency: money.currency } });
    } catch (error) {
      // Nexar explicitly supports idempotent retries. Keep funds reserved on timeouts/409/5xx for safe reconciliation.
      if (Number(error?.status) >= 400 && Number(error.status) < 500 && Number(error.status) !== 409 && Number(error.status) !== 429) {
        await refundNexarBoostOrder(env, customer.id, orderId, totalUsdMinor, `Nexar rejected Social Boosting order: ${providerErrorMessage(error)}`);
        await env.DB.prepare("UPDATE transactions SET status='failed' WHERE reference=? AND status='pending'").bind(`SB-${orderId}`).run();
        return jsonError(`The service provider rejected this order. Your USD wallet has been restored. ${providerErrorMessage(error)}`, 502, request);
      }
      await env.DB.prepare("UPDATE orders SET status='review', failure_reason=?, updated_at=? WHERE id=? AND status='processing'").bind('Nexar order outcome is pending reconciliation. Reuse the same idempotency key for any provider retry; customer funds remain reserved.', new Date().toISOString(), orderId).run();
      return respond({ ok: false, order_id: orderId, status: 'review', message: 'Your order is being checked. Your funds are safely reserved. Please do not submit it again.' }, 202, request);
    }
    const result = providerEnvelope(providerResult.data);
    const providerOrderId = result?.order_id ?? result?.id ?? result?.order?.id ?? null;
    if (!providerOrderId) {
      await env.DB.prepare("UPDATE orders SET status='review', provider_response_json=?, failure_reason=?, updated_at=? WHERE id=? AND status='processing'")
        .bind(JSON.stringify(providerResult.data).slice(0,100000), 'Nexar response did not contain a recognisable order ID; manual reconciliation required.', new Date().toISOString(), orderId).run();
      return respond({ ok: false, order_id: orderId, status: 'review', message: 'The provider response needs checking. Your funds remain reserved; do not submit another order.' }, 202, request);
    }
    const providerStatus = String(result.status || result.order_status || 'pending').toLowerCase();
    const localStatus = ['completed','complete','success','successful','delivered'].includes(providerStatus) ? 'completed' : 'processing';
    const done = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare('UPDATE orders SET provider_order_id=?, provider_status=?, provider_response_json=?, status=?, updated_at=? WHERE id=? AND customer_id=? AND status IN (\'processing\',\'review\')')
        .bind(String(providerOrderId), providerStatus, JSON.stringify(providerResult.data).slice(0,100000), localStatus, done, orderId, customer.id),
      env.DB.prepare("UPDATE transactions SET status='successful' WHERE reference=? AND status='pending'").bind(`SB-${orderId}`)
    ]);
    const order = await env.DB.prepare('SELECT id, category, service, country, quantity, amount_minor, currency, status, provider_order_id, provider_status, created_at, updated_at FROM orders WHERE id=? AND customer_id=?').bind(orderId, customer.id).first();
    return respond({ ok: true, order: customerSafeOrder(order), message: 'Your Social Boosting order has been submitted.' }, 201, request);
  } catch (error) {
    return jsonError(`The Social Boosting order could not be prepared. ${providerErrorMessage(error)}`, error?.status === 429 ? 429 : 502, request);
  }
}

async function nexarSocialBoostRoutes(request, env, url, path, method) {
  if (path === '/api/customer/social-boost/purchase' && method === 'POST') return nexarSocialBoostPurchase(request, env, url);
  const refreshMatch = path.match(/^\/api\/customer\/social-boost\/orders\/([^/]+)\/refresh$/);
  if (refreshMatch && method === 'POST') {
    const customer = await getCustomer(request, env);
    if (!customer) return jsonError('A verified customer login is required.', 401, request);
    await ensureSocialLogOrderSchema(env);
    const orderId = decodeURIComponent(refreshMatch[1]);
    const order = await env.DB.prepare(`SELECT id, customer_id, status, provider_order_id, amount_minor, currency, provider_status, country
      FROM orders WHERE id=? AND customer_id=? AND category='social_boosting'`).bind(orderId, customer.id).first();
    if (!order) return jsonError('Social Boosting order not found.', 404, request);
    if (!order.provider_order_id) return respond({ ok: true, order, message: 'The provider order reference is not available yet. This order remains under review.' }, 202, request);
    if (['completed','failed'].includes(String(order.status))) return respond({ ok: true, order, unchanged: true }, 200, request);
    try {
      let found = null;
      for (let page = 1; page <= 5 && !found; page++) {
        const response = await nexarCall(env, 'social-boost/orders', { params: { page, per_page: 100, driver: order.country === 'nigerian' ? 'nigerian' : 'global' } });
        const data = providerEnvelope(response.data);
        const rows = Array.isArray(data) ? data : (data?.orders || data?.data || []);
        found = rows.find(row => String(row.order_id ?? row.id) === String(order.provider_order_id)) || null;
        if (!Array.isArray(rows) || rows.length < 100) break;
      }
      if (!found) return respond({ ok: true, order, message: 'Nexar has not returned this order in the recent order pages yet. Your funds remain reserved.' }, 202, request);
      const providerStatus = String(found.status || found.order_status || 'pending').toLowerCase();
      const now = new Date().toISOString();
      const success = ['completed','complete','success','successful','delivered'].includes(providerStatus);
      const failed = ['failed','cancelled','canceled','rejected','refunded'].includes(providerStatus);
      if (failed) {
        const refunded = await refundNexarBoostOrder(env, customer.id, orderId, Number(order.amount_minor), `Nexar reports Social Boosting order ${providerStatus}.`);
        if (refunded) await env.DB.prepare("UPDATE transactions SET status='failed' WHERE reference=? AND status='pending'").bind(`SB-${orderId}`).run();
      } else {
        await env.DB.prepare(`UPDATE orders SET provider_status=?, status=?, provider_response_json=?, updated_at=?
          WHERE id=? AND customer_id=? AND category='social_boosting' AND status IN ('processing','review')`)
          .bind(providerStatus, success ? 'completed' : 'processing', JSON.stringify(found).slice(0,100000), now, orderId, customer.id).run();
        if (success) await env.DB.prepare("UPDATE transactions SET status='successful' WHERE reference=? AND status='pending'").bind(`SB-${orderId}`).run();
      }
      const updated = await env.DB.prepare(`SELECT id, category, service, country, quantity, amount_minor, currency, status, provider_order_id, provider_status, created_at, updated_at, failure_reason FROM orders WHERE id=? AND customer_id=?`).bind(orderId, customer.id).first();
      return respond({ ok: true, order: customerSafeOrder(updated), message: failed ? 'The provider marked this order unsuccessful. Your USD wallet has been restored.' : success ? 'Your Social Boosting order is complete.' : 'Your order is still being processed.' }, 200, request);
    } catch (error) {
      return jsonError(`Could not refresh the provider order status. ${providerErrorMessage(error)}`, error?.status === 429 ? 429 : 502, request);
    }
  }
  if (path === '/api/customer/social-boost/services' && method === 'GET') {
    const customer = await getCustomer(request, env);
    if (!customer) return jsonError('A verified customer login is required.', 401, request);
    const driver = url.searchParams.get('driver') === 'nigerian' ? 'nigerian' : 'global';
    try {
      const result = await nexarCall(env, 'social-boost/services', { params: { driver } });
      const data = providerEnvelope(result.data);
      const services = Array.isArray(data) ? data : (data?.services || data?.data || []);
      return respond({ ok: true, driver, services, request_id: result.data?.request_id || null }, 200, request);
    } catch (error) {
      return jsonError(providerErrorMessage(error), error?.status === 429 ? 429 : 502, request);
    }
  }
  if (path === '/api/admin/providers/test' && method === 'POST') {
    const body = await readBody(request);
    if (String(body?.product || '') !== 'social_boosting') return null;
    const admin = await getAdmin(request, env);
    if (!admin) return jsonError('Administrator login required.', 401, request);
    try {
      const accountResponse = await nexarCall(env, 'account');
      const accountData = providerEnvelope(accountResponse.data);
      const servicesResponse = await nexarCall(env, 'social-boost/services', { params: { driver: 'global' } });
      const servicesData = providerEnvelope(servicesResponse.data);
      const services = Array.isArray(servicesData) ? servicesData : (servicesData?.services || servicesData?.data || []);
      const message = `Connected. Account verified; ${Array.isArray(services) ? services.length : 0} global services returned.`;
      const now = new Date().toISOString();
      await env.DB.prepare(`INSERT INTO provider_configs
        (id, provider, product, base_url, api_key_enc, extra_enc, enabled, verification_status, last_test_at, last_test_message, updated_at)
        VALUES (?, 'nexar', 'social_boosting', 'https://resellers.nexarhq.com/api/v1/reseller/', '', '', 1, 'connected', ?, ?, ?)
        ON CONFLICT(provider, product) DO UPDATE SET enabled=1, verification_status='connected', last_test_at=excluded.last_test_at, last_test_message=excluded.last_test_message, updated_at=excluded.updated_at`)
        .bind(crypto.randomUUID(), now, message, now).run();
      await env.DB.prepare('INSERT INTO audit_logs (admin_id, action, detail, created_at) VALUES (?, ?, ?, ?)')
        .bind(admin.id, 'provider.connection_test', JSON.stringify({ provider: 'nexar', product: 'social_boosting', result: 'connected', account: accountData?.account?.business_name || null }), now).run();
      return respond({ ok: true, provider: 'nexar', product: 'social_boosting', status: 'connected', message }, 200, request);
    } catch (error) {
      const message = providerErrorMessage(error); const now = new Date().toISOString();
      try { await env.DB.prepare(`INSERT INTO provider_configs
        (id, provider, product, base_url, api_key_enc, extra_enc, enabled, verification_status, last_test_at, last_test_message, updated_at)
        VALUES (?, 'nexar', 'social_boosting', 'https://resellers.nexarhq.com/api/v1/reseller/', '', '', 0, 'error', ?, ?, ?)
        ON CONFLICT(provider, product) DO UPDATE SET enabled=0, verification_status='error', last_test_at=excluded.last_test_at, last_test_message=excluded.last_test_message, updated_at=excluded.updated_at`)
        .bind(crypto.randomUUID(), now, message, now).run(); } catch {}
      return jsonError(message, error?.status === 429 ? 429 : 502, request);
    }
  }
  return null;
}

async function handle(request, env) {
  if (!env.DB) return jsonError("Database binding DB is missing.", 500, request);
  const origin = request.headers.get("Origin") || "";
  if (origin && !ALLOWED_ORIGINS.has(origin)) return jsonError("Origin not allowed.", 403, request);
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;

  if (method === "POST" && path === "/api/webhooks/flutterwave") {
    return await processFlutterwaveWebhook(request, env);
  }

  if (method === "GET" && path === "/api/health") {
    await env.DB.prepare("SELECT 1").first();
    return respond({ ok: true, service: "Speedy.ng API", database: "connected" }, 200, request);
  }

  const customerResponse = await customerRoutes(request, env, path, method);
  if (customerResponse) return customerResponse;

  const socialOrderResponse = await socialLogOrderRoutes(request, env, url, path, method);
  if (socialOrderResponse) return socialOrderResponse;
  const visualOrderResponse = await visualNumberOrderRoutes(request, env, url, path, method);
  if (visualOrderResponse) return visualOrderResponse;

  const providerCustomerResponse = await youngpgCustomerRoutes(request, env, url, path, method);
  if (providerCustomerResponse) return providerCustomerResponse;

  const providerAdminResponse = await youngpgAdminRoutes(request, env, path, method);
  if (providerAdminResponse) return providerAdminResponse;

  const nexarResponse = await nexarSocialBoostRoutes(request, env, url, path, method);
  if (nexarResponse) return nexarResponse;

  if (method === "POST" && path === "/api/admin/initial-setup") {
    if (!env.ADMIN_SETUP_TOKEN) return jsonError("Configure the ADMIN_SETUP_TOKEN secret first.", 503, request);
    const body = await readBody(request);
    if (!body) return jsonError("Invalid JSON.", 400, request);
    if (body.setupToken !== env.ADMIN_SETUP_TOKEN) return jsonError("Unauthorized.", 401, request);
    const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM admin_users").first();
    if (Number(count?.total || 0) > 0) return jsonError("Administrator setup has already been completed.", 409, request);
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return jsonError("Enter a valid email address.", 400, request);
    if (password.length < 14) return jsonError("Password must be at least 14 characters.", 400, request);
    const id = crypto.randomUUID();
    const salt = token();
    const storedHash = await passwordHash(password, salt);
    await env.DB.prepare(`INSERT INTO admin_users (id, email, password_hash, password_salt, role, active, created_at) VALUES (?, ?, ?, ?, 'owner', 1, ?)`)
      .bind(id, email, storedHash, salt, new Date().toISOString()).run();
    return respond({ ok: true, message: "Administrator account created." }, 201, request);
  }

  if (method === "POST" && path === "/api/admin/login") {
    const body = await readBody(request);
    if (!body) return jsonError("Invalid JSON.", 400, request);
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");
    const admin = await env.DB.prepare(`SELECT id, email, password_hash, password_salt, role FROM admin_users WHERE email = ? AND active = 1`).bind(email).first();
    if (!admin) return jsonError("Invalid email or password.", 401, request);
    const verifiedIterations = await verifyPassword(password, admin.password_salt, admin.password_hash, [100000, 210000]);
    if (!verifiedIterations) return jsonError("Invalid email or password.", 401, request);
    const sessionToken = token();
    const now = new Date();
    const expiry = new Date(now.getTime() + 8 * 60 * 60 * 1000);
    await env.DB.prepare(`INSERT INTO admin_sessions (id, admin_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`)
      .bind(crypto.randomUUID(), admin.id, await hash(sessionToken), expiry.toISOString(), now.toISOString()).run();
    return respond({ ok: true, token: sessionToken, expiresAt: expiry.toISOString(), admin: { id: admin.id, email: admin.email, role: admin.role } }, 200, request);
  }

  const admin = await getAdmin(request, env);
  if (!admin) return jsonError("Administrator login required.", 401, request);

  if (method === "GET" && path === "/api/admin/integrations/status") {
    const from = String(env.EMAIL_FROM || "");
    const emailDomain = (from.match(/@([A-Za-z0-9.-]+)/) || [])[1] || "";
    return respond({ ok: true, integrations: {
      flutterwave: { configured: Boolean(env.FLW_CLIENT_ID && env.FLW_CLIENT_SECRET && (env.FLW_WEBHOOK_SECRET || env.FLW_SECRET_HASH)), environment: String(env.FLW_ENVIRONMENT || "production").toLowerCase() },
      email: { configured: Boolean(env.RESEND_API_KEY && env.EMAIL_FROM && (env.EMAIL_VERIFICATION_PEPPER || env.ENCRYPTION_KEY)), sender: from, domain: emailDomain }
    } }, 200, request);
  }

  if (method === "POST" && path === "/api/admin/integrations/test") {
    const body = await readBody(request);
    const service = String(body?.service || "").toLowerCase();
    if (!["flutterwave", "email"].includes(service)) return jsonError("Choose Flutterwave or email.", 400, request);
    if (service === "flutterwave") {
      try {
        await flutterwaveAccessToken(env);
        await env.DB.prepare("INSERT INTO audit_logs (admin_id, action, detail, created_at) VALUES (?, ?, ?, ?)")
          .bind(admin.id, "integration.connection_test", JSON.stringify({ service, result: "oauth_success", environment: String(env.FLW_ENVIRONMENT || "production") }), new Date().toISOString()).run();
        return respond({ ok: true, service, status: "connected", message: "Flutterwave V4 credentials authenticated successfully. No charge or wallet credit was created." }, 200, request);
      } catch (error) {
        return jsonError(String(error?.message || "Flutterwave authentication failed."), 502, request);
      }
    }
    if (!env.RESEND_API_KEY || !env.EMAIL_FROM) return jsonError("Configure RESEND_API_KEY and EMAIL_FROM as Worker secrets first.", 503, request);
    try {
      const response = await fetch("https://api.resend.com/domains", { headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, Accept: "application/json" } });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error("Resend rejected the API key. Check the key and account access.");
      const senderDomain = ((String(env.EMAIL_FROM).match(/@([A-Za-z0-9.-]+)/) || [])[1] || "").toLowerCase();
      const domains = Array.isArray(data.data) ? data.data : [];
      const match = domains.find(x => String(x.name || "").toLowerCase() === senderDomain);
      const verified = Boolean(match && String(match.status || "").toLowerCase() === "verified");
      await env.DB.prepare("INSERT INTO audit_logs (admin_id, action, detail, created_at) VALUES (?, ?, ?, ?)")
        .bind(admin.id, "integration.connection_test", JSON.stringify({ service, result: verified ? "sender_verified" : "sender_not_verified", sender_domain: senderDomain }), new Date().toISOString()).run();
      return respond({ ok: true, service, status: verified ? "connected" : "needs_setup", message: verified ? `Resend API key works and ${senderDomain} is verified. This checks sender configuration, not inbox delivery.` : `Resend API key works, but ${senderDomain || "the EMAIL_FROM domain"} is not verified in this Resend account.`, sender_domain: senderDomain }, 200, request);
    } catch (error) {
      return jsonError(String(error?.message || "Resend connection test failed."), 502, request);
    }
  }

  if (method === "GET" && path === "/api/admin/orders") {
    await ensureVisualOrderSchema(env);
    const category = String(url.searchParams.get("category") || "").trim().toLowerCase();
    const status = String(url.searchParams.get("status") || "").trim().toLowerCase();
    const search = String(url.searchParams.get("q") || "").trim().slice(0, 100);
    if (category && !["visual_numbers", "social_logs", "social_boosting"].includes(category)) return jsonError("Invalid order category.", 400, request);
    if (status && !["processing", "completed", "failed", "review", "pending"].includes(status)) return jsonError("Invalid order status.", 400, request);
    const where = [], values = [];
    if (category) { where.push("o.category=?"); values.push(category); }
    if (status) { where.push("o.status=?"); values.push(status); }
    if (search) { where.push("(o.id LIKE ? OR o.service LIKE ? OR c.email LIKE ? OR o.provider_order_id LIKE ?)"); values.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`); }
    const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || 100)));
    values.push(limit);
    const result = await env.DB.prepare(`SELECT o.id, o.customer_id, c.email AS customer_email, o.category, o.service, o.country,
      o.quantity, o.amount_minor, o.currency, o.status, o.provider, o.provider_order_id, o.provider_phone,
      o.provider_status, o.expires_at, o.provider_cancel_at, o.provider_refund_confirmed, o.provider_refund_at, o.failure_reason, o.created_at, o.updated_at
      FROM orders o JOIN customers c ON c.id=o.customer_id ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
      ORDER BY o.created_at DESC LIMIT ?`).bind(...values).all();
    return respond({ ok: true, orders: result.results || [] }, 200, request);
  }

  if (method === "GET" && path.startsWith("/api/admin/orders/")) {
    await ensureVisualOrderSchema(env);
    const orderId = decodeURIComponent(path.slice("/api/admin/orders/".length));
    if (!orderId || orderId.includes("/")) return jsonError("Invalid order ID.", 400, request);
    const order = await env.DB.prepare(`SELECT o.id, o.customer_id, c.email AS customer_email, o.category, o.service, o.country,
      o.quantity, o.amount_minor, o.currency, o.status, o.provider, o.provider_order_id, o.provider_phone,
      o.provider_status, o.expires_at, o.provider_cancel_at, o.provider_refund_confirmed, o.provider_refund_at, o.failure_reason, o.created_at, o.updated_at
      FROM orders o JOIN customers c ON c.id=o.customer_id WHERE o.id=?`).bind(orderId).first();
    if (!order) return jsonError("Order not found.", 404, request);
    return respond({ ok: true, order }, 200, request);
  }

  if (method === "POST" && path.startsWith("/api/admin/orders/") && path.endsWith("/attach-visual-reference")) {
    await ensureVisualOrderSchema(env);
    const orderId = decodeURIComponent(path.slice("/api/admin/orders/".length, -"/attach-visual-reference".length).replace(/\/$/, ""));
    const body = await readBody(request);
    const providerOrderId = String(body?.provider_order_id || "").trim();
    const phone = String(body?.phone_number || "").trim();
    if (!orderId || orderId.includes("/") || !/^[a-zA-Z0-9_-]{1,80}$/.test(providerOrderId) || !/^\+?[0-9 ()-]{5,30}$/.test(phone)) {
      return jsonError("Provide a valid order ID, provider rental ID, and phone number.", 400, request);
    }
    const now = new Date().toISOString();
    const timerDates = await visualRefundTimerDates(env, Date.now());
    const result = await env.DB.prepare(`UPDATE orders SET provider_order_id=?, provider_phone=?, provider_status='RECONCILIATION_ATTACHED',
      provider_cancel_at=?, expires_at=?, provider_refund_confirmed=0, provider_refund_at=NULL,
      status='processing', failure_reason='Provider rental reference attached by an administrator; status will be checked before any refund.', updated_at=?
      WHERE id=? AND category='visual_numbers' AND status='review' AND provider_order_id IS NULL`)
      .bind(providerOrderId, phone, timerDates.providerCancelAt, timerDates.customerRefundAt, now, orderId).run();
    if (Number(result?.meta?.changes || 0) !== 1) return jsonError("This order is not an eligible unresolved Visual Numbers order. No changes were made.", 409, request);
    await env.DB.prepare("INSERT INTO audit_logs (admin_id, action, detail, created_at) VALUES (?, ?, ?, ?)")
      .bind(admin.id, "visual_number.reference_attached", JSON.stringify({ order_id: orderId, provider_order_id: providerOrderId }), now).run();
    return respond({ ok: true, message: "Provider reference attached. The order can now be checked; no refund has been issued.", order_id: orderId }, 200, request);
  }

  if (method === "GET" && path === "/api/admin/me") return respond({ ok: true, admin }, 200, request);
  if (method === "POST" && path === "/api/admin/logout") {
    const authorization = request.headers.get("Authorization") || "";
    const suppliedToken = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
    await env.DB.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").bind(await hash(suppliedToken)).run();
    return respond({ ok: true }, 200, request);
  }
  if (method === "GET" && path === "/api/admin/summary") {
    const customers = await env.DB.prepare("SELECT COUNT(*) AS total FROM customers").first();
    const orders = await env.DB.prepare("SELECT COUNT(*) AS total FROM orders").first();
    const transactions = await env.DB.prepare("SELECT COUNT(*) AS total FROM transactions").first();
    return respond({ ok: true, summary: { customers: Number(customers?.total || 0), orders: Number(orders?.total || 0), transactions: Number(transactions?.total || 0) } }, 200, request);
  }
  if (method === "GET" && path === "/api/admin/settings") {
    const result = await env.DB.prepare("SELECT setting_key, setting_value, updated_at FROM app_settings ORDER BY setting_key").all();
    const settings = {};
    for (const row of result.results || []) settings[row.setting_key] = row.setting_value;
    return respond({ ok: true, settings, settings_rows: result.results || [] }, 200, request);
  }
  if (method === "POST" && path === "/api/admin/settings") {
    const body = await readBody(request);
    if (!body || typeof body !== "object" || Array.isArray(body)) return jsonError("Provide a settings object or a setting key and value.", 400, request);
    // Accept both the earlier dashboard contract ({settings:{...}}) and
    // the single-setting contract ({key,value}) to avoid breaking the admin UI.
    const values = body.settings && typeof body.settings === "object" && !Array.isArray(body.settings)
      ? body.settings
      : (typeof body.key === "string" ? { [body.key]: body.value } : null);
    if (!values || Object.keys(values).length === 0) return jsonError("No settings were provided.", 400, request);
    const allowed = new Set(["usd_ngn_rate", "maintenance_mode", "support_telegram", "support_email", "global_markup", "visual_number_timeout_minutes", "visual_number_supplier_cancel_seconds", "visual_number_customer_refund_seconds"]);
    const mergedSettings = {};
    for (const key of ["visual_number_supplier_cancel_seconds", "visual_number_customer_refund_seconds"]) {
      const existing = await env.DB.prepare("SELECT setting_value FROM app_settings WHERE setting_key=?").bind(key).first();
      mergedSettings[key] = Number(values[key] ?? existing?.setting_value ?? (key === "visual_number_supplier_cancel_seconds" ? 255 : 270));
    }
    if (mergedSettings.visual_number_supplier_cancel_seconds > mergedSettings.visual_number_customer_refund_seconds) return jsonError("Supplier cancellation time must be at or before the customer refund time.", 400, request);
    const now = new Date().toISOString();
    const statements = [];
    for (const [key, rawValue] of Object.entries(values)) {
      if (!allowed.has(key) || !["string", "number", "boolean"].includes(typeof rawValue)) return jsonError(`Invalid or unsupported setting: ${key}`, 400, request);
      const value = String(rawValue);
      if (value.length > 500) return jsonError(`Setting is too long: ${key}`, 400, request);
      if (key === "usd_ngn_rate" && (!Number.isFinite(Number(value)) || Number(value) <= 0)) return jsonError("Invalid exchange rate.", 400, request);
      if (key === "global_markup" && (!Number.isFinite(Number(value)) || Number(value) < 0)) return jsonError("Global markup must be a non-negative number.", 400, request);
      if (key === "visual_number_timeout_minutes" && (!Number.isInteger(Number(value)) || Number(value) < 5 || Number(value) > 60)) return jsonError("Visual Numbers timeout must be between 5 and 60 minutes.", 400, request);
      if (["visual_number_supplier_cancel_seconds", "visual_number_customer_refund_seconds"].includes(key) && (!Number.isInteger(Number(value)) || Number(value) < 0 || Number(value) > 3600)) return jsonError("Visual Numbers timer values must be whole seconds from 0 to 3600.", 400, request);
      if (key === "maintenance_mode" && !["true", "false"].includes(value.toLowerCase())) return jsonError("Maintenance mode must be true or false.", 400, request);
      statements.push(env.DB.prepare(`INSERT INTO app_settings (setting_key, setting_value, updated_at, updated_by) VALUES (?, ?, ?, ?) ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = excluded.updated_at, updated_by = excluded.updated_by`).bind(key, value, now, admin.id));
    }
    await env.DB.batch(statements);
    return respond({ ok: true, settings: Object.fromEntries(Object.entries(values).map(([k,v]) => [k, String(v)])) }, 200, request);
  }
  if (method === "POST" && path === "/api/admin/wallet/adjust") {
    const body = await readBody(request);
    if (!body) return jsonError("Invalid JSON.", 400, request);
    const customerId = String(body.customerId || "").trim();
    const currency = String(body.currency || "").toUpperCase();
    const action = String(body.action || "").toLowerCase();
    const amountMinor = Number(body.amount_minor);
    const note = String(body.note || "").trim().slice(0, 500);
    if (!customerId || !["NGN", "USD"].includes(currency) || !["add", "redeem"].includes(action)) {
      return jsonError("Provide a customer, currency, and add/redeem action.", 400, request);
    }
    if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0) {
      return jsonError("Amount must be a positive integer in minor units (kobo for NGN, cents for USD).", 400, request);
    }
    const exists = await env.DB.prepare("SELECT id FROM customers WHERE id = ?").bind(customerId).first();
    if (!exists) return jsonError("Customer not found.", 404, request);

    const now = new Date().toISOString();
    const delta = action === "add" ? amountMinor : -amountMinor;
    const reference = `ADMIN-${crypto.randomUUID()}`;
    const createWallet = env.DB.prepare(`
      INSERT OR IGNORE INTO wallets (id, customer_id, currency, balance_minor, updated_at)
      VALUES (?, ?, ?, 0, ?)
    `).bind(crypto.randomUUID(), customerId, currency, now);
    const updateWallet = env.DB.prepare(`
      UPDATE wallets SET balance_minor=balance_minor+?, updated_at=?
      WHERE customer_id=? AND currency=? AND balance_minor+?>=0
    `).bind(delta, now, customerId, currency, delta);
    const audit = env.DB.prepare(`
      INSERT INTO wallet_admin_actions
        (admin_id, customer_id, currency, action, amount_minor, note, created_at)
      SELECT CASE WHEN changes()=1 THEN ? ELSE NULL END, ?, ?, ?, ?, ?, ?
    `).bind(admin.id, customerId, currency, action, amountMinor, note, now);
    const transaction = env.DB.prepare(`
      INSERT INTO transactions
        (id, customer_id, type, currency, amount_minor, status, reference, description, created_at)
      SELECT ?, CASE WHEN changes()=1 THEN ? ELSE NULL END,
             ?, ?, ?, 'successful', ?, ?, ?
    `).bind(
      crypto.randomUUID(), customerId, `admin_${action}`, currency, delta,
      reference, note || `Admin ${action} wallet balance`, now
    );

    try {
      const results = await env.DB.batch([createWallet, updateWallet, audit, transaction]);
      if (
        Number(results[1]?.meta?.changes || 0) !== 1 ||
        Number(results[2]?.meta?.changes || 0) !== 1 ||
        Number(results[3]?.meta?.changes || 0) !== 1
      ) {
        return jsonError("Wallet adjustment could not be completed. Check the wallet balance and try again.", 409, request);
      }
    } catch (error) {
      console.error("Admin wallet adjustment rolled back:", error?.message || error);
      return jsonError("Wallet adjustment could not be completed. Check the wallet balance and try again.", 409, request);
    }

    const wallet = await env.DB.prepare("SELECT currency, balance_minor, updated_at FROM wallets WHERE customer_id = ? AND currency = ?")
      .bind(customerId, currency).first();
    return respond({ ok: true, customerId, action, amount_minor: amountMinor, wallet }, 200, request);
  }

  if (method === "GET" && path.startsWith("/api/admin/customers/") && path.endsWith("/wallets")) {
    const customerId = path.slice("/api/admin/customers/".length, -"/wallets".length).replace(/\/$/, "");
    const customer = await env.DB.prepare("SELECT id, email, email_verified, status, created_at FROM customers WHERE id = ?").bind(customerId).first();
    if (!customer) return jsonError("Customer not found.", 404, request);
    await ensureCustomerWallets(env, customerId);
    const wallets = await env.DB.prepare("SELECT currency, balance_minor, updated_at FROM wallets WHERE customer_id = ? ORDER BY currency").bind(customerId).all();
    return respond({ ok: true, customer, wallets: wallets.results }, 200, request);
  }

  if (method === "GET" && path === "/api/admin/customers") {
    const q = String(url.searchParams.get("q") || "").trim().slice(0, 100);
    const result = await env.DB.prepare(`SELECT id, email, email_verified, status, created_at
      FROM customers WHERE email LIKE ? ORDER BY created_at DESC LIMIT 100`).bind(`%${q}%`).all();
    const customers = [];
    for (const item of result.results || []) {
      const balances = await env.DB.prepare("SELECT currency, balance_minor FROM wallets WHERE customer_id=?").bind(item.id).all();
      customers.push({ ...item, wallets: balances.results || [] });
    }
    return respond({ ok: true, customers }, 200, request);
  }

  if (method === "GET" && path === "/api/admin/wallet/deposits") {
    const result = await env.DB.prepare(`SELECT d.*, c.email FROM wallet_deposits d
      JOIN customers c ON c.id=d.customer_id ORDER BY d.created_at DESC LIMIT 100`).all();
    return respond({ ok: true, deposits: result.results || [] }, 200, request);
  }

  if (method === "GET" && path === "/api/admin/providers/status") {
    const rows = await env.DB.prepare("SELECT provider, product, enabled, verification_status, last_test_at, last_test_message FROM provider_configs ORDER BY provider, product").all();
    const configs = rows.results || [];
    const find = (provider, product, legacyProvider = null) => configs.find(x => String(x.provider).toLowerCase() === provider && String(x.product).toLowerCase() === product) || (legacyProvider ? configs.find(x => String(x.provider).toLowerCase() === legacyProvider && String(x.product).toLowerCase() === product) : null) || null;
    return respond({ ok: true, providers: {
      youngpg: { visualNumbers: find("youngpg_virtual", "visual_numbers", "youngpg"), socialLogs: find("youngpg_media", "social_logs", "youngpg") },
      nexar: { officialNumbers: { status: "pending_api_access" }, socialBoosting: find("nexar", "social_boosting") || { status: "not_tested", enabled: 0, verification_status: "not_configured" } }
    } }, 200, request);
  }

  if (method === "GET" && path === "/api/admin/pricing/rules") {
    const result = await env.DB.prepare("SELECT * FROM pricing_rules ORDER BY provider, product, country, service LIMIT 1000").all();
    return respond({ ok: true, rules: result.results || [] }, 200, request);
  }

  if (method === "POST" && path === "/api/admin/pricing/rules") {
    const body = await readBody(request);
    const provider = String(body?.provider || "*").trim().toLowerCase();
    const product = String(body?.product || "*").trim().toLowerCase();
    const country = String(body?.country || "*").trim();
    const service = String(body?.service || "*").trim();
    const markupType = String(body?.markup_type || "percent").toLowerCase();
    const markupValue = Number(body?.markup_value);
    if (!body || !["percent", "fixed"].includes(markupType) || !Number.isFinite(markupValue) || markupValue < 0 || markupValue > 1000000) {
      return jsonError("Provide a valid markup type and non-negative markup value.", 400, request);
    }
    const now = new Date().toISOString();
    await env.DB.prepare(`INSERT INTO pricing_rules
      (id, provider, product, country, service, markup_type, markup_value, active, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(provider, product, country, service) DO UPDATE SET
        markup_type=excluded.markup_type, markup_value=excluded.markup_value,
        active=excluded.active, updated_at=excluded.updated_at`)
      .bind(crypto.randomUUID(), provider, product, country, service, markupType, markupValue, body.active === false ? 0 : 1, now).run();
    await env.DB.prepare("INSERT INTO audit_logs (admin_id, action, detail, created_at) VALUES (?, ?, ?, ?)")
      .bind(admin.id, "pricing.rule.updated", JSON.stringify({ provider, product, country, service, markupType, markupValue }).slice(0, 1000), now).run();
    return respond({ ok: true, message: "Pricing rule saved." }, 200, request);
  }

  if (method === "GET" && path === "/api/admin/audit") {
    const result = await env.DB.prepare("SELECT action, detail, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100").all();
    return respond({ ok: true, logs: result.results }, 200, request);
  }
  return jsonError("Endpoint not found.", 404, request);
}

async function processExpiredVisualNumberOrders(env) {
  await ensureVisualOrderSchema(env);
  const due = await env.DB.prepare(`SELECT id, customer_id, provider_order_id, provider_phone, provider_cancel_at,
      expires_at, provider_refund_confirmed, status
    FROM orders WHERE category='visual_numbers' AND provider='youngpg_virtual' AND status IN ('processing','review')
      AND provider_order_id IS NOT NULL AND COALESCE(provider_refund_confirmed,0)=0
    ORDER BY created_at ASC LIMIT 100`).all();
  let checked = 0, providerConfirmed = 0, completed = 0, deferred = 0;
  for (const order of due.results || []) {
    checked++;
    try {
      const result = await attemptVisualProviderCancellation(env, order);
      if (result.confirmed) providerConfirmed++;
      else if (result.completed) completed++;
      else if (result.reason !== 'not_due') deferred++;
    } catch (error) {
      deferred++;
      console.error('Visual Numbers automatic status check deferred:', order.id, error?.message || error);
    }
  }
  // Provider confirmation is recorded here; customer wallet credit is only made
  // when the customer presses Refund after their configured timer has elapsed.
  return { checked, providerConfirmed, completed, deferred };
}


export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      const origin = request.headers.get("Origin") || "";
      if (origin && !ALLOWED_ORIGINS.has(origin)) return new Response(null, { status: 403, headers: corsHeaders(request) });
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }
    try { return await handle(request, env); }
    catch (error) {
      console.error("Speedy.ng API error:", error?.message || String(error));
      return jsonError("Server error. Check Worker logs.", 500, request);
    }
  },
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(processExpiredVisualNumberOrders(env));
  }
};
