// server/_core/index.ts
import "dotenv/config";
import express2 from "express";
import { createServer } from "http";
import net from "net";
import { createExpressMiddleware } from "@trpc/server/adapters/express";

// shared/const.ts
var COOKIE_NAME = "app_session_id";
var ONE_YEAR_MS = 1e3 * 60 * 60 * 24 * 365;
var AXIOS_TIMEOUT_MS = 3e4;
var UNAUTHED_ERR_MSG = "Please login (10001)";
var NOT_ADMIN_ERR_MSG = "You do not have required permission (10002)";
var OAUTH_STATE_COOKIE = "__Host-oauth_state";
var decodeOAuthState = (state) => {
  let decoded;
  try {
    decoded = atob(state);
  } catch {
    return { redirectUri: "" };
  }
  try {
    const parsed = JSON.parse(decoded);
    if (parsed && typeof parsed.redirectUri === "string") return parsed;
  } catch {
  }
  return { redirectUri: decoded };
};

// server/_core/oauth.ts
import { parse as parseCookieHeader2 } from "cookie";

// server/db.ts
import { desc, eq } from "drizzle-orm";
import { createHash } from "node:crypto";
import { drizzle } from "drizzle-orm/mysql2";

// drizzle/schema.ts
import { int, index, mysqlEnum, mysqlTable, text, timestamp, varchar } from "drizzle-orm/mysql-core";
var users = mysqlTable("users", {
  id: int("id").autoincrement().primaryKey(),
  openId: varchar("openId", { length: 64 }).notNull().unique(),
  name: text("name"),
  email: varchar("email", { length: 320 }),
  loginMethod: varchar("loginMethod", { length: 64 }),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt").defaultNow().onUpdateNow().notNull(),
  lastSignedIn: timestamp("lastSignedIn").defaultNow().notNull()
});
var scans = mysqlTable(
  "scans",
  {
    id: int("id").autoincrement().primaryKey(),
    sessionId: varchar("sessionId", { length: 64 }).notNull(),
    inputMode: mysqlEnum("inputMode", ["message", "link", "screenshot", "document"]).notNull(),
    contentHash: varchar("contentHash", { length: 64 }).notNull(),
    riskScore: int("riskScore").notNull(),
    verdict: varchar("verdict", { length: 32 }).notNull(),
    source: varchar("source", { length: 32 }).notNull(),
    signals: text("signals").notNull(),
    createdAt: timestamp("createdAt").defaultNow().notNull()
  },
  (table) => ({
    sessionCreatedIdx: index("scans_session_created_idx").on(table.sessionId, table.createdAt),
    createdIdx: index("scans_created_idx").on(table.createdAt)
  })
);

// server/_core/env.ts
var ENV = {
  appId: process.env.VITE_APP_ID ?? "",
  cookieSecret: process.env.JWT_SECRET ?? "",
  databaseUrl: process.env.DATABASE_URL ?? "",
  oAuthServerUrl: process.env.OAUTH_SERVER_URL ?? "",
  ownerOpenId: process.env.OWNER_OPEN_ID ?? "",
  isProduction: process.env.NODE_ENV === "production",
  forgeApiUrl: process.env.BUILT_IN_FORGE_API_URL ?? "",
  forgeApiKey: process.env.BUILT_IN_FORGE_API_KEY ?? ""
};

// server/db.ts
var _db = null;
async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(process.env.DATABASE_URL);
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}
function hashScanContent(value) {
  return createHash("sha256").update(value.trim()).digest("hex");
}
async function createScan(input) {
  const db = await getDb();
  if (!db) {
    throw new Error("Database is not available");
  }
  await db.insert(scans).values(input);
}
async function getRecentScans(sessionId) {
  const db = await getDb();
  if (!db) {
    return [];
  }
  return db.select({
    id: scans.id,
    risk: scans.riskScore,
    verdict: scans.verdict,
    mode: scans.inputMode,
    createdAt: scans.createdAt
  }).from(scans).where(eq(scans.sessionId, sessionId)).orderBy(desc(scans.createdAt)).limit(10);
}
async function upsertUser(user) {
  if (!user.openId) {
    throw new Error("User openId is required for upsert");
  }
  const db = await getDb();
  if (!db) {
    console.warn("[Database] Cannot upsert user: database not available");
    return;
  }
  try {
    const values = { openId: user.openId };
    const updateSet = {};
    const textFields = ["name", "email", "loginMethod"];
    const assignNullable = (field) => {
      const value = user[field];
      if (value === void 0) return;
      const normalized = value ?? null;
      values[field] = normalized;
      updateSet[field] = normalized;
    };
    textFields.forEach(assignNullable);
    if (user.lastSignedIn !== void 0) {
      values.lastSignedIn = user.lastSignedIn;
      updateSet.lastSignedIn = user.lastSignedIn;
    }
    if (user.role !== void 0) {
      values.role = user.role;
      updateSet.role = user.role;
    } else if (user.openId === ENV.ownerOpenId) {
      values.role = "admin";
      updateSet.role = "admin";
    }
    if (!values.lastSignedIn) values.lastSignedIn = /* @__PURE__ */ new Date();
    if (Object.keys(updateSet).length === 0) updateSet.lastSignedIn = /* @__PURE__ */ new Date();
    await db.insert(users).values(values).onDuplicateKeyUpdate({ set: updateSet });
  } catch (error) {
    console.error("[Database] Failed to upsert user:", error);
    throw error;
  }
}
async function getUserByOpenId(openId) {
  const db = await getDb();
  if (!db) return void 0;
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result.length > 0 ? result[0] : void 0;
}

// server/_core/cookies.ts
function isSecureRequest(req) {
  if (req.protocol === "https") return true;
  const forwardedProto = req.headers["x-forwarded-proto"];
  if (!forwardedProto) return false;
  const protoList = Array.isArray(forwardedProto) ? forwardedProto : forwardedProto.split(",");
  return protoList.some((proto) => proto.trim().toLowerCase() === "https");
}
function getSessionCookieOptions(req) {
  return {
    httpOnly: true,
    path: "/",
    sameSite: "none",
    secure: isSecureRequest(req)
  };
}

// shared/_core/errors.ts
var HttpError = class extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
    this.name = "HttpError";
  }
};
var ForbiddenError = (msg) => new HttpError(403, msg);

// server/_core/sdk.ts
import axios from "axios";
import { parse as parseCookieHeader } from "cookie";
import { SignJWT, jwtVerify } from "jose";
var isNonEmptyString = (value) => typeof value === "string" && value.length > 0;
var EXCHANGE_TOKEN_PATH = `/webdev.v1.WebDevAuthPublicService/ExchangeToken`;
var GET_USER_INFO_PATH = `/webdev.v1.WebDevAuthPublicService/GetUserInfo`;
var GET_USER_INFO_WITH_JWT_PATH = `/webdev.v1.WebDevAuthPublicService/GetUserInfoWithJwt`;
var OAuthService = class {
  constructor(client) {
    this.client = client;
    console.log("[OAuth] Initialized with baseURL:", ENV.oAuthServerUrl);
    if (!ENV.oAuthServerUrl) {
      console.error(
        "[OAuth] ERROR: OAUTH_SERVER_URL is not configured! Set OAUTH_SERVER_URL environment variable."
      );
    }
  }
  decodeState(state) {
    return decodeOAuthState(state).redirectUri;
  }
  async getTokenByCode(code, state) {
    const payload = {
      clientId: ENV.appId,
      grantType: "authorization_code",
      code,
      redirectUri: this.decodeState(state)
    };
    const { data } = await this.client.post(
      EXCHANGE_TOKEN_PATH,
      payload
    );
    return data;
  }
  async getUserInfoByToken(token) {
    const { data } = await this.client.post(
      GET_USER_INFO_PATH,
      {
        accessToken: token.accessToken
      }
    );
    return data;
  }
};
var createOAuthHttpClient = () => axios.create({
  baseURL: ENV.oAuthServerUrl,
  timeout: AXIOS_TIMEOUT_MS
});
var SDKServer = class {
  client;
  oauthService;
  constructor(client = createOAuthHttpClient()) {
    this.client = client;
    this.oauthService = new OAuthService(this.client);
  }
  deriveLoginMethod(platforms, fallback) {
    if (fallback && fallback.length > 0) return fallback;
    if (!Array.isArray(platforms) || platforms.length === 0) return null;
    const set = new Set(
      platforms.filter((p) => typeof p === "string")
    );
    if (set.has("REGISTERED_PLATFORM_EMAIL")) return "email";
    if (set.has("REGISTERED_PLATFORM_GOOGLE")) return "google";
    if (set.has("REGISTERED_PLATFORM_APPLE")) return "apple";
    if (set.has("REGISTERED_PLATFORM_MICROSOFT") || set.has("REGISTERED_PLATFORM_AZURE"))
      return "microsoft";
    if (set.has("REGISTERED_PLATFORM_GITHUB")) return "github";
    const first = Array.from(set)[0];
    return first ? first.toLowerCase() : null;
  }
  /**
   * Exchange OAuth authorization code for access token
   * @example
   * const tokenResponse = await sdk.exchangeCodeForToken(code, state);
   */
  async exchangeCodeForToken(code, state) {
    return this.oauthService.getTokenByCode(code, state);
  }
  /**
   * Get user information using access token
   * @example
   * const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);
   */
  async getUserInfo(accessToken) {
    const data = await this.oauthService.getUserInfoByToken({
      accessToken
    });
    const loginMethod = this.deriveLoginMethod(
      data?.platforms,
      data?.platform ?? data.platform ?? null
    );
    return {
      ...data,
      platform: loginMethod,
      loginMethod
    };
  }
  parseCookies(cookieHeader) {
    if (!cookieHeader) {
      return /* @__PURE__ */ new Map();
    }
    const parsed = parseCookieHeader(cookieHeader);
    return new Map(Object.entries(parsed));
  }
  getSessionSecret() {
    const secret = ENV.cookieSecret;
    return new TextEncoder().encode(secret);
  }
  /**
   * Create a session token for a Manus user openId
   * @example
   * const sessionToken = await sdk.createSessionToken(userInfo.openId);
   */
  async createSessionToken(openId, options = {}) {
    return this.signSession(
      {
        openId,
        appId: ENV.appId,
        name: options.name || ""
      },
      options
    );
  }
  async signSession(payload, options = {}) {
    const issuedAt = Date.now();
    const expiresInMs = options.expiresInMs ?? ONE_YEAR_MS;
    const expirationSeconds = Math.floor((issuedAt + expiresInMs) / 1e3);
    const secretKey = this.getSessionSecret();
    return new SignJWT({
      openId: payload.openId,
      appId: payload.appId,
      name: payload.name
    }).setProtectedHeader({ alg: "HS256", typ: "JWT" }).setExpirationTime(expirationSeconds).sign(secretKey);
  }
  async verifySession(cookieValue) {
    if (!cookieValue) {
      console.warn("[Auth] Missing session cookie");
      return null;
    }
    try {
      const secretKey = this.getSessionSecret();
      const { payload } = await jwtVerify(cookieValue, secretKey, {
        algorithms: ["HS256"]
      });
      const { openId, appId, name } = payload;
      if (!isNonEmptyString(openId) || !isNonEmptyString(appId) || !isNonEmptyString(name)) {
        console.warn("[Auth] Session payload missing required fields");
        return null;
      }
      return {
        openId,
        appId,
        name
      };
    } catch (error) {
      console.warn("[Auth] Session verification failed", String(error));
      return null;
    }
  }
  async getUserInfoWithJwt(jwtToken) {
    const payload = {
      jwtToken,
      projectId: ENV.appId
    };
    const { data } = await this.client.post(
      GET_USER_INFO_WITH_JWT_PATH,
      payload
    );
    const loginMethod = this.deriveLoginMethod(
      data?.platforms,
      data?.platform ?? data.platform ?? null
    );
    return {
      ...data,
      platform: loginMethod,
      loginMethod
    };
  }
  async authenticateRequest(req) {
    const cookies = this.parseCookies(req.headers.cookie);
    let sessionToken = cookies.get(COOKIE_NAME);
    if (!sessionToken) {
      const authHeader = req.headers.authorization;
      if (typeof authHeader === "string" && authHeader.startsWith("Bearer ")) {
        sessionToken = authHeader.slice(7);
      }
    }
    const session = await this.verifySession(sessionToken);
    if (!session) {
      throw ForbiddenError("Invalid session cookie");
    }
    if (session.openId.startsWith(CRON_OPEN_ID_PREFIX)) {
      const userInfo = await this.getUserInfoWithJwt(sessionToken ?? "");
      const taskUid = userInfo.taskUid ?? null;
      if (!taskUid) {
        throw ForbiddenError("Cron session missing task_uid");
      }
      return buildCronUser(userInfo);
    }
    const sessionUserId = session.openId;
    const signedInAt = /* @__PURE__ */ new Date();
    let user = await getUserByOpenId(sessionUserId);
    if (!user) {
      try {
        const userInfo = await this.getUserInfoWithJwt(sessionToken ?? "");
        await upsertUser({
          openId: userInfo.openId,
          name: userInfo.name || null,
          email: userInfo.email ?? null,
          loginMethod: userInfo.loginMethod ?? userInfo.platform ?? null,
          lastSignedIn: signedInAt
        });
        user = await getUserByOpenId(userInfo.openId);
      } catch (error) {
        console.error("[Auth] Failed to sync user from OAuth:", error);
        throw ForbiddenError("Failed to sync user info");
      }
    }
    if (!user) {
      throw ForbiddenError("User not found");
    }
    await upsertUser({
      openId: user.openId,
      lastSignedIn: signedInAt
    });
    return user;
  }
};
var CRON_OPEN_ID_PREFIX = "cron_";
function buildCronUser(userInfo) {
  const now = /* @__PURE__ */ new Date();
  return {
    id: -1,
    openId: userInfo.openId,
    name: userInfo.name || "Manus Scheduled Task",
    email: null,
    loginMethod: null,
    role: "user",
    createdAt: now,
    updatedAt: now,
    lastSignedIn: now,
    taskUid: userInfo.taskUid ?? void 0,
    isCron: true
  };
}
var sdk = new SDKServer();

// server/_core/oauth.ts
function getQueryParam(req, key) {
  const value = req.query[key];
  return typeof value === "string" ? value : void 0;
}
function registerOAuthRoutes(app) {
  app.get("/api/oauth/callback", async (req, res) => {
    const code = getQueryParam(req, "code");
    const state = getQueryParam(req, "state");
    if (!code || !state) {
      res.status(400).json({ error: "code and state are required" });
      return;
    }
    const { nonce } = decodeOAuthState(state);
    const expectedNonce = parseCookieHeader2(req.headers.cookie ?? "")[OAUTH_STATE_COOKIE];
    if (!nonce || nonce !== expectedNonce) {
      res.status(403).json({ error: "invalid oauth state" });
      return;
    }
    res.clearCookie(OAUTH_STATE_COOKIE, { path: "/", secure: true, sameSite: "none" });
    try {
      const tokenResponse = await sdk.exchangeCodeForToken(code, state);
      const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);
      if (!userInfo.openId) {
        res.status(400).json({ error: "openId missing from user info" });
        return;
      }
      await upsertUser({
        openId: userInfo.openId,
        name: userInfo.name || null,
        email: userInfo.email ?? null,
        loginMethod: userInfo.loginMethod ?? userInfo.platform ?? null,
        lastSignedIn: /* @__PURE__ */ new Date()
      });
      const sessionToken = await sdk.createSessionToken(userInfo.openId, {
        name: userInfo.name || "",
        expiresInMs: ONE_YEAR_MS
      });
      const cookieOptions = getSessionCookieOptions(req);
      res.cookie(COOKIE_NAME, sessionToken, { ...cookieOptions, maxAge: ONE_YEAR_MS });
      res.redirect(302, "/");
    } catch (error) {
      console.error("[OAuth] Callback failed", error);
      res.status(500).json({ error: "OAuth callback failed" });
    }
  });
}

// server/_core/storageProxy.ts
function registerStorageProxy(app) {
  app.get("/manus-storage/*", async (req, res) => {
    const key = req.params[0];
    if (!key) {
      res.status(400).send("Missing storage key");
      return;
    }
    if (!ENV.forgeApiUrl || !ENV.forgeApiKey) {
      res.status(500).send("Storage proxy not configured");
      return;
    }
    try {
      const forgeUrl = new URL(
        "v1/storage/presign/get",
        ENV.forgeApiUrl.replace(/\/+$/, "") + "/"
      );
      forgeUrl.searchParams.set("path", key);
      const forgeResp = await fetch(forgeUrl, {
        headers: { Authorization: `Bearer ${ENV.forgeApiKey}` }
      });
      if (!forgeResp.ok) {
        const body = await forgeResp.text().catch(() => "");
        console.error(`[StorageProxy] forge error: ${forgeResp.status} ${body}`);
        res.status(502).send("Storage backend error");
        return;
      }
      const { url } = await forgeResp.json();
      if (!url) {
        res.status(502).send("Empty signed URL from backend");
        return;
      }
      res.set("Cache-Control", "no-store");
      res.redirect(307, url);
    } catch (err) {
      console.error("[StorageProxy] failed:", err);
      res.status(502).send("Storage proxy error");
    }
  });
}

// server/routers.ts
import { z as z2 } from "zod";
import { TRPCError as TRPCError3 } from "@trpc/server";

// shared/scan.ts
var INPUT_MODES = ["message", "link", "screenshot", "document"];
var EXAMPLES = {
  bank: {
    label: "Bank alert",
    mode: "message",
    value: "URGENT: Your account will be suspended today. Verify your identity immediately at https://secure-firstnational.co/verify to avoid losing access. Reply YES to confirm."
  },
  delivery: {
    label: "Delivery text",
    mode: "message",
    value: "Your parcel could not be delivered. Pay the $2.99 redelivery fee within 12 hours: https://bit.ly/4parcel-fee"
  },
  link: {
    label: "Suspicious link",
    mode: "link",
    value: "https://microsoft-support-login.com/account/verify?session=8841"
  }
};
var URL_PATTERN = /https?:\/\/[^\s<>'"]+/i;
var SHORTENER_PATTERN = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|shorturl\.at|is\.gd)$/i;
var RISKY_TLD_PATTERN = /\.(zip|top|click|support|live|work|tk|gq|ml|cf|ru)$/i;
function inspectUrl(value) {
  const rawUrl = value.match(URL_PATTERN)?.[0]?.replace(/[),.!?]+$/, "");
  if (!rawUrl) return null;
  try {
    const parsed = new URL(rawUrl);
    const hostname = parsed.hostname.toLowerCase();
    const isShortened = SHORTENER_PATTERN.test(hostname);
    const isLookalike = /(microsoft-support|secure-firstnational|paypa1|appleid-security|amazon-account|netflix-billing)/i.test(hostname);
    const isDeepSubdomain = hostname.split(".").length >= 4;
    const hasRiskyTld = RISKY_TLD_PATTERN.test(hostname);
    const isSecure = parsed.protocol === "https:";
    const operatorNote = isLookalike ? "Brand-like hostname; verify through the official app instead." : isShortened ? "Short link hides the final destination." : hasRiskyTld ? "Unusual top-level domain deserves independent verification." : isSecure ? "Encrypted transport does not prove the site is legitimate." : "No HTTPS protection detected.";
    return {
      url: rawUrl,
      hostname,
      protocol: isSecure ? "HTTPS" : parsed.protocol === "http:" ? "HTTP" : "UNKNOWN",
      isSecure,
      isShortened,
      isLookalike,
      isDeepSubdomain,
      hasRiskyTld,
      operatorNote
    };
  } catch {
    return null;
  }
}
function analyzeScan(value, mode) {
  const text2 = value.trim();
  const signals = [];
  const urlInsight = inspectUrl(text2);
  const urgency = /(urgent|immediately|act now|within \d+ hours?|today|expires?|suspended|last warning|final notice)/i;
  const credentialRequest = /(verify (your )?(identity|account|details)|confirm (your )?(account|password|details)|login|sign in|one[- ]time|otp|password|security code)/i;
  const paymentRequest = /(?:\bpay\b|\bpayment\b|\bfee\b|\brefund\b|\bprize\b|\bgift card\b|\btransfer\b|\binvoice\b|\$\d|\bmoney\b)/i;
  const shortened = /(bit\.ly|tinyurl\.com|t\.co|goo\.gl|shorturl\.at)/i;
  const lookalike = /(microsoft-support|secure-firstnational|paypa1|appleid-security|amazon-account|netflix-billing)/i;
  const replyRequest = /(reply|text|call|click)\s+[A-Z0-9]+/i;
  if (urgency.test(text2)) {
    signals.push({ label: "Artificial urgency", detail: "The message pressures you to act before you have time to verify it.", tone: "critical", evidence: text2.match(urgency)?.[0] ?? "urgent language" });
  }
  if (credentialRequest.test(text2)) {
    signals.push({ label: "Credential request", detail: "It asks for access, identity, or security details through the message.", tone: "critical", evidence: text2.match(credentialRequest)?.[0] ?? "account verification" });
  }
  if (paymentRequest.test(text2)) {
    signals.push({ label: "Money is involved", detail: "A payment, fee, reward, or transfer makes this a high-value target for fraud.", tone: "warning", evidence: text2.match(paymentRequest)?.[0] ?? "payment language" });
  }
  if (shortened.test(text2)) {
    signals.push({ label: "Obscured destination", detail: "A shortened link hides the website you would actually visit.", tone: "critical", evidence: text2.match(shortened)?.[0] ?? "shortened URL" });
  }
  if (lookalike.test(text2)) {
    signals.push({ label: "Lookalike domain", detail: "The destination borrows a trusted brand name but is not the official domain.", tone: "critical", evidence: text2.match(lookalike)?.[0] ?? "brand-like domain" });
  }
  if (replyRequest.test(text2)) {
    signals.push({ label: "Reply-to-action", detail: "It asks you to respond from the same unverified conversation.", tone: "warning", evidence: text2.match(replyRequest)?.[0] ?? "reply instruction" });
  }
  if (mode === "link" && !/^https:\/\//i.test(text2)) {
    signals.push({ label: "Unencrypted link", detail: "This URL does not begin with HTTPS, so the connection may not be protected.", tone: "warning", evidence: "http://" });
  }
  if (urlInsight?.isDeepSubdomain) {
    signals.push({ label: "Deeply nested domain", detail: "Multiple subdomains can make the real owner of a destination harder to spot.", tone: "warning", evidence: urlInsight.hostname });
  }
  if (urlInsight?.hasRiskyTld) {
    signals.push({ label: "Risky top-level domain", detail: "This top-level domain is frequently used in throwaway or impersonation campaigns.", tone: "warning", evidence: urlInsight.hostname.split(".").slice(-1)[0] ?? "unusual TLD" });
  }
  if (signals.length === 0) {
    signals.push({ label: "No obvious trigger found", detail: "The quick scan did not find common scam patterns. That is not proof of safety.", tone: "info", evidence: "pattern scan" });
  }
  const signalWeights = {
    "Artificial urgency": 18,
    "Credential request": 22,
    "Money is involved": 14,
    "Obscured destination": 18,
    "Lookalike domain": 24,
    "Reply-to-action": 10,
    "Unencrypted link": 8,
    "Deeply nested domain": 7,
    "Risky top-level domain": 10,
    "No obvious trigger found": 0
  };
  const weightedRisk = 10 + signals.reduce((total, signal) => total + (signalWeights[signal.label] ?? 5), 0);
  const risk = Math.min(99, Math.max(8, weightedRisk));
  const verdict = risk >= 68 ? "High risk" : risk >= 40 ? "Needs review" : "Low risk";
  const summary = verdict === "High risk" ? "This message combines multiple patterns commonly used to rush people into unsafe clicks, replies, or payments." : verdict === "Needs review" ? "There are a few signals worth checking before you interact. Use an official channel to verify the request." : "Nothing in this quick scan looks immediately suspicious, but that is not proof of safety\u2014stay cautious with unexpected messages.";
  const nextSteps = verdict === "High risk" ? ["Do not click, reply, or share any code from this message.", "Open the organization\u2019s official app or type its website yourself.", "Block and report the sender after saving the message as evidence."] : verdict === "Needs review" ? ["Pause before clicking or sending information.", "Verify the request using a phone number or website you already trust.", "If the request is unexpected, treat it as suspicious and report it."] : ["Check the sender address and destination before continuing.", "Never share passwords or one-time codes in response to a message.", "When in doubt, verify through a separate trusted channel."];
  return {
    risk,
    verdict,
    summary,
    signals: signals.slice(0, 6),
    nextSteps,
    source: mode === "link" ? "URL quick scan" : mode === "screenshot" ? "Screenshot notes" : mode === "document" ? "Document scan" : "Message quick scan",
    urlInsight,
    riskBreakdown: {
      pressure: Math.min(100, urgency.test(text2) ? 85 : 12),
      access: Math.min(100, credentialRequest.test(text2) ? 90 : 8),
      money: Math.min(100, paymentRequest.test(text2) ? 78 : 6),
      destination: Math.min(100, urlInsight ? urlInsight.isLookalike || urlInsight.isShortened ? 92 : urlInsight.isSecure ? 30 : 72 : 5),
      behavior: Math.min(100, replyRequest.test(text2) ? 74 : 10)
    }
  };
}

// server/_core/systemRouter.ts
import { z } from "zod";

// server/_core/notification.ts
import { TRPCError } from "@trpc/server";
var TITLE_MAX_LENGTH = 1200;
var CONTENT_MAX_LENGTH = 2e4;
var trimValue = (value) => value.trim();
var isNonEmptyString2 = (value) => typeof value === "string" && value.trim().length > 0;
var buildEndpointUrl = (baseUrl) => {
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  return new URL(
    "webdevtoken.v1.WebDevService/SendNotification",
    normalizedBase
  ).toString();
};
var validatePayload = (input) => {
  if (!isNonEmptyString2(input.title)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification title is required."
    });
  }
  if (!isNonEmptyString2(input.content)) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: "Notification content is required."
    });
  }
  const title = trimValue(input.title);
  const content = trimValue(input.content);
  if (title.length > TITLE_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification title must be at most ${TITLE_MAX_LENGTH} characters.`
    });
  }
  if (content.length > CONTENT_MAX_LENGTH) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Notification content must be at most ${CONTENT_MAX_LENGTH} characters.`
    });
  }
  return { title, content };
};
async function notifyOwner(payload) {
  const { title, content } = validatePayload(payload);
  if (!ENV.forgeApiUrl) {
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service URL is not configured."
    });
  }
  if (!ENV.forgeApiKey) {
    throw new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: "Notification service API key is not configured."
    });
  }
  const endpoint = buildEndpointUrl(ENV.forgeApiUrl);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${ENV.forgeApiKey}`,
        "content-type": "application/json",
        "connect-protocol-version": "1"
      },
      body: JSON.stringify({ title, content })
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      console.warn(
        `[Notification] Failed to notify owner (${response.status} ${response.statusText})${detail ? `: ${detail}` : ""}`
      );
      return false;
    }
    return true;
  } catch (error) {
    console.warn("[Notification] Error calling notification service:", error);
    return false;
  }
}

// server/_core/trpc.ts
import { initTRPC, TRPCError as TRPCError2 } from "@trpc/server";
import superjson from "superjson";
var t = initTRPC.context().create({
  transformer: superjson
});
var router = t.router;
var publicProcedure = t.procedure;
var requireUser = t.middleware(async (opts) => {
  const { ctx, next } = opts;
  if (!ctx.user) {
    throw new TRPCError2({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }
  return next({
    ctx: {
      ...ctx,
      user: ctx.user
    }
  });
});
var protectedProcedure = t.procedure.use(requireUser);
var adminProcedure = t.procedure.use(
  t.middleware(async (opts) => {
    const { ctx, next } = opts;
    if (!ctx.user || ctx.user.role !== "admin") {
      throw new TRPCError2({ code: "FORBIDDEN", message: NOT_ADMIN_ERR_MSG });
    }
    return next({
      ctx: {
        ...ctx,
        user: ctx.user
      }
    });
  })
);

// server/_core/systemRouter.ts
var systemRouter = router({
  health: publicProcedure.input(
    z.object({
      timestamp: z.number().min(0, "timestamp cannot be negative")
    })
  ).query(() => ({
    ok: true
  })),
  notifyOwner: adminProcedure.input(
    z.object({
      title: z.string().min(1, "title is required"),
      content: z.string().min(1, "content is required")
    })
  ).mutation(async ({ input }) => {
    const delivered = await notifyOwner(input);
    return {
      success: delivered
    };
  })
});

// server/document.ts
import { PDFParse } from "pdf-parse";
import mammoth from "mammoth";
var MAX_FILE_BYTES = 10 * 1024 * 1024;
var TEXT_EXTENSIONS = /* @__PURE__ */ new Set([".txt", ".md", ".csv", ".json", ".html", ".htm", ".xml", ".log"]);
var DocumentInputError = class extends Error {
};
function extensionOf(fileName) {
  const lower = fileName.toLowerCase();
  const index2 = lower.lastIndexOf(".");
  return index2 >= 0 ? lower.slice(index2) : "";
}
async function extractDocumentText(fileName, mimeType, bytes) {
  if (bytes.length === 0) throw new DocumentInputError("The uploaded file is empty.");
  if (bytes.length > MAX_FILE_BYTES) throw new DocumentInputError("Files must be 10 MB or smaller.");
  const extension = extensionOf(fileName);
  const isPlainText = mimeType.startsWith("text/") || TEXT_EXTENSIONS.has(extension);
  if (isPlainText) {
    return bytes.toString("utf8").replace(/\u0000/g, "").trim();
  }
  if (mimeType === "application/pdf" || extension === ".pdf") {
    const parser = new PDFParse({ data: bytes });
    try {
      const result = await parser.getText();
      const text2 = result.text.replace(/\u0000/g, "").trim();
      if (!text2) {
        throw new DocumentInputError("This PDF has no selectable text. Image-only PDFs need OCR support.");
      }
      return text2;
    } finally {
      await parser.destroy();
    }
  }
  if (mimeType === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" || extension === ".docx") {
    const result = await mammoth.extractRawText({ buffer: bytes });
    const text2 = result.value.replace(/\u0000/g, "").trim();
    if (!text2) throw new DocumentInputError("This DOCX does not contain readable text.");
    return text2;
  }
  throw new DocumentInputError("Unsupported file type. Use PDF, DOCX, TXT, MD, CSV, JSON, HTML, or XML.");
}

// server/routers.ts
var scanInput = z2.object({
  value: z2.string().trim().min(1, "Paste a message or URL to scan").max(1e4, "Scan input is too long"),
  mode: z2.enum(INPUT_MODES),
  sessionId: z2.string().regex(/^[a-zA-Z0-9_-]{16,64}$/, "Invalid scan session")
});
var historyInput = z2.object({
  sessionId: z2.string().regex(/^[a-zA-Z0-9_-]{16,64}$/, "Invalid scan session")
});
var documentInput = z2.object({
  fileName: z2.string().trim().min(1).max(180),
  mimeType: z2.string().trim().max(120),
  dataBase64: z2.string().min(1).max(14e6),
  sessionId: z2.string().regex(/^[a-zA-Z0-9_-]{16,64}$/, "Invalid scan session")
});
var appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query((opts) => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return { success: true };
    })
  }),
  scan: router({
    analyze: publicProcedure.input(scanInput).mutation(async ({ input }) => {
      const result = analyzeScan(input.value, input.mode);
      await createScan({
        sessionId: input.sessionId,
        inputMode: input.mode,
        contentHash: hashScanContent(input.value),
        riskScore: result.risk,
        verdict: result.verdict,
        source: result.source,
        signals: JSON.stringify(result.signals.map(({ label, tone }) => ({ label, tone })))
      });
      return result;
    }),
    analyzeDocument: publicProcedure.input(documentInput).mutation(async ({ input, ctx }) => {
      try {
        const bytes = Buffer.from(input.dataBase64, "base64");
        const text2 = await extractDocumentText(input.fileName, input.mimeType, bytes);
        const boundedText = text2.slice(0, 1e4);
        const result = analyzeScan(boundedText, "document");
        await createScan({
          sessionId: input.sessionId,
          inputMode: "document",
          contentHash: hashScanContent(boundedText),
          riskScore: result.risk,
          verdict: result.verdict,
          source: result.source,
          signals: JSON.stringify(result.signals.map(({ label, tone }) => ({ label, tone })))
        });
        return { ...result, fileName: input.fileName, truncated: text2.length > boundedText.length };
      } catch (error) {
        if (error instanceof DocumentInputError) {
          throw new TRPCError3({ code: "BAD_REQUEST", message: error.message });
        }
        console.error("[Scan] Document extraction failed", { fileName: input.fileName, error, requestId: ctx.req.headers["x-request-id"] });
        throw new TRPCError3({ code: "BAD_REQUEST", message: "The document could not be read. Try a text-based PDF or DOCX." });
      }
    }),
    history: publicProcedure.input(historyInput).query(async ({ input }) => {
      const rows = await getRecentScans(input.sessionId);
      return rows.map((row) => ({
        id: row.id,
        mode: row.mode,
        label: row.mode === "link" ? EXAMPLES.link.label : row.mode === "document" ? "Document scan" : row.mode === "screenshot" ? "Screenshot scan" : "Message scan",
        risk: row.risk,
        verdict: row.verdict,
        createdAt: row.createdAt
      }));
    })
  })
});

// server/_core/context.ts
async function createContext(opts) {
  let user = null;
  try {
    user = await sdk.authenticateRequest(opts.req);
  } catch (error) {
    user = null;
  }
  return {
    req: opts.req,
    res: opts.res,
    user
  };
}

// server/_core/vite.ts
import express from "express";
import fs2 from "fs";
import { nanoid } from "nanoid";
import path2 from "path";
import { createServer as createViteServer } from "vite";

// vite.config.ts
import { jsxLocPlugin } from "@builder.io/vite-plugin-jsx-loc";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs";
import path from "node:path";
import { defineConfig } from "vite";
import { vitePluginManusRuntime } from "vite-plugin-manus-runtime";
var PROJECT_ROOT = import.meta.dirname;
var LOG_DIR = path.join(PROJECT_ROOT, ".manus-logs");
var MAX_LOG_SIZE_BYTES = 1 * 1024 * 1024;
var TRIM_TARGET_BYTES = Math.floor(MAX_LOG_SIZE_BYTES * 0.6);
function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}
function trimLogFile(logPath, maxSize) {
  try {
    if (!fs.existsSync(logPath) || fs.statSync(logPath).size <= maxSize) {
      return;
    }
    const lines = fs.readFileSync(logPath, "utf-8").split("\n");
    const keptLines = [];
    let keptBytes = 0;
    const targetSize = TRIM_TARGET_BYTES;
    for (let i = lines.length - 1; i >= 0; i--) {
      const lineBytes = Buffer.byteLength(`${lines[i]}
`, "utf-8");
      if (keptBytes + lineBytes > targetSize) break;
      keptLines.unshift(lines[i]);
      keptBytes += lineBytes;
    }
    fs.writeFileSync(logPath, keptLines.join("\n"), "utf-8");
  } catch {
  }
}
function writeToLogFile(source, entries) {
  if (entries.length === 0) return;
  ensureLogDir();
  const logPath = path.join(LOG_DIR, `${source}.log`);
  const lines = entries.map((entry) => {
    const ts = (/* @__PURE__ */ new Date()).toISOString();
    return `[${ts}] ${JSON.stringify(entry)}`;
  });
  fs.appendFileSync(logPath, `${lines.join("\n")}
`, "utf-8");
  trimLogFile(logPath, MAX_LOG_SIZE_BYTES);
}
function vitePluginManusDebugCollector() {
  return {
    name: "manus-debug-collector",
    transformIndexHtml(html) {
      if (process.env.NODE_ENV === "production") {
        return html;
      }
      return {
        html,
        tags: [
          {
            tag: "script",
            attrs: {
              src: "/__manus__/debug-collector.js",
              defer: true
            },
            injectTo: "head"
          }
        ]
      };
    },
    configureServer(server) {
      server.middlewares.use("/__manus__/logs", (req, res, next) => {
        if (req.method !== "POST") {
          return next();
        }
        const handlePayload = (payload) => {
          if (payload.consoleLogs?.length > 0) {
            writeToLogFile("browserConsole", payload.consoleLogs);
          }
          if (payload.networkRequests?.length > 0) {
            writeToLogFile("networkRequests", payload.networkRequests);
          }
          if (payload.sessionEvents?.length > 0) {
            writeToLogFile("sessionReplay", payload.sessionEvents);
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true }));
        };
        const reqBody = req.body;
        if (reqBody && typeof reqBody === "object") {
          try {
            handlePayload(reqBody);
          } catch (e) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: false, error: String(e) }));
          }
          return;
        }
        let body = "";
        req.on("data", (chunk) => {
          body += chunk.toString();
        });
        req.on("end", () => {
          try {
            const payload = JSON.parse(body);
            handlePayload(payload);
          } catch (e) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: false, error: String(e) }));
          }
        });
      });
    }
  };
}
var plugins = [react(), tailwindcss(), jsxLocPlugin(), vitePluginManusRuntime(), vitePluginManusDebugCollector()];
var vite_config_default = defineConfig({
  plugins,
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "client", "src"),
      "@shared": path.resolve(import.meta.dirname, "shared"),
      "@assets": path.resolve(import.meta.dirname, "attached_assets")
    }
  },
  envDir: path.resolve(import.meta.dirname),
  root: path.resolve(import.meta.dirname, "client"),
  publicDir: path.resolve(import.meta.dirname, "client", "public"),
  build: {
    outDir: path.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  },
  server: {
    host: true,
    allowedHosts: [
      ".manuspre.computer",
      ".manus.computer",
      ".manus-asia.computer",
      ".manuscomputer.ai",
      ".manusvm.computer",
      "localhost",
      "127.0.0.1"
    ],
    fs: {
      strict: true,
      deny: ["**/.*"]
    }
  }
});

// server/_core/vite.ts
async function setupVite(app, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    server: serverOptions,
    appType: "custom"
  });
  app.use(vite.middlewares);
  app.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path2.resolve(
        import.meta.dirname,
        "../..",
        "client",
        "index.html"
      );
      let template = await fs2.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app) {
  const distPath = process.env.NODE_ENV === "development" ? path2.resolve(import.meta.dirname, "../..", "dist", "public") : path2.resolve(import.meta.dirname, "public");
  if (!fs2.existsSync(distPath)) {
    console.error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app.use(express.static(distPath));
  app.use("*", (_req, res) => {
    res.sendFile(path2.resolve(distPath, "index.html"));
  });
}

// server/_core/index.ts
function isPortAvailable(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(port, () => {
      server.close(() => resolve(true));
    });
    server.on("error", () => resolve(false));
  });
}
async function findAvailablePort(startPort = 3e3) {
  for (let port = startPort; port < startPort + 20; port++) {
    if (await isPortAvailable(port)) {
      return port;
    }
  }
  throw new Error(`No available port found starting from ${startPort}`);
}
async function startServer() {
  const app = express2();
  const server = createServer(app);
  app.use(express2.json({ limit: "50mb" }));
  app.use(express2.urlencoded({ limit: "50mb", extended: true }));
  registerStorageProxy(app);
  registerOAuthRoutes(app);
  app.use(
    "/api/trpc",
    createExpressMiddleware({
      router: appRouter,
      createContext
    })
  );
  if (process.env.NODE_ENV === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const preferredPort = parseInt(process.env.PORT || "3000");
  const port = await findAvailablePort(preferredPort);
  if (port !== preferredPort) {
    console.log(`Port ${preferredPort} is busy, using port ${port} instead`);
  }
  server.listen(port, () => {
    console.log(`Server running on http://localhost:${port}/`);
  });
}
startServer().catch(console.error);
