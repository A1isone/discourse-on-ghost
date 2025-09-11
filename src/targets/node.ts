import process from "node:process";
import { config as loadEnv } from "dotenv";
import express, { type Request, type Response, type RequestHandler } from "express";
import cookieParser from "cookie-parser";
import axios from "axios";
import crypto from "crypto";
import jwt from "jsonwebtoken"; // For Ghost Admin API and session cookies

import { deferGetConfig } from "../services/config.js";
import { useRequestLogging } from "../controllers/middleware.js";
import { bootstrapInjector } from "../services/dependency-injection.js";
import { RoutingManager } from "../routing.js";
import { core, envToConfigMapping } from "./shared-node.js";

loadEnv();

const config = bootstrapInjector(core, deferGetConfig(process.env, envToConfigMapping));
if (!config) {
  process.exit(1);
}

const app = express();
export { app };

app.disable("x-powered-by");
app.use(cookieParser());
app.use(useRequestLogging());

// ------------------------- ENV -------------------------
const getEnv = (k: string) => (process.env[k] ?? "").trim();
const SSO_SECRET = getEnv("DISCOURSE_SSO_SECRET");
const DISCOURSE_URL = getEnv("DISCOURSE_URL");
const GHOST_URL = getEnv("GHOST_URL");
const GHOST_ADMIN_KEY = getEnv("GHOST_ADMIN_API_KEY"); // "id:secret"
const SESSION_SECRET = getEnv("SESSION_SECRET");
const SESSION_COOKIE = "dog_member";
const SESSION_TTL_SECONDS = 10 * 60;

// ------------------------- Helpers -------------------------
function createGhostAdminToken(): string {
  const [id, secret] = GHOST_ADMIN_KEY.split(":");
  return jwt.sign({}, Buffer.from(secret, "hex"), {
    keyid: id,
    algorithm: "HS256",
    expiresIn: "5m",
    audience: "/v5/admin/",
  });
}

/**
 * Compute an HMAC-SHA256 signature (hex) for a base64-encoded SSO payload using the configured SSO secret.
 *
 * @param payloadBase64 - The base64-encoded payload to sign.
 * @returns The hex-encoded HMAC-SHA256 digest.
 */
function signHmac(payloadBase64: string): string {
  return crypto.createHmac("sha256", SSO_SECRET).update(payloadBase64).digest("hex");
}

/**
 * Create a signed JWT session token for a user payload.
 *
 * The token is signed with HS256 and embeds the provided payload; it expires after SESSION_TTL_SECONDS.
 *
 * @param payload - Claims to include in the token (e.g., `{ sub, email, name, iat, exp }`)
 * @param secret - HMAC secret used to sign the token
 * @returns A compact JWT string usable as the session cookie value
 */
function signSessionJWT(payload: object, secret: string): string {
  return jwt.sign(payload, secret, {
    algorithm: "HS256",
    expiresIn: SESSION_TTL_SECONDS,
  });
}

/**
 * Verifies a JWT session token and returns its decoded payload or null if invalid.
 *
 * Attempts to verify `token` using `secret` via jsonwebtoken; on success returns the decoded payload (typically an object with session claims), and on failure returns `null` without throwing.
 *
 * @param token - The JWT string to verify.
 * @param secret - The signing secret used to verify the token.
 * @returns The decoded token payload on successful verification, or `null` if verification fails.
 */
function verifySessionJWT(token: string, secret: string): null | any {
  try {
    return jwt.verify(token, secret);
  } catch {
    return null;
  }
}

// ------------------------- Routes -------------------------
app.get("/health", (_req, res) => res.status(200).send("OK"));

// ------------------------- login-from-ghost -------------------------
const loginFromGhost: RequestHandler = async (_req: Request, res: Response) => {
  core.logger.info("Starting login-from-ghost...");

  try {
    if (!GHOST_URL || !GHOST_ADMIN_KEY || !SESSION_SECRET) {
      core.logger.error("Missing Ghost config");
      return res.status(500).send("Server missing Ghost config");
    }

    const token = createGhostAdminToken();
    const ghostResp = await axios.get(`${GHOST_URL}/ghost/api/admin/members/`, {
      headers: { Authorization: `Ghost ${token}` },
      params: { limit: 1, order: "last_seen_at desc" },
    });

    const member = ghostResp.data?.members?.[0];
    if (!member) {
      core.logger.warn("No member found, redirecting to sign-in");
      return res.redirect(`${GHOST_URL}/#/portal/signin`);
    }

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      sub: member.id,
      email: member.email,
      name: member.name || "",
      iat: now,
      exp: now + SESSION_TTL_SECONDS,
    };

    const cookie = signSessionJWT(payload, SESSION_SECRET);
    res.cookie(SESSION_COOKIE, cookie, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: SESSION_TTL_SECONDS * 1000,
      path: "/",
    });

    if (!DISCOURSE_URL) {
      core.logger.error("DISCOURSE_URL missing");
      return res.status(500).send("Missing DISCOURSE_URL");
    }

    core.logger.info(`Redirecting to Discourse: ${DISCOURSE_URL}`);
    return res.redirect(302, DISCOURSE_URL);

  } catch (err: any) {
    core.logger.error({ error: err?.response?.data || err.message }, "login-from-ghost failed");
    console.error(err);
    return res.status(500).send(`login-from-ghost failed: ${err.message}`);
  }
};

app.get("/login-from-ghost", loginFromGhost);

// ------------------------- discourse/sso -------------------------
const discourseSSOHandler: RequestHandler = async (req: Request, res: Response) => {
  core.logger.info("Starting discourse/sso...");

  try {
    if (!SSO_SECRET || !DISCOURSE_URL) {
      core.logger.error("Missing SSO_SECRET or DISCOURSE_URL");
      return res.status(500).send("Server misconfigured");
    }

    const sso = req.query.sso as string | undefined;
    const sig = req.query.sig as string | undefined;
    if (!sso || !sig) return res.status(400).send("Missing sso or sig");

    const expected = signHmac(sso);
    if (expected !== sig) return res.status(403).send("Invalid SSO signature");

    const decoded = Buffer.from(sso, "base64").toString("utf8");
    const params = new URLSearchParams(decoded);
    const nonce = params.get("nonce");
    if (!nonce) return res.status(400).send("Missing nonce");

    const token = req.cookies?.[SESSION_COOKIE] as string | undefined;
    const session = token ? verifySessionJWT(token, SESSION_SECRET) : null;
    if (!session || (typeof session === "object" && "exp" in session && (session.exp as number) <= Math.floor(Date.now() / 1000))) {
      return res.redirect(302, `${req.protocol}://${req.get("host")}/login-from-ghost`);
    }

    const ghostToken = createGhostAdminToken();
    const ghostResp = await axios.get(`${GHOST_URL}/ghost/api/admin/members/`, {
      headers: { Authorization: `Ghost ${ghostToken}` },
      params: { filter: `id:'${session.sub}'`, fields: "id,email,name" },
    });

    const member = ghostResp.data?.members?.[0];
    if (!member) return res.status(404).send("Member not found");

    // 🔥 Add fields to quietly create and activate accounts
    const identity = new URLSearchParams({
      nonce,
      external_id: member.id,
      email: member.email,
      username: (member.name || member.email.split("@")[0]).replace(/\s+/g, "_"),
      name: member.name || "",
      require_activation: "false",
      suppress_welcome_message: "true",
    });

    const b64 = Buffer.from(identity.toString(), "utf8").toString("base64");
    const returnSig = signHmac(b64);
    const redirectUrl = `${DISCOURSE_URL}/session/sso_login?sso=${encodeURIComponent(b64)}&sig=${returnSig}`;

    core.logger.info("Redirecting back to Discourse", { redirectUrl });
    return res.redirect(302, redirectUrl);

  } catch (err: any) {
    core.logger.error({ error: err?.response?.data || err.message }, "SSO handler error");
    console.error(err);
    return res.status(500).send(`SSO error: ${err.message}`);
  }
};

app.get("/discourse/sso", discourseSSOHandler);

// ------------------------- Start Server -------------------------
const routingManager = new RoutingManager();
routingManager.addAllRoutes(app);

app.listen(config.port, "0.0.0.0", () => {
  core.logger.info(`Listening on http://0.0.0.0:${config.port}`);
});

app.listen(config.port, "0.0.0.0", () => {
  core.logger.info(`Listening on http://0.0.0.0:${config.port}`);
});
