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
    audience: "/v5/admin/",
  });
}

function signHmac(payloadBase64: string): string {
  // --- FIX IS HERE ---
  return crypto.createHmac("sha256", SSO_SECRET).update(payloadBase64).digest("hex");
}

function signSessionJWT(payload: object, secret: string): string {
  return jwt.sign(payload, secret, {
    algorithm: "HS256",
  });
}

function verifySessionJWT(token: string, secret: string): null | any {
  try {
    return jwt.verify(token, secret);
  } catch {
    return null;
  }
}

function createDiscourseSsoUrl(member: { id: string; email: string; name: string | null }, nonce: string): string {
  if (!DISCOURSE_URL || !SSO_SECRET) {
    throw new Error("Cannot create SSO URL, DISCOURSE_URL or SSO_SECRET is not configured.");
  }

  const ssoParams = new URLSearchParams({
    nonce,
    external_id: member.id,
    email: member.email,
    username: (member.name || member.email.split("@")[0]).replace(/\s+/g, "_"),
    name: member.name || "",
    require_activation: "false",
    suppress_welcome_message: "true",
  });

  const ssoBase64 = Buffer.from(ssoParams.toString(), "utf8").toString("base64");
  const ssoSignature = signHmac(ssoBase64);
  
  return `${DISCOURSE_URL}/session/sso_login?sso=${encodeURIComponent(ssoBase64)}&sig=${ssoSignature}`;
}

// ------------------------- Routes -------------------------
app.get("/health", (_req, res) => res.status(200).send("OK"));

// ------------------------- login-from-ghost -------------------------
const loginFromGhost: RequestHandler = async (req: Request, res: Response) => {
  core.logger.info("Starting login-from-ghost...");
  
  try {
    if (!GHOST_URL || !GHOST_ADMIN_KEY || !SESSION_SECRET || !DISCOURSE_URL || !SSO_SECRET) {
      core.logger.error("Missing server configuration");
      return res.status(500).send("Server is missing required configuration");
    }

    let nonce: string | null = null;
    const sso = req.query.sso as string | undefined;
    const sig = req.query.sig as string | undefined;

    if (sso && sig) {
      core.logger.info("Received SSO request from Discourse, extracting nonce...");
      const expected = signHmac(sso);
      if (expected !== sig) return res.status(403).send("Invalid SSO signature from Discourse");

      const decoded = Buffer.from(sso, "base64").toString("utf8");
      const params = new URLSearchParams(decoded);
      nonce = params.get("nonce");
      if (!nonce) return res.status(400).send("Missing nonce from Discourse payload");
    } else {
      core.logger.info("No SSO params from Discourse, generating a new nonce...");
      nonce = crypto.randomBytes(16).toString("hex");
    }
    
    let member: any = null;
    const memberId = req.query.member_id as string | undefined;

    const ghostToken = createGhostAdminToken();
    
    if (memberId) {
        core.logger.info(`Member ID found in query: ${memberId}. Fetching member...`);
        const ghostResp = await axios.get(`${GHOST_URL}/ghost/api/admin/members/${memberId}/`, {
            headers: { Authorization: `Ghost ${ghostToken}` },
        });
        member = ghostResp.data?.members?.[0];
    } else {
        core.logger.info("No member ID in query. Assuming Discourse-initiated flow, fetching most recent member...");
        const ghostResp = await axios.get(`${GHOST_URL}/ghost/api/admin/members/`, {
            headers: { Authorization: `Ghost ${ghostToken}` },
            params: { limit: 1, order: "last_seen_at desc" },
        });
        member = ghostResp.data?.members?.[0];
    }
    
    if (!member) {
      core.logger.error(`Could not find a member. Redirecting to Ghost Portal to sign in.`);
      return res.redirect(`${GHOST_URL}/#/portal/signin`);
    }

    const now = Math.floor(Date.now() / 1000);
    const sessionPayload = {
      sub: member.id,
      email: member.email,
      name: member.name || "",
      iat: now,
      exp: now + SESSION_TTL_SECONDS,
    };

    const cookie = signSessionJWT(sessionPayload, SESSION_SECRET);
    res.cookie(SESSION_COOKIE, cookie, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: SESSION_TTL_SECONDS * 1000,
      path: "/",
    });
    
    const ssoUrl = createDiscourseSsoUrl(member, nonce);
    
    core.logger.info(`Redirecting to Discourse SSO URL for member: ${member.email}`);
    return res.redirect(302, ssoUrl);

  } catch (err: any) {
    core.logger.error({ error: err?.response?.data || err.message }, "login-from-ghost failed");
    console.error(err);
    return res.status(500).send(`login-from-ghost failed: ${err.message}`);
  }
};

app.get("/login-from-ghost", loginFromGhost);

// ------------------------- discourse/sso (Legacy Fallback) -------------------------
const discourseSSOHandler: RequestHandler = async (_req: Request, res: Response) => {
  core.logger.info("Redirecting from legacy SSO endpoint to login-from-ghost.");
  return res.redirect(302, `/login-from-ghost`);
};

app.get("/discourse/sso", discourseSSOHandler);

// ------------------------- Start Server -------------------------
const routingManager = new RoutingManager();
routingManager.addAllRoutes(app);

app.listen(config.port, "0.0.0.0", () => {
  core.logger.info(`Listening on http://0.0.0.0:${config.port}`);
});
