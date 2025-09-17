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
  return crypto.createHmac("sha256", SSO_SECRET).update(payloadBase64).digest("hex");
}

// --- JWT session helpers ---
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

// ------------------------- Routes -------------------------
app.get("/health", (_req, res) => res.status(200).send("OK"));

// ------------------------- login-from-ghost -------------------------
// MODIFIED: This handler now correctly initiates SSO with Discourse
const loginFromGhost: RequestHandler = async (req: Request, res: Response) => {
  core.logger.info("Starting login-from-ghost...");

  try {
    // This part is modified to check the session first
    const token = req.cookies?.[SESSION_COOKIE] as string | undefined;
    const session = token ? verifySessionJWT(token, SESSION_SECRET) : null;

    if (!session) {
      // If no session, redirect to Ghost to create one
      core.logger.info("No session found, redirecting to Ghost portal to log in.");
      // The return URL will bring the user back here to complete the SSO handshake
      const returnUrl = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
      return res.redirect(
        `${GHOST_URL}/#/portal/signin?redirect=${encodeURIComponent(returnUrl)}`
      );
    }
    
    if (!DISCOURSE_URL || !SSO_SECRET) {
      core.logger.error("DISCOURSE_URL or SSO_SECRET missing");
      return res.status(500).send("Server misconfigured");
    }

    // NEW: Logic to create a new SSO payload and redirect to Discourse
    const nonce = crypto.randomBytes(16).toString("hex");
    const payload = new URLSearchParams({
        nonce,
        return_sso_url: `${DISCOURSE_URL}/session/sso_login`,
    }).toString();

    const payloadBase64 = Buffer.from(payload).toString('base64');
    const signature = signHmac(payloadBase64);

    const redirectUrl = `${DISCOURSE_URL}/session/sso_provider?sso=${payloadBase64}&sig=${signature}`;

    core.logger.info(`Redirecting to Discourse to initiate SSO: ${redirectUrl}`);
    return res.redirect(302, redirectUrl);

  } catch (err: any) {
    core.logger.error({ error: err?.response?.data || err.message }, "login-from-ghost failed");
    console.error(err);
    return res.status(500).send(`login-from-ghost failed: ${err.message}`);
  }
};

app.get("/login-from-ghost", loginFromGhost);

// ------------------------- discourse/sso -------------------------
// UNCHANGED: This handler correctly processes the callback from Discourse
const discourseSSOHandler: RequestHandler = async (req: Request, res: Response) => {
  core.logger.info("Starting discourse/sso...");

  try {
    if (!SSO_SECRET || !DISCOURSE_URL || !GHOST_URL || !GHOST_ADMIN_KEY || !SESSION_SECRET) {
      core.logger.error("Missing required server configuration");
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
    
    // If session is invalid, redirect to the start of the login flow
    if (!session || (typeof session === "object" && "exp" in session && (session.exp as number) <= Math.floor(Date.now() / 1000))) {
      core.logger.warn("Invalid or expired session during SSO callback, restarting login flow.");
      return res.redirect(302, `/login-from-ghost`);
    }

    // Now we use the valid session to get member details
    const ghostToken = createGhostAdminToken();
    const ghostResp = await axios.get(`${GHOST_URL}/ghost/api/admin/members/${session.sub}/`, {
      headers: { Authorization: `Ghost ${ghostToken}` },
      params: { fields: "id,email,name" },
    });

    const member = ghostResp.data?.members?.[0];
    if (!member) {
      core.logger.error(`Member with ID ${session.sub} not found in Ghost.`);
      return res.status(404).send("Member not found");
    }

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

    core.logger.info("Redirecting back to Discourse to complete login", { redirectUrl });
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
