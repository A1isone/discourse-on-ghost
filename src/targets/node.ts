import process from "node:process";
import { config as loadEnv } from "dotenv";
import express, { type Request, type Response, type RequestHandler } from "express";
import cookieParser from "cookie-parser";
import axios from "axios";
import crypto from "crypto";
import jwt from "jsonwebtoken";

// --- Boilerplate and Config Loading ---
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

// --- Environment Variables ---
const getEnv = (k: string) => (process.env[k] ?? "").trim();
const SSO_SECRET = getEnv("DISCOURSE_SSO_SECRET");
const DISCOURSE_URL = getEnv("DISCOURSE_URL");
const GHOST_URL = getEnv("GHOST_URL");
const GHOST_ADMIN_KEY = getEnv("GHOST_ADMIN_API_KEY");
const SESSION_SECRET = getEnv("SESSION_SECRET");
const SESSION_COOKIE = "sso_session";
const SESSION_TTL_SECONDS = 10 * 60; // 10 minutes
// --- Helper Functions ---

function createGhostAdminToken(): string {
  const [id, secret] = GHOST_ADMIN_KEY.split(":");
  return jwt.sign({}, Buffer.from(secret, "hex"), {
    keyid: id,
    algorithm: "HS256",
    audience: "/admin/",
    expiresIn: "5m",
  });
}

function signDiscourseHmac(payloadBase64: string): string {
  return crypto.createHmac("sha256", SSO_SECRET).update(payloadBase64).digest("hex");
}

function signSessionJWT(payload: object): string {
  return jwt.sign(payload, SESSION_SECRET, {
    algorithm: "HS256",
    expiresIn: SESSION_TTL_SECONDS,
  });
}

function verifySessionJWT(token: string): any | null {
  try {
    return jwt.verify(token, SESSION_SECRET);
  } catch {
    return null;
  }
}

// --- Routes ---

// STEP 1: The user clicks the community link, which directs them here.
app.get("/login-from-ghost", (req: Request, res: Response) => {
  core.logger.info("Step 1: Starting login flow. Redirecting to Ghost Portal.");
  const callbackUrl = `https://${req.get("host")}/ghost/callback`;
  const ghostSignInUrl = `${GHOST_URL}/#/portal?action=signin&redirect=${encodeURIComponent(callbackUrl)}`;
  return res.redirect(302, ghostSignInUrl);
});

// STEP 2: Ghost redirects the user here after a successful login.
const ghostCallback: RequestHandler = async (req: Request, res: Response) => {
  core.logger.info("Step 2: Received callback from Ghost.");
  const token = req.query.token as string | undefined;

  if (!token) {
    core.logger.error("Ghost callback is missing token.");
    return res.status(400).send("Callback from Ghost is missing the required token.");
  }

  try {
    const ghostAdminToken = createGhostAdminToken();
    const response = await axios.get(`${GHOST_URL}/ghost/api/admin/members/token/`, {
      headers: { Authorization: `Ghost ${ghostAdminToken}` },
      params: { token },
    });

    const member = response.data?.members?.[0];
    if (!member) {
      core.logger.error("Member not found for the provided token.");
      return res.status(404).send("Member not found.");
    }

    core.logger.info(`Step 3: Verified member ${member.email}. Creating session.`);

    const sessionToken = signSessionJWT(member);
    res.cookie(SESSION_COOKIE, sessionToken, {
      httpOnly: true,
      secure: true,
      maxAge: SESSION_TTL_SECONDS * 1000,
      sameSite: "lax",
    });

    return res.redirect(302, "/sso/discourse");
  } catch (err: any) {
    const errorMsg = err.response?.data?.errors?.[0]?.message || err.message;
    core.logger.error({ error: errorMsg }, "Failed to exchange Ghost token.");
    return res.status(500).send(`Error verifying Ghost token: ${errorMsg}`);
  }
};
app.get("/ghost/callback", ghostCallback);

// STEP 5: Construct the final payload and redirect to Discourse.
const ssoDiscourse: RequestHandler = async (req: Request, res: Response) => {
  core.logger.info("Step 5: Preparing to redirect to Discourse.");
  const sessionToken = req.cookies?.[SESSION_COOKIE];
  const member = sessionToken ? verifySessionJWT(sessionToken) : null;

  if (!member) {
    core.logger.warn("No valid session found. Restarting login flow.");
    return res.redirect(302, "/login-from-ghost");
  }

  if (!member.email || !member.id) {
    core.logger.error("Missing required member fields for SSO.");
    return res.status(400).send("Invalid member data.");
  }

  const nonce = crypto.randomBytes(16).toString("hex");
  const externalId = member.uuid || member.id;

  const username = (member.name || member.email.split("@")[0])
    .replace(/\s+/g, "_")
    .replace(/[^a-zA-Z0-9_]/g, "");

  const discoursePayload = new URLSearchParams({
    nonce,
    external_id: externalId,
    email: member.email,
    name: member.name || "",
    username,
  }).toString();

  const payloadBase64 = Buffer.from(discoursePayload).toString("base64");
  const signature = signDiscourseHmac(payloadBase64);

  const redirectUrl = `${DISCOURSE_URL}/session/sso_login?sso=${encodeURIComponent(payloadBase64)}&sig=${signature}`;

  core.logger.info(`Redirecting verified member to Discourse: ${externalId}`);
  return res.redirect(302, redirectUrl);
};
app.get("/sso/discourse", ssoDiscourse);

// --- Health Check and Server Start ---
app.get("/health", (_req, res) => res.status(200).send("OK"));

const routingManager = new RoutingManager();
routingManager.addAllRoutes(app);

app.listen(config.port, "0.0.0.0", () => {
  core.logger.info(`Listening on http://0.0.0.0:${config.port}`);
});
