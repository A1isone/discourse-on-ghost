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
const SESSION_SECRET = getEnv("SESSION_SECRET");
const SESSION_COOKIE = "ghost_sso_member_session"; // Renamed for clarity
const SESSION_TTL_SECONDS = 10 * 60; // 10 minutes

// --- Helper Functions ---

/**
 * Creates a signed JWT for the middleware's internal session management.
 * This session temporarily stores the Ghost Member's data.
 */
function signSessionJWT(payload: object): string {
  return jwt.sign(payload, SESSION_SECRET, {
    algorithm: "HS256",
    expiresIn: SESSION_TTL_SECONDS,
  });
}

/**
 * Verifies the middleware's internal session JWT.
 */
function verifySessionJWT(token: string): any | null {
  try {
    return jwt.verify(token, SESSION_SECRET);
  } catch {
    return null;
  }
}

/**
 * Creates the HMAC-SHA256 signature required by Discourse SSO.
 */
function signDiscourseHmac(payloadBase64: string): string {
  return crypto.createHmac("sha256", SSO_SECRET).update(payloadBase64).digest("hex");
}

// --- Main SSO Route ---

/**
 * This is the primary entry point for the SSO process.
 * It checks if the user is logged into Ghost, and if so,
 * redirects them to Discourse to log in.
 */
const loginFromGhost: RequestHandler = async (req: Request, res: Response) => {
  core.logger.info("Starting SSO process...");

  try {
    // 1. Check for an existing, valid session cookie from THIS middleware.
    const sessionToken = req.cookies?.[SESSION_COOKIE];
    let member = sessionToken ? verifySessionJWT(sessionToken) : null;

    // 2. If no valid session, verify the user's login status with Ghost.
    if (!member) {
      core.logger.info("No valid middleware session. Checking Ghost for member status...");
      try {
        // This is the key step: we ask the Ghost Member API who is logged in,
        // passing along the user's browser cookies to identify them.
        const ghostApiResponse = await axios.get(`${GHOST_URL}/api/members/me/`, {
          headers: {
            Cookie: req.headers.cookie, // Forward user's cookies to Ghost
          },
        });

        member = ghostApiResponse.data.members[0];

        if (member) {
          core.logger.info(`Verified member from Ghost: ${member.email}`);
          // Create our own short-lived session to avoid hitting the Ghost API on every request.
          const newSessionToken = signSessionJWT(member);
          res.cookie(SESSION_COOKIE, newSessionToken, {
            httpOnly: true,
            secure: true,
            maxAge: SESSION_TTL_SECONDS * 1000,
            sameSite: "lax",
          });
        }
      } catch (error) {
        // If the Ghost API call fails, it means the user is not logged into Ghost.
        core.logger.info("User is not logged into Ghost. Redirecting to Ghost Portal.");
        const returnUrl = `https://${req.get("host")}${req.originalUrl}`;
        const ghostSignInUrl = `${GHOST_URL}/#/portal/signin?redirect=${encodeURIComponent(returnUrl)}`;
        return res.redirect(302, ghostSignInUrl);
      }
    } else {
        core.logger.info(`Valid middleware session found for member: ${member.email}`);
    }

    // 3. If we don't have a member after all checks, something is wrong.
    if (!member) {
      core.logger.error("Could not identify Ghost member after checks.");
      return res.status(401).send("Unable to identify Ghost member. Please log in to your Ghost account.");
    }

    // 4. We have a verified member. Construct the SSO payload for Discourse.
    const nonce = crypto.randomBytes(16).toString("hex");
    const discoursePayload = new URLSearchParams({
      nonce,
      external_id: member.id,
      email: member.email,
      name: member.name || "",
      username: (member.name || member.email.split("@")[0]).replace(/\s+/g, "_"),
    }).toString();

    const payloadBase64 = Buffer.from(discoursePayload).toString("base64");
    const signature = signDiscourseHmac(payloadBase64);

    const redirectUrl = `${DISCOURSE_URL}/session/sso_login?sso=${encodeURIComponent(
      payloadBase64
    )}&sig=${signature}`;
    
    core.logger.info(`Redirecting verified member to Discourse: ${member.id}`);
    return res.redirect(302, redirectUrl);

  } catch (err: any) {
    const errorMessage = err?.response?.data || err.message;
    core.logger.error({ error: errorMessage }, "SSO process failed with an unexpected error.");
    console.error(err);
    return res.status(500).send(`An unexpected error occurred during login: ${errorMessage}`);
  }
};

// --- Route Definitions ---
app.get("/health", (_req, res) => res.status(200).send("OK"));

// All community links should point to this single endpoint.
app.get("/login-from-ghost", loginFromGhost);

// --- Start Server ---
const routingManager = new RoutingManager();
routingManager.addAllRoutes(app);

app.listen(config.port, "0.0.0.0", () => {
  core.logger.info(`Listening on http://0.0.0.0:${config.port}`);
});
