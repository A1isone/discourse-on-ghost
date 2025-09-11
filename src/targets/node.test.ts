/**
 * Tests for src/targets/node.ts
 *
 * Test framework: The repository's configured test runner (expected: Jest or Vitest).
 * - We use jest-style APIs (describe/it/expect, jest.fn) which Vitest also supports via compatible APIs.
 * - We mock external modules (axios, jsonwebtoken, dotenv, routing, DI, config) to isolate route logic.
 *
 * Focus areas:
 * - Health endpoint
 * - /login-from-ghost flows: missing config, no member -> redirect to Ghost signin, success -> session cookie + redirect to Discourse, missing DISCOURSE_URL
 * - /discourse/sso flows: misconfig, missing params, invalid sig, missing nonce, expired session -> redirect to /login-from-ghost, member not found -> 404, success -> redirect URL contains expected params and signature
 * - Headers/middleware basics: x-powered-by disabled
 * - Server bootstrap: app.listen invoked twice with expected args (per diff)
 */

import crypto from "crypto";

// Compatibility: support both Jest and Vitest globals
const jestLike = (global as any).jest || (global as any).vi;

// Helper to set env before module import
function withEnv(vars: Record<string, string>, fn: () => Promise<void> | void) {
  const old = { ...process.env };
  Object.assign(process.env, vars);
  return Promise.resolve()
    .then(() => fn())
    .finally(() => {
      process.env = old;
    });
}

// Common fixed env for successful flows
const BASE_ENV = {
  DISCOURSE_SSO_SECRET: "not-used-here",
  DISCOURSE_URL: "https://forum.example.com",
  GHOST_URL: "https://ghost.example.com",
  GHOST_ADMIN_API_KEY: "abcd1234:ffffffffffffffffffffffffffffffff", // id:secret(hex)
  SESSION_SECRET: "super-secret-session",
};

type SupertestLike = (app: any) => {
  get: (path: string) => {
    set: (k: string, v: string) => any;
    query: (q: Record<string, any>) => any;
    expect: (status: number) => any;
  };
};

// Try to import supertest if present; otherwise create a minimal shim using http
let request: any;
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  request = require("supertest") as SupertestLike;
} catch {
  // Minimal fallback using http to avoid new dependency
  const http = require("http");
  request = (app: any) => {
    return {
      get: (path: string) => {
        const headers: Record<string, string> = {};
        const queries: Record<string, string> = {};
        const builder: any = {
          set(k: string, v: string) {
            headers[k] = v;
            return builder;
          },
          query(q: Record<string, string>) {
            Object.assign(queries, q);
            return builder;
          },
          async expect(status: number) {
            const url = queries && Object.keys(queries).length
              ? path + "?" + new URLSearchParams(queries as any).toString()
              : path;
            const server = app; // Express app can act as a handler
            const res: any = await new Promise((resolve, reject) => {
              const req = new http.IncomingMessage(null as any);
              const chunks: Buffer[] = [];
              const resObj: any = new http.ServerResponse(req);
              resObj.assignSocket(new (require("stream").Duplex)());
              // This fallback is intentionally minimal and won't assert headers/body.
              // Prefer supertest if available.
              try {
                app({ method: "GET", url, headers }, resObj);
                resolve(resObj);
              } catch (e) {
                reject(e);
              }
            });
            if (res.statusCode !== status) {
              throw new Error(`Expected status ${status} but got ${res.statusCode}`);
            }
            return res;
          },
        };
        return builder;
      },
    };
  };
}

// Dynamic mocks declared before importing the module under test
jestLike.mock("dotenv", () => ({ config: jestLike.fn(() => ({})) }));

// Stub RoutingManager to avoid adding external routes
jestLike.mock("../routing.js", () => {
  return {
    RoutingManager: class {
      addAllRoutes = jestLike.fn();
    },
  };
});

// Minimal core and env mapping
const coreMock = {
  logger: {
    info: jestLike.fn(),
    warn: jestLike.fn(),
    error: jestLike.fn(),
  },
};
jestLike.mock("./shared-node.js", () => ({
  core: coreMock,
  envToConfigMapping: {}, // not used directly in tests
}));

// Inject a stable config via DI
jestLike.mock("../services/dependency-injection.js", () => ({
  bootstrapInjector: jestLike.fn((_core: any, _cfg: any) => ({ port: 0 })), // port unused due to listen mock
}));

// Bypass deferGetConfig side-effects, return non-null
jestLike.mock("../services/config.js", () => ({
  deferGetConfig: jestLike.fn(() => ({ port: 0 })),
}));

// Mock axios
const axiosGet = jestLike.fn();
jestLike.mock("axios", () => ({
  __esModule: true,
  default: { get: (...args: any[]) => axiosGet(...args) },
}));

// Mock express to use real app but stub listen so import doesn't open sockets
const realExpress = jestLike.requireActual ? jestLike.requireActual("express") : require("express");
jestLike.mock("express", () => {
  const expressFactory = () => {
    const app = realExpress();
    // stub listen to avoid binding ports
    (app as any).listen = jestLike.fn((_port: number, _host?: string, cb?: () => void) => {
      if (typeof cb === "function") cb();
      return { close: jestLike.fn() };
    });
    return app;
  };
  // Preserve attached properties like Router, json, urlencoded, static
  Object.assign(expressFactory, realExpress);
  return expressFactory;
});

// Spy/mocks for jsonwebtoken to control verify/sign
const jwtVerify = jestLike.fn();
const jwtSign = jestLike.fn(() => "jwt-token");
jestLike.mock("jsonwebtoken", () => ({
  __esModule: true,
  default: {
    verify: (...args: any[]) => jwtVerify(...args),
    sign: (...args: any[]) => jwtSign(...args),
  },
}));

// Utility to (re)load the module under test with fresh state
async function loadModuleWithEnv(extraEnv: Record<string, string> = {}) {
  jestLike.resetModules?.();
  const env = {
    DISCOURSE_SSO_SECRET_OLD: "", // ignore
    DISCOURSE_SSO_SECRET_NEW: "", // ignore
    DISCOURSE_SSO_SECRET_ALT: "", // ignore
    DISCOURSE_SSO_SECRET_ALIAS: "", // ignore
    DISCOURSE_SSO_SECRET_LEGACY: "", // ignore
    // The code expects DISCOURSE_SSO_SECRET via SSO_SECRET var name?
    // In source, const SSO_SECRET = getEnv("DISCOURSE_SSO_SECRET")
    DISCOURSE_SSO_SECRET: extraEnv.DISCOURSE_SSO_SECRET ?? (BASE_ENV as any).DISCOURSE_SSO_SECRET ?? "sso-secret",
    DISCOURSE_URL: extraEnv.DISCOURSE_URL ?? BASE_ENV.DISCOURSE_URL,
    GHOST_URL: extraEnv.GHOST_URL ?? BASE_ENV.GHOST_URL,
    GHOST_ADMIN_API_KEY: extraEnv.GHOST_ADMIN_API_KEY ?? BASE_ENV.GHOST_ADMIN_API_KEY,
    SESSION_SECRET: extraEnv.SESSION_SECRET ?? BASE_ENV.SESSION_SECRET,
    NODE_ENV: "test",
  } as Record<string, string>;
  await withEnv(env, async () => {});
  // Import target after mocks and env set
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const mod = require("./node.ts");
  return mod as { app: any };
}

describe("src/targets/node.ts", () => {
  beforeEach(() => {
    axiosGet.mockReset();
    jwtVerify.mockReset();
    jwtSign.mockReset().mockReturnValue("jwt-token");
    coreMock.logger.info.mockReset();
    coreMock.logger.warn.mockReset();
    coreMock.logger.error.mockReset();
  });

  describe("bootstrap and /health", () => {
    it("disables x-powered-by and serves /health 200 OK", async () => {
      const { app } = await loadModuleWithEnv();
      const res = await request(app).get("/health").expect(200);
      // x-powered-by should be disabled
      expect(res.headers["x-powered-by"]).toBeUndefined();
      expect(res.text).toBe("OK");
    });

    it("calls app.listen twice with expected args", async () => {
      const { app } = await loadModuleWithEnv();
      // listen was stubbed in express mock as jest.fn in the constructed app
      const listenMock = (app as any).listen as jest.Mock;
      expect(listenMock).toHaveBeenCalledTimes(2);
      // Ensure at least one call uses host 0.0.0.0
      const hostArgs = listenMock.mock.calls.map((c) => c.slice(0, 2));
      expect(hostArgs).toEqual(
        expect.arrayContaining([
          expect.arrayContaining([expect.any(Number), "0.0.0.0"]),
        ])
      );
    });
  });

  describe("GET /login-from-ghost", () => {
    it("500 when missing Ghost config", async () => {
      const { app } = await loadModuleWithEnv({
        GHOST_URL: "",
        GHOST_ADMIN_API_KEY: "",
      });
      const res = await request(app).get("/login-from-ghost").expect(500);
      expect(res.text).toContain("Server missing Ghost config");
      expect(coreMock.logger.error).toHaveBeenCalledWith("Missing Ghost config");
    });

    it("redirects to Ghost signin when no member found", async () => {
      const { app } = await loadModuleWithEnv();
      axiosGet.mockResolvedValueOnce({ data: { members: [] } });
      const res = await request(app).get("/login-from-ghost").expect(302);
      expect(res.headers.location).toBe(`${BASE_ENV.GHOST_URL}/#/portal/signin`);
      expect(coreMock.logger.warn).toHaveBeenCalledWith("No member found, redirecting to sign-in");
    });

    it("sets session cookie and redirects to Discourse on success", async () => {
      const { app } = await loadModuleWithEnv();
      axiosGet.mockResolvedValueOnce({
        data: { members: [{ id: "m1", email: "user@example.com", name: "User One" }] },
      });
      const res = await request(app).get("/login-from-ghost").expect(302);
      const setCookie = res.headers["set-cookie"]?.[0] || "";
      expect(setCookie).toMatch(/^dog_member=/);
      expect(setCookie).toMatch(/HttpOnly/i);
      expect(setCookie).toMatch(/Secure/i);
      expect(res.headers.location).toBe(BASE_ENV.DISCOURSE_URL);
    });

    it("500 when DISCOURSE_URL missing", async () => {
      const { app } = await loadModuleWithEnv({ DISCOURSE_URL: "" });
      axiosGet.mockResolvedValueOnce({
        data: { members: [{ id: "m1", email: "user@example.com", name: "User One" }] },
      });
      const res = await request(app).get("/login-from-ghost").expect(500);
      expect(res.text).toContain("Missing DISCOURSE_URL");
      expect(coreMock.logger.error).toHaveBeenCalledWith("DISCOURSE_URL missing");
    });
  });

  describe("GET /discourse/sso", () => {
    function mkSSOParams(nonce = "abc123", extras: Record<string, string> = {}) {
      const params = new URLSearchParams({ nonce, return_sso_url: "https://example.com/return", ...extras });
      const b64 = Buffer.from(params.toString(), "utf8").toString("base64");
      const sig = crypto.createHmac("sha256", "sso-secret").update(b64).digest("hex");
      return { sso: b64, sig };
    }

    it("500 when SSO_SECRET or DISCOURSE_URL missing", async () => {
      const { app } = await loadModuleWithEnv({ DISCOURSE_SSO_SECRET: "", DISCOURSE_URL: "" });
      const { sso, sig } = mkSSOParams();
      const res = await request(app).get("/discourse/sso").query({ sso, sig }).expect(500);
      expect(res.text).toContain("Server misconfigured");
      expect(coreMock.logger.error).toHaveBeenCalledWith("Missing SSO_SECRET or DISCOURSE_URL");
    });

    it("400 when missing sso or sig", async () => {
      const { app } = await loadModuleWithEnv();
      await request(app).get("/discourse/sso").expect(400);
    });

    it("403 when signature invalid", async () => {
      const { app } = await loadModuleWithEnv();
      const { sso } = mkSSOParams();
      const res = await request(app).get("/discourse/sso").query({ sso, sig: "bad" }).expect(403);
      expect(res.text).toContain("Invalid SSO signature");
    });

    it("400 when nonce missing", async () => {
      const { app } = await loadModuleWithEnv();
      const qp = mkSSOParams("");
      const res = await request(app).get("/discourse/sso").query(qp).expect(400);
      expect(res.text).toContain("Missing nonce");
    });

    it("redirects to /login-from-ghost when session missing or expired", async () => {
      const { app } = await loadModuleWithEnv();
      // Simulate verify throwing or returning expired payload
      jwtVerify.mockImplementation(() => {
        return { sub: "m1", exp: Math.floor(Date.now() / 1000) - 10 };
      });
      const { sso, sig } = mkSSOParams();
      const res = await request(app)
        .get("/discourse/sso")
        .set("Cookie", ["dog_member=fake"])
        .query({ sso, sig })
        .expect(302);
      expect(res.headers.location?.endsWith("/login-from-ghost")).toBe(true);
    });

    it("404 when member not found", async () => {
      const { app } = await loadModuleWithEnv();
      jwtVerify.mockReturnValue({ sub: "m1", exp: Math.floor(Date.now() / 1000) + 600 });
      axiosGet.mockResolvedValueOnce({ data: { members: [] } });
      const { sso, sig } = mkSSOParams();
      const res = await request(app).get("/discourse/sso").set("Cookie", ["dog_member=valid"]).query({ sso, sig }).expect(404);
      expect(res.text).toContain("Member not found");
    });

    it("302 redirect back to Discourse with correct payload and signature", async () => {
      const { app } = await loadModuleWithEnv();
      jwtVerify.mockReturnValue({ sub: "m1", exp: Math.floor(Date.now() / 1000) + 600 });
      axiosGet.mockResolvedValueOnce({
        data: { members: [{ id: "m1", email: "john.doe@example.com", name: "John Doe" }] },
      });
      const { sso, sig } = mkSSOParams("xyz789");
      const res = await request(app)
        .get("/discourse/sso")
        .set("Cookie", ["dog_member=valid"])
        .query({ sso, sig })
        .expect(302);

      const loc = res.headers.location as string;
      expect(loc.startsWith("https://forum.example.com/session/sso_login?")).toBe(true);

      const url = new URL(loc);
      const retSSO = url.searchParams.get("sso")!;
      const retSig = url.searchParams.get("sig")!;
      // Verify signature computed with same SSO secret
      const expectedSig = crypto.createHmac("sha256", "sso-secret").update(retSSO).digest("hex");
      expect(retSig).toBe(expectedSig);

      // Validate payload fields
      const decoded = Buffer.from(retSSO, "base64").toString("utf8");
      const p = new URLSearchParams(decoded);
      expect(p.get("nonce")).toBe("xyz789");
      expect(p.get("external_id")).toBe("m1");
      expect(p.get("email")).toBe("john.doe@example.com");
      expect(p.get("username")).toBe("John_Doe"); // spaces replaced with underscores
      expect(p.get("name")).toBe("John Doe");
      expect(p.get("require_activation")).toBe("false");
      expect(p.get("suppress_welcome_message")).toBe("true");
    });

    it("username falls back to email local-part when name missing", async () => {
      const { app } = await loadModuleWithEnv();
      jwtVerify.mockReturnValue({ sub: "m2", exp: Math.floor(Date.now() / 1000) + 600 });
      axiosGet.mockResolvedValueOnce({
        data: { members: [{ id: "m2", email: "no.name@example.com", name: "" }] },
      });
      const { sso, sig } = mkSSOParams("n0");
      const res = await request(app)
        .get("/discourse/sso")
        .set("Cookie", ["dog_member=valid"])
        .query({ sso, sig })
        .expect(302);

      const url = new URL(res.headers.location as string);
      const retSSO = url.searchParams.get("sso")!;
      const decoded = Buffer.from(retSSO, "base64").toString("utf8");
      const p = new URLSearchParams(decoded);
      expect(p.get("username")).toBe("no.name");
    });
  });
});