// @vitest-environment node

import { describe, expect, it, vi, afterEach } from "vitest";
import type { Request } from "express";
import type { User } from "../../drizzle/schema";
import { OAUTH_STATE_MAX_AGE_MS, ONE_YEAR_MS } from "@shared/const";
import { SignJWT } from "jose";
import { assertNotSelfApproval } from "./authorization";
import {
  getOAuthStateCookieClearOptions,
  getOAuthStateCookieOptions,
  getSessionCookieClearOptions,
  getSessionCookieOptions,
} from "./cookies";
import { ENV, isWeakJwtSecret, JWT_AUDIENCE, JWT_ISSUER, parseEnv } from "./env";
import { sanitizeLogValue } from "./logSanitization";
import { clearOAuthStateReplayCache, SDKServer } from "./sdk";

const VALID_SECRET = "valid-sentinel-ops-jwt-secret-value-12345";

const previousEnv = {
  appId: ENV.appId,
  cookieSecret: ENV.cookieSecret,
  isProduction: ENV.isProduction,
};

function createRequest(
  options: {
    protocol?: "http" | "https";
    forwardedProto?: string;
  } = {}
): Request {
  return {
    protocol: options.protocol ?? "http",
    headers: options.forwardedProto
      ? { "x-forwarded-proto": options.forwardedProto }
      : {},
  } as Request;
}

afterEach(() => {
  ENV.appId = previousEnv.appId;
  ENV.cookieSecret = previousEnv.cookieSecret;
  ENV.isProduction = previousEnv.isProduction;
  clearOAuthStateReplayCache();
  vi.restoreAllMocks();
});

async function createSessionJwt(options: {
  issuer?: string;
  audience?: string;
  appId?: string;
  expiresInSeconds?: number;
}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    openId: "user-1",
    appId: options.appId ?? ENV.appId,
    name: "Analyst",
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(options.issuer ?? JWT_ISSUER)
    .setAudience(options.audience ?? JWT_AUDIENCE)
    .setIssuedAt(now)
    .setExpirationTime(now + (options.expiresInSeconds ?? 60))
    .sign(new TextEncoder().encode(VALID_SECRET));
}

describe("environment validation", () => {
  it("rejects invalid production env vars without exposing secret values", () => {
    const databaseUrl =
      "mysql://sentinel_user:super-secret-db-password@localhost:3306/sentinel";
    let message = "";

    expect(() =>
      parseEnv({
        NODE_ENV: "production",
        DATABASE_URL: databaseUrl,
        JWT_SECRET: "secret",
        APP_ID: "sentinel-prod",
        OAUTH_SERVER_URL: "https://oauth.example.com",
        OAUTH_PORTAL_URL: "https://oauth.example.com",
      })
    ).toThrow(/JWT_SECRET/);

    try {
      parseEnv({
        NODE_ENV: "production",
        DATABASE_URL: databaseUrl,
        JWT_SECRET: "secret",
        APP_ID: "sentinel-prod",
        OAUTH_SERVER_URL: "https://oauth.example.com",
        OAUTH_PORTAL_URL: "https://oauth.example.com",
      });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).not.toContain("super-secret-db-password");
    expect(message).not.toContain(databaseUrl);
  });

  it("rejects malformed database URLs", () => {
    expect(() =>
      parseEnv({
        NODE_ENV: "production",
        DATABASE_URL: "not-a-url",
        JWT_SECRET: VALID_SECRET,
        APP_ID: "sentinel-prod",
        OAUTH_SERVER_URL: "https://oauth.example.com",
        OAUTH_PORTAL_URL: "https://oauth.example.com",
      })
    ).toThrow(/DATABASE_URL/);
  });

  it("provides explicit defaults only for test environments", () => {
    const env = parseEnv({ NODE_ENV: "test" });

    expect(env.nodeEnv).toBe("test");
    expect(env.appId).toBe("test-app");
    expect(env.databaseUrl).toContain("sentinel_test");
    expect(isWeakJwtSecret(env.cookieSecret)).toBe(false);
  });

  it("validates AI provider-specific configuration", () => {
    expect(() =>
      parseEnv({
        NODE_ENV: "production",
        DATABASE_URL: "mysql://user:pass@localhost:3306/sentinel",
        JWT_SECRET: VALID_SECRET,
        APP_ID: "sentinel-prod",
        OAUTH_SERVER_URL: "https://oauth.example.com",
        OAUTH_PORTAL_URL: "https://oauth.example.com",
        AI_PROVIDER: "ollama",
      })
    ).toThrow(/OLLAMA_MODEL/);
  });

  it("does not provide production defaults for required configuration", () => {
    expect(() => parseEnv({ NODE_ENV: "production" })).toThrow(
      /DATABASE_URL/
    );
  });
});

describe("authorization hardening", () => {
  it("rejects response action self-approval", () => {
    const user = {
      id: 42,
      openId: "analyst-42",
      email: "analyst@example.com",
      name: "Analyst",
      loginMethod: "test",
      role: "admin",
      createdAt: new Date(),
      updatedAt: new Date(),
      lastSignedIn: new Date(),
    } satisfies User;

    expect(() => {
      assertNotSelfApproval(user, user.id, {
        action: "responseActions.approveAction",
        resource: "ACT-test",
      });
    }).toThrow("Response actions must be approved by a different authorized user");
  });
});

describe("JWT hardening", () => {
  it("rejects weak JWT secrets", async () => {
    ENV.cookieSecret = "short";
    const sdk = new SDKServer();

    await expect(sdk.createSessionToken("user-1")).rejects.toThrow(/JWT_SECRET/);
  });

  it("rejects malformed tokens without logging token or secret values", async () => {
    ENV.cookieSecret = VALID_SECRET;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const sdk = new SDKServer();

    await expect(sdk.verifySession("not-a-jwt")).resolves.toBeNull();

    const logged = warn.mock.calls.flat().join(" ");
    expect(logged).not.toContain("not-a-jwt");
    expect(logged).not.toContain(VALID_SECRET);
  });

  it("validates appId in signed session payloads", async () => {
    ENV.cookieSecret = VALID_SECRET;
    ENV.appId = "sentinel-app";
    const sdk = new SDKServer();

    const token = await sdk.signSession({
      openId: "user-1",
      appId: "different-app",
      name: "Analyst",
    });

    await expect(sdk.verifySession(token)).resolves.toBeNull();
  });

  it("rejects tokens with an invalid issuer", async () => {
    ENV.cookieSecret = VALID_SECRET;
    ENV.appId = "sentinel-app";
    const sdk = new SDKServer();
    const token = await createSessionJwt({ issuer: "wrong-issuer" });

    await expect(sdk.verifySession(token)).resolves.toBeNull();
  });

  it("rejects tokens with an invalid audience", async () => {
    ENV.cookieSecret = VALID_SECRET;
    ENV.appId = "sentinel-app";
    const sdk = new SDKServer();
    const token = await createSessionJwt({ audience: "wrong-audience" });

    await expect(sdk.verifySession(token)).resolves.toBeNull();
  });

  it("rejects expired JWTs", async () => {
    ENV.cookieSecret = VALID_SECRET;
    ENV.appId = "sentinel-app";
    const sdk = new SDKServer();
    const token = await createSessionJwt({ expiresInSeconds: -60 });

    await expect(sdk.verifySession(token)).resolves.toBeNull();
  });

  it("accepts valid issuer, audience, and appId claims", async () => {
    ENV.cookieSecret = VALID_SECRET;
    ENV.appId = "sentinel-app";
    const sdk = new SDKServer();

    const token = await sdk.createSessionToken("user-1", { name: "Analyst" });

    await expect(sdk.verifySession(token)).resolves.toMatchObject({
      openId: "user-1",
      appId: "sentinel-app",
      name: "Analyst",
    });
  });
});

describe("OAuth state security", () => {
  it("rejects invalid state values", async () => {
    ENV.cookieSecret = VALID_SECRET;
    const sdk = new SDKServer();

    await expect(sdk.verifyOAuthState("invalid", "nonce")).resolves.toBeNull();
  });

  it("rejects OAuth state without the state cookie", async () => {
    ENV.cookieSecret = VALID_SECRET;
    ENV.appId = "sentinel-app";
    const sdk = new SDKServer();
    const nonce = sdk.createOAuthStateNonce();
    const state = await sdk.createOAuthState({
      redirectUri: "https://app.example.com/api/oauth/callback",
      returnTo: "/alerts",
      nonce,
    });

    await expect(sdk.verifyOAuthState(state, undefined)).resolves.toBeNull();
  });

  it("rejects expired OAuth state values", async () => {
    ENV.cookieSecret = VALID_SECRET;
    ENV.appId = "sentinel-app";
    const sdk = new SDKServer();
    const nonce = sdk.createOAuthStateNonce();
    const state = await sdk.createOAuthState(
      {
        redirectUri: "https://app.example.com/api/oauth/callback",
        returnTo: "/alerts",
        nonce,
      },
      { expiresInMs: -1000 }
    );

    await expect(sdk.verifyOAuthState(state, nonce)).resolves.toBeNull();
  });

  it("requires the signed state nonce to match the state cookie", async () => {
    ENV.cookieSecret = VALID_SECRET;
    ENV.appId = "sentinel-app";
    const sdk = new SDKServer();
    const nonce = sdk.createOAuthStateNonce();
    const state = await sdk.createOAuthState({
      redirectUri: "https://app.example.com/api/oauth/callback",
      returnTo: "/alerts",
      nonce,
    });

    await expect(sdk.verifyOAuthState(state, "wrong-nonce")).resolves.toBeNull();
  });

  it("prevents replay of a verified OAuth state", async () => {
    ENV.cookieSecret = VALID_SECRET;
    ENV.appId = "sentinel-app";
    const sdk = new SDKServer();
    const nonce = sdk.createOAuthStateNonce();
    const state = await sdk.createOAuthState({
      redirectUri: "https://app.example.com/api/oauth/callback",
      returnTo: "/investigations",
      nonce,
    });

    await expect(sdk.verifyOAuthState(state, nonce)).resolves.toMatchObject({
      returnTo: "/investigations",
      nonce,
    });
    await expect(sdk.verifyOAuthState(state, nonce)).resolves.toBeNull();
  });
});

describe("cookie hardening", () => {
  it("uses secure HttpOnly SameSite=Lax session cookies with explicit expiration", () => {
    ENV.isProduction = true;
    const before = Date.now();
    const options = getSessionCookieOptions(createRequest({ protocol: "http" }));

    expect(options).toMatchObject({
      httpOnly: true,
      maxAge: ONE_YEAR_MS,
      path: "/",
      sameSite: "lax",
      secure: true,
    });
    expect(options.expires).toBeInstanceOf(Date);
    expect(options.expires?.getTime()).toBeGreaterThanOrEqual(
      before + ONE_YEAR_MS - 50
    );
  });

  it("uses a short-lived OAuth state cookie", () => {
    ENV.isProduction = true;
    const before = Date.now();
    const options = getOAuthStateCookieOptions(createRequest({ protocol: "http" }));

    expect(options).toMatchObject({
      httpOnly: true,
      maxAge: OAUTH_STATE_MAX_AGE_MS,
      path: "/api/oauth",
      sameSite: "lax",
      secure: true,
    });
    expect(options.expires).toBeInstanceOf(Date);
    expect(options.expires?.getTime()).toBeGreaterThanOrEqual(
      before + OAUTH_STATE_MAX_AGE_MS - 50
    );
  });

  it("uses expired options when clearing security cookies", () => {
    ENV.isProduction = true;

    expect(getSessionCookieClearOptions(createRequest())).toMatchObject({
      httpOnly: true,
      path: "/",
      sameSite: "lax",
      secure: true,
      expires: new Date(0),
    });
    expect(getOAuthStateCookieClearOptions(createRequest())).toMatchObject({
      httpOnly: true,
      path: "/api/oauth",
      sameSite: "lax",
      secure: true,
      expires: new Date(0),
    });
  });
});

describe("log sanitization", () => {
  it("redacts JWTs, API keys, OAuth tokens, and database credentials", async () => {
    ENV.cookieSecret = VALID_SECRET;
    const sdk = new SDKServer();
    const jwt = await sdk.createSessionToken("user-1");
    const raw = {
      jwtSecret: VALID_SECRET,
      forgeApiKey: "sk-live-secret-api-key",
      accessToken: "oauth-access-token-value",
      nested: {
        databaseUrl:
          "mysql://sentinel_user:super-secret-db-password@localhost:3306/sentinel",
      },
      message: `authorization: Bearer oauth-access-token-value token=${jwt}`,
    };

    const sanitized = JSON.stringify(sanitizeLogValue(raw));

    expect(sanitized).toContain("[REDACTED]");
    expect(sanitized).not.toContain(VALID_SECRET);
    expect(sanitized).not.toContain("sk-live-secret-api-key");
    expect(sanitized).not.toContain("oauth-access-token-value");
    expect(sanitized).not.toContain("super-secret-db-password");
    expect(sanitized).not.toContain(jwt);
  });
});
