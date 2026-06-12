import { COOKIE_NAME, OAUTH_STATE_COOKIE_NAME, ONE_YEAR_MS } from "@shared/const";
import { parse as parseCookieHeader } from "cookie";
import type { Express, Request, Response } from "express";
import * as db from "../db";
import {
  getOAuthStateCookieClearOptions,
  getOAuthStateCookieOptions,
  getSessionCookieOptions,
} from "./cookies";
import { ENV } from "./env";
import { sdk } from "./sdk";

function getQueryParam(req: Request, key: string): string | undefined {
  const value = req.query[key];
  return typeof value === "string" ? value : undefined;
}

function getRequestOrigin(req: Request): string {
  const forwardedProto = req.headers["x-forwarded-proto"];
  const proto =
    typeof forwardedProto === "string"
      ? forwardedProto.split(",")[0]?.trim()
      : Array.isArray(forwardedProto)
        ? forwardedProto[0]
        : req.protocol;
  const host = req.get("host");

  if (!host) {
    throw new Error("Host header is required");
  }

  return `${proto === "https" ? "https" : "http"}://${host}`;
}

function getSafeReturnTo(value: string | undefined): string {
  if (!value) return "/";
  if (!value.startsWith("/") || value.startsWith("//")) return "/";
  return value;
}

function getOAuthStateCookie(req: Request): string | undefined {
  const parsed = parseCookieHeader(req.headers.cookie ?? "");
  const value = parsed[OAUTH_STATE_COOKIE_NAME];
  return typeof value === "string" ? value : undefined;
}

export function registerOAuthRoutes(app: Express) {
  app.get("/api/oauth/login", async (req: Request, res: Response) => {
    try {
      const origin = getRequestOrigin(req);
      const redirectUri = `${origin}/api/oauth/callback`;
      const returnTo = getSafeReturnTo(getQueryParam(req, "returnTo"));
      const nonce = sdk.createOAuthStateNonce();
      const state = await sdk.createOAuthState({ redirectUri, returnTo, nonce });

      const url = new URL(`${ENV.oAuthPortalUrl.replace(/\/$/, "")}/app-auth`);
      url.searchParams.set("appId", ENV.appId);
      url.searchParams.set("redirectUri", redirectUri);
      url.searchParams.set("state", state);
      url.searchParams.set("type", "signIn");

      res.cookie(OAUTH_STATE_COOKIE_NAME, nonce, getOAuthStateCookieOptions(req));
      res.redirect(302, url.toString());
    } catch {
      res.status(500).json({ error: "OAuth login initialization failed" });
    }
  });

  app.get("/api/oauth/callback", async (req: Request, res: Response) => {
    const code = getQueryParam(req, "code");
    const state = getQueryParam(req, "state");

    if (!code || !state) {
      res.status(400).json({ error: "code and state are required" });
      return;
    }

    try {
      const verifiedState = await sdk.verifyOAuthState(
        state,
        getOAuthStateCookie(req)
      );
      res.clearCookie(OAUTH_STATE_COOKIE_NAME, getOAuthStateCookieClearOptions(req));

      if (!verifiedState) {
        res.status(400).json({ error: "invalid OAuth state" });
        return;
      }

      const tokenResponse = await sdk.exchangeCodeForToken(
        code,
        verifiedState.redirectUri
      );
      const userInfo = await sdk.getUserInfo(tokenResponse.accessToken);

      if (!userInfo.openId) {
        res.status(400).json({ error: "openId missing from user info" });
        return;
      }

      await db.upsertUser({
        openId: userInfo.openId,
        name: userInfo.name || null,
        email: userInfo.email ?? null,
        loginMethod: userInfo.loginMethod ?? userInfo.platform ?? null,
        lastSignedIn: new Date(),
      });

      const sessionToken = await sdk.createSessionToken(userInfo.openId, {
        name: userInfo.name || "",
        expiresInMs: ONE_YEAR_MS,
      });

      res.cookie(COOKIE_NAME, sessionToken, {
        ...getSessionCookieOptions(req),
        maxAge: ONE_YEAR_MS,
      });

      res.redirect(302, verifiedState.returnTo);
    } catch {
      res.clearCookie(OAUTH_STATE_COOKIE_NAME, getOAuthStateCookieClearOptions(req));
      console.error("[OAuth] Callback failed");
      res.status(500).json({ error: "OAuth callback failed" });
    }
  });
}
