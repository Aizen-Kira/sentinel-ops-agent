import type { CookieOptions, Request } from "express";
import { OAUTH_STATE_MAX_AGE_MS, ONE_YEAR_MS } from "@shared/const";
import { ENV } from "./env";

function isSecureRequest(req: Request) {
  if (req.protocol === "https") return true;

  const forwardedProto = req.headers["x-forwarded-proto"];
  if (!forwardedProto) return false;

  const protoList = Array.isArray(forwardedProto)
    ? forwardedProto
    : forwardedProto.split(",");

  return protoList.some(proto => proto.trim().toLowerCase() === "https");
}

function getHardenedCookieOptions(
  req: Request,
  options: { maxAge: number; path: string }
): CookieOptions {
  return {
    httpOnly: true,
    maxAge: options.maxAge,
    expires: new Date(Date.now() + options.maxAge),
    path: options.path,
    sameSite: "lax",
    secure: ENV.isProduction ? true : isSecureRequest(req),
  };
}

function getExpiredCookieOptions(req: Request, path: string): CookieOptions {
  return {
    httpOnly: true,
    expires: new Date(0),
    path,
    sameSite: "lax",
    secure: ENV.isProduction ? true : isSecureRequest(req),
  };
}

export function getSessionCookieOptions(
  req: Request
): CookieOptions {
  return getHardenedCookieOptions(req, {
    maxAge: ONE_YEAR_MS,
    path: "/",
  });
}

export function getOAuthStateCookieOptions(req: Request): CookieOptions {
  return getHardenedCookieOptions(req, {
    maxAge: OAUTH_STATE_MAX_AGE_MS,
    path: "/api/oauth",
  });
}

export function getSessionCookieClearOptions(req: Request): CookieOptions {
  return getExpiredCookieOptions(req, "/");
}

export function getOAuthStateCookieClearOptions(req: Request): CookieOptions {
  return getExpiredCookieOptions(req, "/api/oauth");
}
