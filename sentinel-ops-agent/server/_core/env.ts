import { z } from "zod";

export const JWT_ISSUER = "sentinel-ops";
export const JWT_AUDIENCE = "sentinel-ops-web";

const TEST_JWT_SECRET =
  "test-only-sentinel-ops-jwt-secret-32-chars";

const WEAK_SECRET_VALUES = new Set([
  "secret",
  "password",
  "changeme",
  "jwt_secret",
  "replace-with-at-least-32-random-characters",
  "your-secret",
  "your-secret-here",
  "test",
]);

const nodeEnvSchema = z
  .enum(["development", "test", "production"])
  .default("development");

export type NodeEnv = z.infer<typeof nodeEnvSchema>;
export type AiProvider = "auto" | "forge" | "ollama";

export type AppEnv = {
  appId: string;
  cookieSecret: string;
  databaseUrl: string;
  oAuthServerUrl: string;
  oAuthPortalUrl: string;
  ownerOpenId: string;
  nodeEnv: NodeEnv;
  isProduction: boolean;
  forgeApiUrl: string;
  forgeApiKey: string;
  aiProvider: AiProvider;
  cloudModel: string;
  ollamaBaseUrl: string;
  ollamaModel: string;
};

type RawEnv = Record<string, string | undefined>;

export function isWeakJwtSecret(secret: string): boolean {
  const trimmed = secret.trim();
  if (trimmed.length < 32) return true;
  if (WEAK_SECRET_VALUES.has(trimmed.toLowerCase())) return true;
  if (/^(.)\1+$/.test(trimmed)) return true;
  return false;
}

export function assertStrongJwtSecret(secret: string): string {
  if (isWeakJwtSecret(secret)) {
    throw new Error("JWT_SECRET must be at least 32 characters and not use a common weak value");
  }
  return secret;
}

function isValidDatabaseUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return ["mysql:", "mysql2:", "mariadb:"].includes(url.protocol);
  } catch {
    return false;
  }
}

function isTestEnvironment(raw: RawEnv): boolean {
  return raw.NODE_ENV === "test" || raw.VITEST === "true";
}

function withTestDefaults(raw: RawEnv): RawEnv {
  if (!isTestEnvironment(raw)) return raw;

  return {
    ...raw,
    NODE_ENV: raw.NODE_ENV ?? "test",
    DATABASE_URL: raw.DATABASE_URL ?? "mysql://test:test@localhost:3306/sentinel_test",
    JWT_SECRET: raw.JWT_SECRET ?? TEST_JWT_SECRET,
    APP_ID: raw.APP_ID ?? raw.VITE_APP_ID ?? "test-app",
    OAUTH_SERVER_URL: raw.OAUTH_SERVER_URL ?? "https://oauth.test.local",
    OAUTH_PORTAL_URL:
      raw.OAUTH_PORTAL_URL ?? raw.VITE_OAUTH_PORTAL_URL ?? "https://oauth.test.local",
    AI_PROVIDER: raw.AI_PROVIDER ?? "auto",
    LLM_MODEL: raw.LLM_MODEL ?? "gemini-2.5-flash",
    OLLAMA_BASE_URL: raw.OLLAMA_BASE_URL ?? "http://127.0.0.1:11434",
  };
}

const envInputSchema = z
  .object({
    NODE_ENV: nodeEnvSchema,
    DATABASE_URL: z
      .string()
      .trim()
      .min(1, "DATABASE_URL is required")
      .refine(isValidDatabaseUrl, {
        message: "DATABASE_URL must be a valid MySQL-compatible URL",
      }),
    JWT_SECRET: z
      .string()
      .trim()
      .min(1, "JWT_SECRET is required")
      .refine((value) => !isWeakJwtSecret(value), {
        message: "JWT_SECRET must be at least 32 characters and not use a common weak value",
      }),
    APP_ID: z.string().trim().optional(),
    VITE_APP_ID: z.string().trim().optional(),
    OAUTH_SERVER_URL: z.string().trim().url("OAUTH_SERVER_URL must be a valid URL"),
    OAUTH_PORTAL_URL: z.string().trim().url("OAUTH_PORTAL_URL must be a valid URL").optional(),
    VITE_OAUTH_PORTAL_URL: z
      .string()
      .trim()
      .url("VITE_OAUTH_PORTAL_URL must be a valid URL")
      .optional(),
    OWNER_OPEN_ID: z.string().trim().optional().default(""),
    BUILT_IN_FORGE_API_URL: z.string().trim().url().optional().or(z.literal("")),
    BUILT_IN_FORGE_API_KEY: z.string().trim().optional().default(""),
    AI_PROVIDER: z.enum(["auto", "forge", "ollama"]).default("auto"),
    LLM_MODEL: z.string().trim().optional().default("gemini-2.5-flash"),
    OLLAMA_BASE_URL: z
      .string()
      .trim()
      .url("OLLAMA_BASE_URL must be a valid URL")
      .optional()
      .default("http://127.0.0.1:11434"),
    OLLAMA_MODEL: z.string().trim().optional().default(""),
  })
  .superRefine((env, ctx) => {
    const appId = env.APP_ID || env.VITE_APP_ID;
    if (!appId) {
      ctx.addIssue({
        code: "custom",
        path: ["APP_ID"],
        message: "APP_ID or VITE_APP_ID is required",
      });
    }

    const oauthPortalUrl = env.OAUTH_PORTAL_URL || env.VITE_OAUTH_PORTAL_URL;
    if (!oauthPortalUrl) {
      ctx.addIssue({
        code: "custom",
        path: ["OAUTH_PORTAL_URL"],
        message: "OAUTH_PORTAL_URL or VITE_OAUTH_PORTAL_URL is required",
      });
    }

    if (env.AI_PROVIDER === "forge") {
      if (!env.BUILT_IN_FORGE_API_URL) {
        ctx.addIssue({
          code: "custom",
          path: ["BUILT_IN_FORGE_API_URL"],
          message: "BUILT_IN_FORGE_API_URL is required when AI_PROVIDER=forge",
        });
      }
      if (!env.BUILT_IN_FORGE_API_KEY) {
        ctx.addIssue({
          code: "custom",
          path: ["BUILT_IN_FORGE_API_KEY"],
          message: "BUILT_IN_FORGE_API_KEY is required when AI_PROVIDER=forge",
        });
      }
    }

    if (env.AI_PROVIDER === "ollama" && !env.OLLAMA_MODEL) {
      ctx.addIssue({
        code: "custom",
        path: ["OLLAMA_MODEL"],
        message: "OLLAMA_MODEL is required when AI_PROVIDER=ollama",
      });
    }
  });

function formatEnvValidationError(error: z.ZodError): Error {
  const issues = error.issues.map((issue) => {
    const field = issue.path[0]?.toString() || "environment";
    return `${field}: ${issue.message}`;
  });
  const uniqueIssues = Array.from(new Set(issues));
  return new Error(`Environment validation failed: ${uniqueIssues.join("; ")}`);
}

export function parseEnv(raw: RawEnv = process.env): AppEnv {
  const result = envInputSchema.safeParse(withTestDefaults(raw));
  if (!result.success) {
    throw formatEnvValidationError(result.error);
  }

  const env = result.data;
  const appId = env.APP_ID || env.VITE_APP_ID;
  const oAuthPortalUrl = env.OAUTH_PORTAL_URL || env.VITE_OAUTH_PORTAL_URL;

  if (!appId || !oAuthPortalUrl) {
    throw new Error("Environment validation failed");
  }

  return {
    appId,
    cookieSecret: env.JWT_SECRET,
    databaseUrl: env.DATABASE_URL,
    oAuthServerUrl: env.OAUTH_SERVER_URL,
    oAuthPortalUrl,
    ownerOpenId: env.OWNER_OPEN_ID,
    nodeEnv: env.NODE_ENV,
    isProduction: env.NODE_ENV === "production",
    forgeApiUrl: env.BUILT_IN_FORGE_API_URL ?? "",
    forgeApiKey: env.BUILT_IN_FORGE_API_KEY,
    aiProvider: env.AI_PROVIDER,
    cloudModel: env.LLM_MODEL,
    ollamaBaseUrl: env.OLLAMA_BASE_URL,
    ollamaModel: env.OLLAMA_MODEL,
  };
}

export const ENV = parseEnv();
