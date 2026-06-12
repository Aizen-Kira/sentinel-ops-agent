const REDACTED = "[REDACTED]";

const SENSITIVE_KEY_PATTERN =
  /(?:secret|token|api[_-]?key|password|authorization|cookie|database[_-]?url|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token)/i;

const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;
const BEARER_PATTERN = /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi;
const URL_CREDENTIALS_PATTERN =
  /\b([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^@\s/]+)@/gi;
const ASSIGNMENT_PATTERN =
  /\b([A-Z0-9_-]*(?:SECRET|TOKEN|API[_-]?KEY|PASSWORD|AUTHORIZATION|COOKIE|DATABASE[_-]?URL|CLIENT[_-]?SECRET)[A-Z0-9_-]*)\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi;
const JSON_FIELD_PATTERN =
  /(["']?)([A-Za-z0-9_-]*(?:secret|token|api[_-]?key|password|authorization|cookie|database[_-]?url|client[_-]?secret)[A-Za-z0-9_-]*)\1\s*:\s*(["'])(.*?)\3/gi;

function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key);
}

export function sanitizeLogString(value: string): string {
  return value
    .replace(URL_CREDENTIALS_PATTERN, `$1${REDACTED}@`)
    .replace(BEARER_PATTERN, `Bearer ${REDACTED}`)
    .replace(JWT_PATTERN, REDACTED)
    .replace(ASSIGNMENT_PATTERN, `$1=${REDACTED}`)
    .replace(JSON_FIELD_PATTERN, (_match, quote, key) => {
      const normalizedKey = quote ? `${quote}${key}${quote}` : key;
      return `${normalizedKey}:${REDACTED}`;
    });
}

export function sanitizeLogValue(value: unknown, depth = 0): unknown {
  if (depth > 6) return "[MaxDepth]";

  if (typeof value === "string") {
    return sanitizeLogString(value);
  }

  if (
    value === null ||
    typeof value === "undefined" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    typeof value === "bigint"
  ) {
    return value;
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: sanitizeLogString(value.message),
      ...(value.stack ? { stack: sanitizeLogString(value.stack) } : {}),
    };
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeLogValue(item, depth + 1));
  }

  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, item]) => [
        key,
        isSensitiveKey(key) ? REDACTED : sanitizeLogValue(item, depth + 1),
      ])
    );
  }

  return value;
}
