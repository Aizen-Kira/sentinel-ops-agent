const TRUE_VALUES = new Set(["1", "true", "yes", "on"]);
const FALSE_VALUES = new Set(["0", "false", "no", "off"]);

const normalizeFlag = (value: unknown): boolean | null => {
  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.trim().toLowerCase();
  if (TRUE_VALUES.has(normalized)) return true;
  if (FALSE_VALUES.has(normalized)) return false;
  return null;
};

export const DEMO_MODE =
  normalizeFlag(import.meta.env.VITE_DEMO_MODE) ?? import.meta.env.DEV;
