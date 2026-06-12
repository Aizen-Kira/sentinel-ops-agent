import type { User } from "../../drizzle/schema";

export type Capability =
  | "canViewInvestigation"
  | "canApproveAction"
  | "canManageAlerts"
  | "canAdminTenant";

const ROLE_CAPABILITIES: Record<User["role"], Capability[]> = {
  user: ["canViewInvestigation", "canManageAlerts"],
  analyst: ["canViewInvestigation", "canManageAlerts"],
  admin: [
    "canViewInvestigation",
    "canApproveAction",
    "canManageAlerts",
    "canAdminTenant",
  ],
};

export const DEFAULT_TENANT_ID = "default";

export const getTenantIdForUser = (_user: User | null | undefined): string =>
  DEFAULT_TENANT_ID;

export const getUserCapabilities = (user: User | null | undefined): Capability[] =>
  user ? ROLE_CAPABILITIES[user.role] ?? [] : [];

export const hasCapability = (
  user: User | null | undefined,
  capability: Capability
): boolean => getUserCapabilities(user).includes(capability);

export const canUserAccessInvestigation = (
  user: User | null | undefined,
  investigationOwnerId: number | null | undefined
): boolean => {
  if (!user) return false;
  if (user.role === "admin") return true;
  if (typeof investigationOwnerId !== "number") return true;
  return user.id === investigationOwnerId;
};
