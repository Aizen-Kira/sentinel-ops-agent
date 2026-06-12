import { TRPCError } from "@trpc/server";
import { z } from "zod";
import type { User } from "../../drizzle/schema";
import { NOT_ADMIN_ERR_MSG, UNAUTHED_ERR_MSG } from "@shared/const";
import { auditLog } from "./audit";

export const roleSchema = z.enum(["user", "analyst", "admin"]);
export type Role = z.infer<typeof roleSchema>;

const ROLE_RANK: Record<Role, number> = {
  user: 0,
  analyst: 1,
  admin: 2,
};

export function normalizeRole(value: unknown): Role | null {
  const result = roleSchema.safeParse(value);
  return result.success ? result.data : null;
}

export function isRoleAtLeast(actual: unknown, required: Role): boolean {
  const role = normalizeRole(actual);
  if (!role) return false;
  return ROLE_RANK[role] >= ROLE_RANK[required];
}

export function requireUser(user: User | null | undefined): User {
  if (!user) {
    throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }
  return user;
}

export function assertRole(
  user: User | null | undefined,
  requiredRole: Role,
  context: { action: string; resource?: string } = { action: "unknown" }
): User {
  const authenticatedUser = requireUser(user);
  if (!isRoleAtLeast(authenticatedUser.role, requiredRole)) {
    auditLog({
      type: "permission_denied",
      actorUserId: authenticatedUser.id,
      actorOpenId: authenticatedUser.openId,
      role: normalizeRole(authenticatedUser.role) ?? "invalid",
      action: context.action,
      resource: context.resource,
      outcome: "failure",
      reason: `requires role ${requiredRole}`,
    });

    throw new TRPCError({
      code: "FORBIDDEN",
      message: requiredRole === "admin" ? NOT_ADMIN_ERR_MSG : "Forbidden",
    });
  }
  return authenticatedUser;
}

export function assertCanAccessOwnedResource(
  user: User | null | undefined,
  ownerUserId: number | null | undefined,
  context: { action: string; resource: string }
): User {
  const authenticatedUser = requireUser(user);
  if (authenticatedUser.role === "admin") return authenticatedUser;
  if (typeof ownerUserId === "number" && ownerUserId === authenticatedUser.id) {
    return authenticatedUser;
  }

  auditLog({
    type: "permission_denied",
    actorUserId: authenticatedUser.id,
    actorOpenId: authenticatedUser.openId,
    role: normalizeRole(authenticatedUser.role) ?? "invalid",
    action: context.action,
    resource: context.resource,
    outcome: "failure",
    reason: "owner mismatch",
  });

  throw new TRPCError({
    code: "FORBIDDEN",
    message: "You do not have access to this resource",
  });
}

export function assertNotSelfApproval(
  user: User,
  proposedByUserId: number,
  context: { action: string; resource: string }
): void {
  if (user.id !== proposedByUserId) return;

  auditLog({
    type: "permission_denied",
    actorUserId: user.id,
    actorOpenId: user.openId,
    role: normalizeRole(user.role) ?? "invalid",
    action: context.action,
    resource: context.resource,
    outcome: "failure",
    reason: "self approval denied",
  });

  throw new TRPCError({
    code: "FORBIDDEN",
    message: "Response actions must be approved by a different authorized user",
  });
}
