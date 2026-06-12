import { NOT_ADMIN_ERR_MSG, UNAUTHED_ERR_MSG } from '@shared/const';
import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";
import type { TrpcContext } from "./context";
import { hasCapability, type Capability } from "./capabilities";

const t = initTRPC.context<TrpcContext>().create({
  transformer: superjson,
});

export const router = t.router;
export const publicProcedure = t.procedure;

const requireUser = t.middleware(async opts => {
  const { ctx, next } = opts;

  if (!ctx.user) {
    throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
  }

  return next({
    ctx: {
      ...ctx,
      user: ctx.user,
      tenantId: ctx.tenantId,
      capabilities: ctx.capabilities,
    },
  });
});

export const protectedProcedure = t.procedure.use(requireUser);

const requireCapability = (capability: Capability, message = "Forbidden") =>
  t.middleware(async (opts) => {
    const { ctx, next } = opts;

    if (!ctx.user) {
      throw new TRPCError({ code: "UNAUTHORIZED", message: UNAUTHED_ERR_MSG });
    }

    if (!hasCapability(ctx.user, capability)) {
      throw new TRPCError({ code: "FORBIDDEN", message });
    }

    return next({
      ctx: {
        ...ctx,
        user: ctx.user,
        tenantId: ctx.tenantId,
        capabilities: ctx.capabilities,
      },
    });
  });

export const viewInvestigationProcedure = t.procedure.use(
  requireCapability("canViewInvestigation")
);

export const manageAlertsProcedure = t.procedure.use(
  requireCapability("canManageAlerts")
);

export const approveActionProcedure = t.procedure.use(
  requireCapability("canApproveAction")
);

export const adminProcedure = t.procedure.use(
  requireCapability("canAdminTenant", NOT_ADMIN_ERR_MSG)
);
