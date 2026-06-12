import { useAuth } from "@/_core/hooks/useAuth";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";
import { getLoginUrl } from "@/const";
import { useIsMobile } from "@/hooks/useMobile";
import { DEMO_MODE } from "@/lib/demoMode";
import { LogOut, PanelLeft } from "lucide-react";
import { CSSProperties, useEffect, useRef, useState } from "react";
import { useLocation } from "wouter";
import { DashboardLayoutSkeleton } from './DashboardLayoutSkeleton';
import { DemoModeBadge, DemoModeNotice } from "./DemoModeNotice";
import { Button } from "./ui/button";

import { AlertCircle, Brain, BarChart3, Search, History, Building2, Shield, Sparkles } from "lucide-react";

const menuItems = [
  { icon: AlertCircle, label: "Alert Queue", path: "/" },
  { icon: Building2, label: "CEO Brief", path: "/briefing" },
  { icon: Brain, label: "Investigation", path: "/investigation" },
  { icon: BarChart3, label: "Metrics", path: "/metrics" },
  { icon: Search, label: "Query Tool", path: "/query" },
  { icon: History, label: "History", path: "/history" },
];

const SIDEBAR_WIDTH_KEY = "sidebar-width";
const DEFAULT_WIDTH = 280;
const MIN_WIDTH = 200;
const MAX_WIDTH = 480;

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    const saved = localStorage.getItem(SIDEBAR_WIDTH_KEY);
    return saved ? parseInt(saved, 10) : DEFAULT_WIDTH;
  });
  const { loading, user } = useAuth();

  useEffect(() => {
    localStorage.setItem(SIDEBAR_WIDTH_KEY, sidebarWidth.toString());
  }, [sidebarWidth]);

  if (loading) {
    return <DashboardLayoutSkeleton />
  }

  if (!user) {
    return (
      <div className="flex min-h-screen items-center justify-center px-4 py-8">
        <div className="page-hero w-full max-w-4xl px-8 py-10">
          <div className="relative grid gap-8 lg:grid-cols-[1.15fr,0.85fr] lg:items-center">
            <div className="space-y-5">
              <div className="section-kicker">Sentinel Ops</div>
              <h1 className="text-3xl font-semibold leading-tight text-white md:text-5xl">
                Realtime security operations built for startup teams.
              </h1>
              <p className="max-w-xl text-sm leading-7 text-slate-300 md:text-base">
                Sign in to open the live alert feed, executive brief, and local-first
                investigation workflow. {DEMO_MODE
                  ? "This demo environment is optimized for quick walkthroughs."
                  : "Production mode hides demo-only guidance and fallback labels."}
              </p>
            </div>

            <div className="surface-panel p-6">
              <div className="rounded-3xl border border-white/8 bg-white/4 p-6">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[linear-gradient(135deg,rgba(56,189,248,0.22),rgba(59,130,246,0.08))] ring-1 ring-white/10">
                  <Shield className="h-6 w-6 text-sky-300" />
                </div>
                <h2 className="mt-5 text-2xl font-semibold text-white">
                  Sign in to continue
                </h2>
                <p className="mt-3 text-sm leading-6 text-slate-400">
                  Access to this dashboard requires authentication. Continue to launch the login flow.
                </p>
                <Button
                  onClick={() => {
                    window.location.href = getLoginUrl();
                  }}
                  size="lg"
                  className="mt-6 w-full"
                >
                  Sign in
                </Button>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <SidebarProvider
      style={
        {
          "--sidebar-width": `${sidebarWidth}px`,
        } as CSSProperties
      }
    >
      <DashboardLayoutContent setSidebarWidth={setSidebarWidth}>
        {children}
      </DashboardLayoutContent>
    </SidebarProvider>
  );
}

type DashboardLayoutContentProps = {
  children: React.ReactNode;
  setSidebarWidth: (width: number) => void;
};

function DashboardLayoutContent({
  children,
  setSidebarWidth,
}: DashboardLayoutContentProps) {
  const { user, logout } = useAuth();
  const [location, setLocation] = useLocation();
  const { state, toggleSidebar } = useSidebar();
  const isCollapsed = state === "collapsed";
  const [isResizing, setIsResizing] = useState(false);
  const sidebarRef = useRef<HTMLDivElement>(null);
  const activeMenuItem = menuItems.find(item => item.path === location);
  const isMobile = useIsMobile();

  useEffect(() => {
    if (isCollapsed) {
      setIsResizing(false);
    }
  }, [isCollapsed]);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing) return;

      const sidebarLeft = sidebarRef.current?.getBoundingClientRect().left ?? 0;
      const newWidth = e.clientX - sidebarLeft;
      if (newWidth >= MIN_WIDTH && newWidth <= MAX_WIDTH) {
        setSidebarWidth(newWidth);
      }
    };

    const handleMouseUp = () => {
      setIsResizing(false);
    };

    if (isResizing) {
      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
    }

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [isResizing, setSidebarWidth]);

  return (
    <>
      <div className="relative" ref={sidebarRef}>
        <Sidebar
          collapsible="icon"
          className="border-r border-sidebar-border/80 bg-sidebar/78 backdrop-blur-2xl"
          disableTransition={isResizing}
        >
          <SidebarHeader className="justify-center border-b border-sidebar-border/80 px-3 py-4">
            <div className="flex items-start gap-3 transition-all w-full">
              <button
                onClick={toggleSidebar}
                className="mt-0.5 flex h-9 w-9 items-center justify-center rounded-xl border border-sidebar-border/70 bg-white/5 transition-colors hover:bg-sidebar-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring shrink-0"
                aria-label="Toggle navigation"
              >
                <PanelLeft className="h-4 w-4 text-sidebar-foreground/60" />
              </button>
              {!isCollapsed ? (
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[linear-gradient(135deg,rgba(56,189,248,0.28),rgba(59,130,246,0.12))] ring-1 ring-white/10">
                      <Shield className="h-5 w-5 text-sky-300" />
                    </div>
                    <div className="min-w-0">
                      <div className="font-semibold tracking-tight truncate text-sm text-sidebar-foreground">
                        Sentinel Ops
                      </div>
                      <div className="mt-1 flex items-center gap-2 text-[11px] text-sidebar-foreground/60">
                        <span className="inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_12px_rgba(74,222,128,0.8)]" />
                        Realtime command center
                      </div>
                    </div>
                    <DemoModeBadge label="Demo" />
                  </div>
                  <DemoModeNotice compact className="mt-4 flex">
                    Synthetic alerts, local analyst playbooks, and fallback executive briefings may be active.
                  </DemoModeNotice>
                </div>
              ) : null}
            </div>
          </SidebarHeader>

          <SidebarContent className="gap-0 px-2 py-3">
            {!isCollapsed ? (
              <div className="px-3 pb-2">
                <div className="section-kicker">Workspaces</div>
              </div>
            ) : null}
            <SidebarMenu className="px-2 py-1">
              {menuItems.map(item => {
                const isActive = location === item.path;
                return (
                  <SidebarMenuItem key={item.path}>
                    <SidebarMenuButton
                      isActive={isActive}
                      onClick={() => setLocation(item.path)}
                      tooltip={item.label}
                      className={`h-11 rounded-xl transition-all font-normal ${
                        isActive
                          ? "bg-white/8 text-sidebar-foreground shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]"
                          : "text-sidebar-foreground/72 hover:text-sidebar-foreground"
                      }`}
                    >
                      <item.icon
                        className={`h-4 w-4 ${isActive ? "text-primary" : ""}`}
                      />
                      <span>{item.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarContent>

          <SidebarFooter className="p-3">
            {!isCollapsed && DEMO_MODE ? (
              <div className="surface-panel-muted mb-3 flex items-center gap-3 px-3 py-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-sky-400/10 text-sky-300">
                  <Sparkles className="h-4 w-4" />
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-medium text-sidebar-foreground">
                    Demo Ready
                  </p>
                  <p className="text-xs text-sidebar-foreground/60">
                    Local AI and realtime briefing are active.
                  </p>
                </div>
              </div>
            ) : null}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="flex items-center gap-3 rounded-2xl border border-white/8 bg-white/4 px-2 py-2 hover:bg-accent/50 transition-colors w-full text-left group-data-[collapsible=icon]:justify-center focus:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                  <Avatar className="h-9 w-9 border border-white/10 shrink-0">
                    <AvatarFallback className="text-xs font-medium">
                      {user?.name?.charAt(0).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <div className="flex-1 min-w-0 group-data-[collapsible=icon]:hidden">
                    <p className="text-sm font-medium truncate leading-none">
                      {user?.name || "-"}
                    </p>
                    <p className="text-xs text-muted-foreground truncate mt-1.5">
                      {user?.email || "-"}
                    </p>
                  </div>
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuItem
                  onClick={logout}
                  className="cursor-pointer text-destructive focus:text-destructive"
                >
                  <LogOut className="mr-2 h-4 w-4" />
                  <span>Sign out</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarFooter>
        </Sidebar>
        <div
          className={`absolute top-0 right-0 w-1 h-full cursor-col-resize hover:bg-primary/20 transition-colors ${isCollapsed ? "hidden" : ""}`}
          onMouseDown={() => {
            if (isCollapsed) return;
            setIsResizing(true);
          }}
          style={{ zIndex: 50 }}
        />
      </div>

      <SidebarInset className="bg-transparent">
        {isMobile && (
          <div className="sticky top-0 z-40 flex h-14 items-center justify-between border-b border-white/8 bg-background/80 px-2 backdrop-blur supports-[backdrop-filter]:backdrop-blur">
            <div className="flex items-center gap-2">
              <SidebarTrigger className="h-9 w-9 rounded-xl border border-white/8 bg-background/80" />
              <div className="flex items-center gap-3">
                <div className="flex flex-col gap-1">
                  <span className="tracking-tight text-foreground font-medium">
                    {activeMenuItem?.label ?? "Menu"}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
        <main className="dashboard-main flex-1 px-3 pt-4 md:px-5 md:pt-5">{children}</main>
      </SidebarInset>
    </>
  );
}
