import { Suspense, lazy } from "react";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import DashboardLayout from "./components/DashboardLayout";
import { DashboardLayoutSkeleton } from "./components/DashboardLayoutSkeleton";

const AlertQueue = lazy(() => import("./pages/AlertQueue"));
const ExecutiveBrief = lazy(() => import("./pages/ExecutiveBrief"));
const Investigation = lazy(() => import("./pages/Investigation"));
const Metrics = lazy(() => import("./pages/Metrics"));
const QueryTool = lazy(() => import("./pages/QueryTool"));
const InvestigationHistory = lazy(() => import("./pages/InvestigationHistory"));

function Router() {
  return (
    <DashboardLayout>
      <Suspense fallback={<DashboardLayoutSkeleton />}>
        <Switch>
          <Route path={"/"} component={AlertQueue} />
          <Route path={"/briefing"} component={ExecutiveBrief} />
          <Route path={"/investigation"} component={Investigation} />
          <Route path={"/metrics"} component={Metrics} />
          <Route path={"/query"} component={QueryTool} />
          <Route path={"/history"} component={InvestigationHistory} />
          <Route path={"/404"} component={NotFound} />
          <Route component={NotFound} />
        </Switch>
      </Suspense>
    </DashboardLayout>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark">
        <TooltipProvider>
          <Toaster />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
