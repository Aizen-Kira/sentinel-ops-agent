import { useState } from "react";
import { Search, Clock, Zap } from "lucide-react";
import { DemoModeNotice } from "@/components/DemoModeNotice";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";

type SeverityFilter = "" | "critical" | "high" | "medium" | "low";
type StatusFilter = "" | "open" | "acknowledged" | "escalated" | "dismissed";

export default function QueryTool() {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<SeverityFilter>("");
  const [status, setStatus] = useState<StatusFilter>("");
  const [eventType, setEventType] = useState<string>("");
  const [results, setResults] = useState<any[]>([]);
  const [totalResults, setTotalResults] = useState(0);
  const [isSearching, setIsSearching] = useState(false);
  const [queryHistory, setQueryHistory] = useState<string[]>([]);
  const utils = trpc.useUtils();

  const handleSearch = async () => {
    if (!query.trim() && !severity && !status && !eventType) {
      toast.error("Please enter a search query or select filters");
      return;
    }

    setIsSearching(true);
    try {
      const result = await utils.query.search.fetch({
        keyword: query.trim() || undefined,
        severity: severity || undefined,
        status: status || undefined,
        eventType: eventType || undefined,
        limit: 100,
        offset: 0,
      });

      setResults(result.results);
      setTotalResults(result.total);

      // Add to history
      if (query.trim()) {
        setQueryHistory((prev) => [query, ...prev.slice(0, 9)]);
      }

      toast.success(`Found ${result.total} alerts`);
    } catch (error: any) {
      toast.error(`Search failed: ${error.message}`);
    } finally {
      setIsSearching(false);
    }
  };

  const handleQuickSearch = (text: string) => {
    setQuery(text);
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-500/20 text-red-400";
      case "high":
        return "bg-orange-500/20 text-orange-400";
      case "medium":
        return "bg-yellow-500/20 text-yellow-400";
      case "low":
        return "bg-blue-500/20 text-blue-400";
      default:
        return "bg-gray-500/20 text-gray-400";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "open":
        return "bg-red-500/10 text-red-400";
      case "acknowledged":
        return "bg-yellow-500/10 text-yellow-400";
      case "escalated":
        return "bg-orange-500/10 text-orange-400";
      case "dismissed":
        return "bg-green-500/10 text-green-400";
      default:
        return "bg-gray-500/10 text-gray-400";
    }
  };

  const formatTime = (date: Date) => {
    return new Date(date).toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Search className="h-6 w-6 text-purple-500" />
        <div>
          <h1 className="text-2xl font-bold">Query Tool</h1>
          <p className="text-sm text-muted-foreground">SPL-style search and filtering for security events</p>
        </div>
      </div>

      <DemoModeNotice>
        This UI searches the local alert store; Splunk API routes fall back to mock responses when Splunk environment variables are not configured.
      </DemoModeNotice>

      {/* Search Panel */}
      <Card className="p-6 space-y-4">
        <div>
          <label className="text-sm font-medium mb-2 block">Search Query</label>
          <div className="flex gap-2">
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && handleSearch()}
              placeholder='e.g., "failed login" OR "port scan" source:192.168.1.45'
              className="flex-1 px-3 py-2 bg-black/30 border border-border/50 rounded text-sm focus:outline-none focus:border-blue-500"
            />
            <Button onClick={handleSearch} disabled={isSearching} className="gap-2">
              <Search className="h-4 w-4" />
              Search
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            Supports keywords, phrases, AND/OR operators, and field:value syntax
          </p>
        </div>

        {/* Filters */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="text-sm font-medium mb-2 block">Severity</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as SeverityFilter)}
              className="w-full px-3 py-2 bg-black/30 border border-border/50 rounded text-sm focus:outline-none focus:border-blue-500"
            >
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div>
            <label className="text-sm font-medium mb-2 block">Status</label>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as StatusFilter)}
              className="w-full px-3 py-2 bg-black/30 border border-border/50 rounded text-sm focus:outline-none focus:border-blue-500"
            >
              <option value="">All</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="escalated">Escalated</option>
              <option value="dismissed">Dismissed</option>
            </select>
          </div>

          <div>
            <label className="text-sm font-medium mb-2 block">Event Type</label>
            <select
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              className="w-full px-3 py-2 bg-black/30 border border-border/50 rounded text-sm focus:outline-none focus:border-blue-500"
            >
              <option value="">All</option>
              <option value="failed_login">Failed Login</option>
              <option value="port_scan">Port Scan</option>
              <option value="lateral_movement">Lateral Movement</option>
              <option value="data_exfiltration">Data Exfiltration</option>
            </select>
          </div>
        </div>

        {/* Quick Filters */}
        <div>
          <p className="text-xs font-medium text-muted-foreground mb-2">Quick Searches:</p>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleQuickSearch("failed login")}
              className="text-xs"
            >
              Failed Logins
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleQuickSearch("port scan")}
              className="text-xs"
            >
              Port Scans
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleQuickSearch("lateral movement")}
              className="text-xs"
            >
              Lateral Movement
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleQuickSearch("data exfiltration")}
              className="text-xs"
            >
              Data Exfiltration
            </Button>
          </div>
        </div>
      </Card>

      {/* Query History */}
      {queryHistory.length > 0 && (
        <Card className="p-4">
          <h2 className="font-semibold mb-3 flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Recent Queries
          </h2>
          <div className="flex flex-wrap gap-2">
            {queryHistory.map((q, idx) => (
              <Button
                key={idx}
                variant="outline"
                size="sm"
                onClick={() => handleQuickSearch(q)}
                className="text-xs"
              >
                {q.length > 20 ? q.substring(0, 20) + "..." : q}
              </Button>
            ))}
          </div>
        </Card>
      )}

      {/* Results */}
      <div>
        {results.length === 0 && !isSearching ? (
          <Card className="p-8 text-center text-muted-foreground">
            <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>Enter a search query to find security events</p>
          </Card>
        ) : isSearching ? (
          <Card className="p-8 text-center text-muted-foreground">
            <Zap className="h-12 w-12 mx-auto mb-4 animate-pulse" />
            <p>Searching...</p>
          </Card>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="font-semibold">
                Search Results ({totalResults} alerts)
              </h2>
            </div>

            {results.map((alert) => (
              <Card key={alert.id} className="p-4 border-l-4" style={{ borderLeftColor: alert.severity === "critical" ? "#ef4444" : alert.severity === "high" ? "#f97316" : alert.severity === "medium" ? "#eab308" : "#3b82f6" }}>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <span className={`px-2 py-1 rounded text-xs font-bold ${getSeverityColor(alert.severity)}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      <span className="text-sm font-mono text-muted-foreground">{alert.eventId}</span>
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${getStatusColor(alert.status)}`}>
                        {alert.status.charAt(0).toUpperCase() + alert.status.slice(1)}
                      </span>
                    </div>
                    <h3 className="text-lg font-semibold mb-1">{alert.title}</h3>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground">Source:</span>
                        <div className="font-mono text-foreground">{alert.source}</div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Target:</span>
                        <div className="font-mono text-foreground">{alert.target || "N/A"}</div>
                      </div>
                    </div>
                  </div>
                  <div className="text-right text-xs text-muted-foreground">
                    {formatTime(alert.createdAt)}
                  </div>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
