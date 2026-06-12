import { History, ChevronRight } from "lucide-react";
import { ConnectionStatus } from "@/components/ConnectionStatus";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useRealtime } from "@/hooks/useRealtime";
import { trpc } from "@/lib/trpc";

export default function InvestigationHistory() {
  const { status: realtimeStatus } = useRealtime();
  const { data: investigations = [], isLoading } =
    trpc.history.investigations.useQuery({
      limit: 50,
      offset: 0,
    });

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "bg-green-500/20 text-green-400";
      case "in_progress":
        return "bg-blue-500/20 text-blue-400";
      case "failed":
        return "bg-red-500/20 text-red-400";
      default:
        return "bg-gray-500/20 text-gray-400";
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.9) return "text-green-400";
    if (confidence >= 0.7) return "text-yellow-400";
    if (confidence > 0) return "text-orange-400";
    return "text-muted-foreground";
  };

  const formatConfidence = (value: unknown) => {
    const numeric =
      typeof value === "number"
        ? value
        : typeof value === "string"
          ? Number.parseFloat(value)
          : 0;

    return Number.isFinite(numeric) ? numeric : 0;
  };

  const formatAnalyst = (investigation: {
    analystName?: string | null;
    analystEmail?: string | null;
    userId: number;
  }) =>
    investigation.analystName ||
    investigation.analystEmail ||
    `Analyst #${investigation.userId}`;

  const formatTimestamp = (value: Date | string | null | undefined) => {
    if (!value) return "Not available";
    return new Date(value).toLocaleString();
  };

  const getAlertCount = (alertIds: unknown) =>
    Array.isArray(alertIds) ? alertIds.length : 0;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
            <History className="w-8 h-8 text-blue-500" />
            Investigation History
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Past AI investigations and their conclusions
          </p>
        </div>
        <ConnectionStatus status={realtimeStatus} />
      </div>

      <div className="space-y-3">
        {isLoading ? (
          <Card className="p-8 text-center text-muted-foreground">
            Loading investigation history...
          </Card>
        ) : investigations.length === 0 ? (
          <Card className="p-8 text-center text-muted-foreground">
            No investigations have been recorded yet.
          </Card>
        ) : (
          investigations.map((inv) => {
            const confidence = formatConfidence(inv.confidenceScore);

            return (
              <Card
                key={inv.id}
                className="p-4 hover:bg-card/80 transition-colors cursor-pointer group"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-2">
                      <div
                        className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(inv.status)}`}
                      >
                        {inv.status === "completed"
                          ? "Completed"
                          : inv.status === "in_progress"
                            ? "In Progress"
                            : "Failed"}
                      </div>
                      <span className="text-xs text-muted-foreground font-mono">
                        {inv.investigationId}
                      </span>
                    </div>

                    <h3 className="font-semibold text-foreground mb-2">
                      {inv.investigationId}
                    </h3>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm mb-3">
                      <div>
                        <span className="text-xs text-muted-foreground/60">
                          Alerts:
                        </span>
                        <p className="text-foreground/80">
                          {getAlertCount(inv.alertIds)}
                        </p>
                      </div>
                      <div>
                        <span className="text-xs text-muted-foreground/60">
                          Analyst:
                        </span>
                        <p className="text-foreground/80">
                          {formatAnalyst(inv)}
                        </p>
                      </div>
                      <div>
                        <span className="text-xs text-muted-foreground/60">
                          Started:
                        </span>
                        <p className="text-foreground/80">
                          {formatTimestamp(inv.createdAt)}
                        </p>
                      </div>
                      {confidence > 0 && (
                        <div>
                          <span className="text-xs text-muted-foreground/60">
                            Confidence:
                          </span>
                          <p
                            className={`font-semibold ${getConfidenceColor(confidence)}`}
                          >
                            {(confidence * 100).toFixed(0)}%
                          </p>
                        </div>
                      )}
                    </div>

                    <p className="text-sm text-muted-foreground line-clamp-2">
                      {inv.conclusion || "Conclusion not available yet."}
                    </p>
                  </div>

                  <Button
                    variant="ghost"
                    size="sm"
                    className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </Button>
                </div>
              </Card>
            );
          })
        )}
      </div>
    </div>
  );
}
