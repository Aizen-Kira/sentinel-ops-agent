import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { Card } from "@/components/ui/card";

export function MetricsCharts(props: {
  timelineData: Array<{ time: string; alerts: number }>;
  severityData: Array<{ name: string; value: number; fill: string }>;
  statusData: Array<{ name: string; value: number; fill: string }>;
}) {
  return (
    <>
      <div className="grid gap-6 xl:grid-cols-2">
        <Card className="surface-panel p-6">
          <h2 className="text-lg font-semibold text-white">Alert Timeline (24h)</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Track how live alert pressure moves across the last day.
          </p>
          <div className="mt-6 h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={props.timelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
                <XAxis dataKey="time" stroke="#7f8da5" />
                <YAxis stroke="#7f8da5" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "rgba(8,12,24,0.94)",
                    border: "1px solid rgba(255,255,255,0.08)",
                    borderRadius: 16,
                  }}
                />
                <Bar dataKey="alerts" fill="#60a5fa" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card className="surface-panel p-6">
          <h2 className="text-lg font-semibold text-white">Severity Distribution</h2>
          <p className="mt-2 text-sm leading-6 text-slate-400">
            Show the mix of risk levels currently flowing through the queue.
          </p>
          <div className="mt-6 h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={props.severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, value }) => `${name}: ${value}`}
                  outerRadius={88}
                  dataKey="value"
                >
                  {props.severityData.map((entry, index) => (
                    <Cell key={`severity-${index}`} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "rgba(8,12,24,0.94)",
                    border: "1px solid rgba(255,255,255,0.08)",
                    borderRadius: 16,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <Card className="surface-panel p-6">
        <h2 className="text-lg font-semibold text-white">Alert Status Breakdown</h2>
        <p className="mt-2 text-sm leading-6 text-slate-400">
          This chart helps the audience see queue progression from open to dismissed.
        </p>
        <div className="mt-6 h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={props.statusData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
              <XAxis dataKey="name" stroke="#7f8da5" />
              <YAxis stroke="#7f8da5" />
              <Tooltip
                contentStyle={{
                  backgroundColor: "rgba(8,12,24,0.94)",
                  border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 16,
                }}
              />
              <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                {props.statusData.map((entry, index) => (
                  <Cell key={`status-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>
    </>
  );
}

export default MetricsCharts;
