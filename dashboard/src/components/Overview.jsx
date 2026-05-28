import {formatNumber} from "@/lib/format";
import MetricCard from "./MetricCard";

export default function Overview({overview = {}}) {
  return (
    <section className="metric-grid">
      <MetricCard label="Sessions" value={overview.total_sessions} sub={`${formatNumber(overview.sessions_24h)} in 24h`} />
      <MetricCard label="Events" value={overview.total_events} sub={`${formatNumber(overview.events_1h)} in 1h`} />
      <MetricCard label="HTTP Requests" value={overview.total_http_requests} sub="captured requests" />
      <MetricCard label="Credentials" value={overview.total_credentials} sub="login attempts" />
      <MetricCard label="Unique IPs" value={overview.unique_ips_24h} sub="last 24h" />
      <MetricCard label="Active Nodes" value={overview.active_nodes} sub="registered active" />
    </section>
  );
}
