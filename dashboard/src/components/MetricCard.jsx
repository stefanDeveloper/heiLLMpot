import {formatNumber} from "@/lib/format";

export default function MetricCard({label, value, sub}) {
  return (
    <div className="metric">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{formatNumber(value)}</div>
      <div className="metric-sub">{sub}</div>
    </div>
  );
}
