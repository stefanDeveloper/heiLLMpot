import {formatNumber} from "@/lib/format";

export default function BarList({rows = [], labelKey, valueKey, emptyText}) {
  if (!rows.length) {
    return <div className="empty">{emptyText}</div>;
  }

  const max = Math.max(...rows.map((row) => Number(row[valueKey] || 0)), 1);

  return (
    <div className="bar-list">
      {rows.map((row) => {
        const value = Number(row[valueKey] || 0);
        const width = Math.max(4, Math.round((value / max) * 100));
        return (
          <div className="bar-row" key={`${row[labelKey]}-${value}`}>
            <div className="bar-label">
              <div className="truncate">{row[labelKey] || "unknown"}</div>
              <div className="bar-track">
                <div className="bar-fill" style={{width: `${width}%`}} />
              </div>
            </div>
            <div className="mono">{formatNumber(value)}</div>
          </div>
        );
      })}
    </div>
  );
}
