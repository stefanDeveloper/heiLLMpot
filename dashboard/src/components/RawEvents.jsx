import {formatTime, shortId} from "@/lib/format";
import Badge from "./Badge";

export default function RawEvents({rows = []}) {
  if (!rows.length) {
    return <div className="empty">No raw events captured yet.</div>;
  }

  return (
    <div className="event-feed">
      {rows.slice(0, 30).map((row) => {
        const raw = typeof row.raw === "string" ? row.raw : JSON.stringify(row.raw, null, 2);
        return (
          <div className="event-card" key={row.id}>
            <div className="event-top">
              <div><Badge value={row.event_type} /> <Badge value={row.protocol} /></div>
              <div className="muted mono">{formatTime(row.occurred_at)}</div>
            </div>
            <div className="muted">node {row.node_id} · session {shortId(row.session_id)}</div>
            <pre>{raw.slice(0, 1800)}</pre>
          </div>
        );
      })}
    </div>
  );
}
