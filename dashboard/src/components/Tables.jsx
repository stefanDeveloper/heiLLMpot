import {formatNumber, formatTime} from "@/lib/format";
import Badge from "./Badge";

function EmptyRow({text}) {
  return (
    <tr>
      <td className="empty" colSpan="99">{text}</td>
    </tr>
  );
}

export function SessionsTable({rows = []}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Started</th>
            <th>Node</th>
            <th>Proto</th>
            <th>Client</th>
            <th>Geo</th>
            <th>Events</th>
            <th>Class</th>
          </tr>
        </thead>
        <tbody>
          {!rows.length ? <EmptyRow text="No sessions captured yet." /> : rows.map((row) => (
            <tr key={row.id}>
              <td className="mono">{formatTime(row.started_at)}</td>
              <td>{row.node_id}</td>
              <td><Badge value={row.protocol} /></td>
              <td><code>{row.client_ip || ""}:{row.client_port || ""}</code></td>
              <td>{row.geo_country_iso || row.geo_country || ""}</td>
              <td>{formatNumber(row.event_count)}</td>
              <td><Badge value={row.classification} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function HttpTable({rows = []}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Node</th>
            <th>Method</th>
            <th>Path</th>
            <th>Status</th>
            <th>User agent</th>
          </tr>
        </thead>
        <tbody>
          {!rows.length ? <EmptyRow text="No HTTP requests captured yet." /> : rows.map((row) => (
            <tr key={row.id}>
              <td className="mono">{formatTime(row.occurred_at)}</td>
              <td>{row.node_id}</td>
              <td><Badge value={row.method || "GET"} /></td>
              <td><code>{row.path || ""}</code></td>
              <td>{row.status_code || ""}</td>
              <td className="truncate">{row.user_agent || ""}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function CredentialsTable({rows = []}) {
  return (
    <div className="table-wrap compact">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Proto</th>
            <th>Username</th>
            <th>Password</th>
          </tr>
        </thead>
        <tbody>
          {!rows.length ? <EmptyRow text="No credential attempts captured yet." /> : rows.map((row) => (
            <tr key={row.id}>
              <td className="mono">{formatTime(row.occurred_at)}</td>
              <td><Badge value={row.protocol} /></td>
              <td><code>{row.username || ""}</code></td>
              <td><code>{row.password || ""}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function DailyTable({rows = []}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Day</th>
            <th>Node</th>
            <th>Proto</th>
            <th>Label</th>
            <th>Sessions</th>
            <th>IPs</th>
            <th>Events</th>
          </tr>
        </thead>
        <tbody>
          {!rows.length ? <EmptyRow text="Daily stats are not available yet." /> : rows.map((row) => (
            <tr key={`${row.day}-${row.node_id}-${row.protocol}-${row.label}`}>
              <td className="mono">{String(row.day || "").slice(0, 10)}</td>
              <td>{row.node_id}</td>
              <td><Badge value={row.protocol} /></td>
              <td><Badge value={row.label} /></td>
              <td>{formatNumber(row.session_count)}</td>
              <td>{formatNumber(row.unique_ips)}</td>
              <td>{formatNumber(row.total_events)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
