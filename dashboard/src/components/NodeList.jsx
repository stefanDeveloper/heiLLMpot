import {formatTime} from "@/lib/format";
import Badge from "./Badge";

export default function NodeList({nodes = []}) {
  if (!nodes.length) {
    return <div className="empty">No nodes registered yet.</div>;
  }

  return (
    <div className="stack">
      {nodes.map((node) => (
        <div className="node-card" key={node.node_id}>
          <div className="node-title">
            <strong>{node.node_id}</strong>
            <Badge value={node.health} />
          </div>
          <div className="muted">{node.region || "no region"} {node.ip_address || ""}</div>
          <div className="muted">last seen {formatTime(node.last_seen) || "never"}</div>
        </div>
      ))}
    </div>
  );
}
