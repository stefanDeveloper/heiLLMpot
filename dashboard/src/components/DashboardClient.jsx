"use client";

import {useEffect, useState} from "react";

import {formatNumber, formatTime} from "@/lib/format";
import BarList from "./BarList";
import NodeList from "./NodeList";
import Overview from "./Overview";
import Panel from "./Panel";
import RawEvents from "./RawEvents";
import {CredentialsTable, DailyTable, HttpTable, SessionsTable} from "./Tables";

export default function DashboardClient({initialRefreshMs, secretsRedacted}) {
  const [snapshot, setSnapshot] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function refresh() {
      try {
        const response = await fetch("/api/snapshot", {cache: "no-store"});
        const data = await response.json();
        if (!response.ok || data.status !== "ok") {
          throw new Error(data.message || `HTTP ${response.status}`);
        }
        if (!cancelled) {
          setSnapshot(data);
          setError("");
        }
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
    }

    refresh();
    const timer = setInterval(refresh, initialRefreshMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [initialRefreshMs]);

  const redacted = snapshot?.redacted ?? secretsRedacted;

  return (
    <>
      <header className="app-header">
        <div className="brand">
          <img src="/mark.svg" alt="" className="brand-mark" />
          <div>
            <h1>heiLLMpot Dashboard</h1>
            <p>Live orchestrator telemetry</p>
          </div>
        </div>
        <div className="header-actions">
          <span className="chip">{redacted ? "Secrets redacted" : "Secrets visible"}</span>
          <span className={`chip ${error ? "chip-bad" : "chip-ok"}`}>{error ? "Offline" : "Live"}</span>
          <span className="muted">{error || (snapshot ? `Updated ${formatTime(snapshot.generated_at)}` : "Waiting for data")}</span>
        </div>
      </header>

      <main>
        <Overview overview={snapshot?.overview || {}} />
        <section className="dashboard-grid">
          <Panel title="Recent Sessions" subtitle={`${formatNumber(snapshot?.recent_sessions?.length || 0)} shown`}>
            <SessionsTable rows={snapshot?.recent_sessions || []} />
          </Panel>
          <Panel title="Nodes" subtitle="health">
            <NodeList nodes={snapshot?.nodes || []} />
          </Panel>
          <Panel title="Event Types" subtitle="all time">
            <BarList rows={snapshot?.event_types || []} labelKey="event_type" valueKey="count" emptyText="No events yet." />
          </Panel>
          <Panel title="Top Paths" subtitle="HTTP">
            <BarList rows={snapshot?.top_paths || []} labelKey="path" valueKey="count" emptyText="No HTTP paths yet." />
          </Panel>
          <Panel title="Top IPs" subtitle="sessions">
            <BarList rows={snapshot?.top_ips || []} labelKey="client_ip" valueKey="sessions" emptyText="No client IPs yet." />
          </Panel>
          <Panel title="Recent HTTP Requests" subtitle="latest first">
            <HttpTable rows={snapshot?.http_requests || []} />
          </Panel>
          <Panel title="Credentials" subtitle="attempts">
            <CredentialsTable rows={snapshot?.credentials || []} />
          </Panel>
          <Panel title="Recent Raw Events" subtitle="JSON preview">
            <RawEvents rows={snapshot?.recent_events || []} />
          </Panel>
          <Panel title="Daily Stats" subtitle="materialized view">
            <DailyTable rows={snapshot?.daily_stats || []} />
          </Panel>
        </section>
      </main>
    </>
  );
}
