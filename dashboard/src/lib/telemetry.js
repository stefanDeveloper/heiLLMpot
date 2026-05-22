import {query, queryOne} from "./db.js";
import {envBool, envInt} from "./env.js";

export async function getSnapshot() {
  const limit = rowLimit();
  const [
    overview,
    nodes,
    recentSessions,
    recentEvents,
    httpRequests,
    credentials,
    topPaths,
    topIps,
    eventTypes,
    dailyStats
  ] = await Promise.all([
    getOverview(),
    getNodes(),
    getRecentSessions(limit),
    getRecentEvents(limit),
    getHttpRequests(limit),
    getCredentials(limit),
    getTopPaths(),
    getTopIps(),
    getEventTypes(),
    getDailyStats()
  ]);

  return {
    overview,
    nodes,
    recent_sessions: recentSessions,
    recent_events: recentEvents,
    http_requests: httpRequests,
    credentials,
    top_paths: topPaths,
    top_ips: topIps,
    event_types: eventTypes,
    daily_stats: dailyStats
  };
}

function rowLimit() {
  return envInt("DASHBOARD_ROW_LIMIT", 80, 10, 500);
}

function maskSecret(value) {
  if (!value) return "";
  if (!envBool("DASHBOARD_REDACT_SECRETS", true)) return value;
  if (value.length <= 2) return "*".repeat(value.length);
  if (value.length <= 6) return `${value[0]}${"*".repeat(value.length - 1)}`;
  return `${value.slice(0, 2)}${"*".repeat(Math.min(value.length - 4, 16))}${value.slice(-2)}`;
}

async function getOverview() {
  return queryOne(`
    SELECT
      (SELECT COUNT(*)::int FROM sessions) AS total_sessions,
      (SELECT COUNT(*)::int FROM sessions WHERE started_at >= NOW() - INTERVAL '1 hour') AS sessions_1h,
      (SELECT COUNT(*)::int FROM sessions WHERE started_at >= NOW() - INTERVAL '24 hours') AS sessions_24h,
      (SELECT COUNT(DISTINCT client_ip)::int FROM sessions WHERE started_at >= NOW() - INTERVAL '24 hours') AS unique_ips_24h,
      (SELECT COUNT(*)::int FROM events) AS total_events,
      (SELECT COUNT(*)::int FROM events WHERE occurred_at >= NOW() - INTERVAL '1 hour') AS events_1h,
      (SELECT COUNT(*)::int FROM credentials) AS total_credentials,
      (SELECT COUNT(*)::int FROM http_requests) AS total_http_requests,
      (SELECT COUNT(*)::int FROM honeypot_nodes WHERE active = TRUE) AS active_nodes,
      (SELECT COUNT(*)::int FROM bot_classifications WHERE label = 'bot') AS bot_sessions,
      (SELECT COUNT(*)::int FROM bot_classifications WHERE label = 'human') AS human_sessions,
      (SELECT COUNT(*)::int FROM bot_classifications WHERE label = 'unknown') AS unknown_sessions
  `);
}

async function getNodes() {
  return query(`
    SELECT
      node_id,
      region,
      ip_address::text AS ip_address,
      registered_at,
      last_seen,
      active,
      CASE
        WHEN last_seen >= NOW() - INTERVAL '2 minutes' THEN 'live'
        WHEN last_seen >= NOW() - INTERVAL '15 minutes' THEN 'warm'
        WHEN last_seen IS NULL THEN 'never_seen'
        ELSE 'stale'
      END AS health
    FROM honeypot_nodes
    ORDER BY COALESCE(last_seen, registered_at) DESC
    LIMIT 100
  `);
}

async function getRecentSessions(limit) {
  return query(`
    SELECT
      s.id::text AS id,
      s.node_id,
      s.protocol,
      s.session_ref,
      s.client_ip::text AS client_ip,
      s.client_port,
      s.geo_country,
      s.geo_country_iso,
      s.geo_city,
      s.geo_org,
      s.started_at,
      s.ended_at,
      COALESCE(s.duration_sec, 0) AS duration_sec,
      s.event_count,
      COALESCE(bc.label, 'unclassified') AS classification,
      bc.confidence
    FROM sessions s
    LEFT JOIN bot_classifications bc ON bc.session_id = s.id
    ORDER BY s.started_at DESC NULLS LAST
    LIMIT $1
  `, [limit]);
}

async function getRecentEvents(limit) {
  return query(`
    SELECT id, session_id::text AS session_id, node_id, protocol, event_type,
           occurred_at, raw
    FROM events
    ORDER BY occurred_at DESC
    LIMIT $1
  `, [limit]);
}

async function getHttpRequests(limit) {
  return query(`
    SELECT id, session_id::text AS session_id, node_id, method, path,
           status_code, user_agent, referer, content_type, body_size_bytes,
           occurred_at
    FROM http_requests
    ORDER BY occurred_at DESC
    LIMIT $1
  `, [limit]);
}

async function getCredentials(limit) {
  const rows = await query(`
    SELECT id, session_id::text AS session_id, node_id, protocol, username,
           password, occurred_at, success
    FROM credentials
    ORDER BY occurred_at DESC
    LIMIT $1
  `, [limit]);
  return rows.map((row) => ({...row, password: maskSecret(row.password)}));
}

async function getTopPaths() {
  return query(`
    SELECT path, COUNT(*)::int AS count, MAX(occurred_at) AS last_seen
    FROM http_requests
    WHERE path IS NOT NULL AND path <> ''
    GROUP BY path
    ORDER BY count DESC, last_seen DESC
    LIMIT 12
  `);
}

async function getTopIps() {
  return query(`
    SELECT client_ip::text AS client_ip, COUNT(*)::int AS sessions,
           COALESCE(MAX(geo_country_iso), '') AS country,
           COALESCE(MAX(geo_org), '') AS org,
           MAX(started_at) AS last_seen
    FROM sessions
    WHERE client_ip IS NOT NULL
    GROUP BY client_ip
    ORDER BY sessions DESC, last_seen DESC
    LIMIT 12
  `);
}

async function getEventTypes() {
  return query(`
    SELECT event_type, COUNT(*)::int AS count, MAX(occurred_at) AS last_seen
    FROM events
    GROUP BY event_type
    ORDER BY count DESC, last_seen DESC
    LIMIT 12
  `);
}

async function getDailyStats() {
  try {
    return await query(`
      SELECT day, node_id, protocol, label, session_count, unique_ips,
             unique_countries, avg_duration_sec, total_events
      FROM daily_stats
      ORDER BY day DESC, node_id, protocol, label
      LIMIT 40
    `);
  } catch (_error) {
    return [];
  }
}
