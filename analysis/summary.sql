-- Quick analyst notebook for the orchestrator PostgreSQL database.
-- Run with:
--   docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" < analysis/summary.sql

REFRESH MATERIALIZED VIEW daily_stats;

\echo '== Overall session counts =='
SELECT
  COUNT(*) AS sessions,
  COUNT(DISTINCT client_ip) AS unique_ips,
  COUNT(DISTINCT node_id) AS nodes,
  MIN(started_at) AS first_seen,
  MAX(started_at) AS last_seen
FROM sessions;

\echo '== Daily stats =='
SELECT day, node_id, protocol, label, session_count, unique_ips, total_events
FROM daily_stats
ORDER BY day DESC, node_id, protocol, label
LIMIT 100;

\echo '== Top source IPs =='
SELECT client_ip, geo_country_iso, geo_org, COUNT(*) AS sessions, SUM(event_count) AS events
FROM sessions
GROUP BY client_ip, geo_country_iso, geo_org
ORDER BY sessions DESC, events DESC
LIMIT 25;

\echo '== Top requested HTTP paths =='
SELECT path, method, status_code, COUNT(*) AS hits
FROM http_requests
GROUP BY path, method, status_code
ORDER BY hits DESC
LIMIT 25;

\echo '== Top user agents =='
SELECT user_agent, COUNT(*) AS hits
FROM http_requests
WHERE user_agent IS NOT NULL AND user_agent <> ''
GROUP BY user_agent
ORDER BY hits DESC
LIMIT 25;

\echo '== Credential attempts =='
SELECT protocol, username, password, COUNT(*) AS attempts
FROM credentials
GROUP BY protocol, username, password
ORDER BY attempts DESC
LIMIT 25;

\echo '== Recent raw command events =='
SELECT occurred_at, node_id, raw->'data'->>'client_ip' AS client_ip,
       raw->'data'->>'command' AS command
FROM events
WHERE event_type = 'command'
ORDER BY occurred_at DESC
LIMIT 25;
