import pg from "pg";

import {envInt} from "./env.js";

const {Pool} = pg;

function createPool() {
  return new Pool({
    host: process.env.DB_HOST || "postgres",
    port: envInt("DB_PORT", 5432, 1, 65535),
    database: process.env.DB_NAME || "honeypot_db",
    user: process.env.DB_USER || "orchestrator_app",
    password: process.env.DB_PASSWORD || "changeme",
    connectionTimeoutMillis: 3000,
    max: envInt("DASHBOARD_DB_POOL_SIZE", 6, 1, 50)
  });
}

export function getPool() {
  if (!globalThis.__heillmpotDashboardPool) {
    globalThis.__heillmpotDashboardPool = createPool();
  }
  return globalThis.__heillmpotDashboardPool;
}

export async function query(sql, params = []) {
  const result = await getPool().query(sql, params);
  return result.rows;
}

export async function queryOne(sql, params = []) {
  const rows = await query(sql, params);
  return rows[0] || {};
}
