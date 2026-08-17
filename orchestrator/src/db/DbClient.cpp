#include "DbClient.hpp"

#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <arpa/inet.h>

namespace {

void checkResult(PGresult* res, const char* context) {
    if (!res || (PQresultStatus(res) != PGRES_COMMAND_OK &&
                 PQresultStatus(res) != PGRES_TUPLES_OK)) {
        std::string err = res ? PQresultErrorMessage(res) : "null result";
        if (res) PQclear(res);
        throw std::runtime_error(std::string(context) + ": " + err);
    }
}

std::string safeStr(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col)) return "";
    return PQgetvalue(res, row, col);
}

}  // namespace

// ─── Construction / connection ────────────────────────────────────────────────

DbClient::DbClient(const std::shared_ptr<OrchestratorConfig>& cfg) : m_cfg(cfg) {
    connect();

    // Open GeoIP databases
    if (!cfg->geoip_db_path.empty()) {
        int status = MMDB_open(cfg->geoip_db_path.c_str(), MMDB_MODE_MMAP, &m_cityDb);
        m_cityOpen = (status == MMDB_SUCCESS);
    }
    if (!cfg->geoip_asn_path.empty()) {
        int status = MMDB_open(cfg->geoip_asn_path.c_str(), MMDB_MODE_MMAP, &m_asnDb);
        m_asnOpen = (status == MMDB_SUCCESS);
    }
}

DbClient::~DbClient() {
    if (m_conn) PQfinish(m_conn);
    if (m_cityOpen) MMDB_close(&m_cityDb);
    if (m_asnOpen)  MMDB_close(&m_asnDb);
}

void DbClient::connect() {
    std::string connStr =
        "host="     + m_cfg->db_host +
        " port="    + std::to_string(m_cfg->db_port) +
        " dbname="  + m_cfg->db_name +
        " user="    + m_cfg->db_user +
        " password=" + m_cfg->db_password;
    m_conn = PQconnectdb(connStr.c_str());
    if (PQstatus(m_conn) != CONNECTION_OK) {
        std::string err = PQerrorMessage(m_conn);
        PQfinish(m_conn);
        m_conn = nullptr;
        throw std::runtime_error("PostgreSQL connection failed: " + err);
    }
}

void DbClient::ensureConnected() {
    if (!m_conn || PQstatus(m_conn) != CONNECTION_OK) {
        if (m_conn) PQfinish(m_conn);
        connect();
    }
}

PGresult* DbClient::execParams(const char* sql, int nParams,
                                 const char* const* paramValues) {
    ensureConnected();
    PGresult* res = PQexecParams(m_conn, sql, nParams,
                                  nullptr, paramValues, nullptr, nullptr, 0);
    checkResult(res, sql);
    return res;
}

void DbClient::pruneOldSessions(int retentionDays) {
    if (retentionDays <= 0) return;
    ensureConnected();
    std::string sql = "DELETE FROM sessions WHERE started_at < NOW() - INTERVAL '" + std::to_string(retentionDays) + " days'";
    PGresult* res = PQexec(m_conn, sql.c_str());
    checkResult(res, "pruneOldSessions");
    PQclear(res);
}

// ─── GeoIP ───────────────────────────────────────────────────────────────────

GeoInfo DbClient::geoLookup(const std::string& ip) {
    GeoInfo info;
    if (ip.empty()) return info;

    int gaiErr = 0;
    MMDB_lookup_result_s city_res, asn_res;

    if (m_cityOpen) {
        city_res = MMDB_lookup_string(&m_cityDb, ip.c_str(), &gaiErr, nullptr);
        if (gaiErr == 0 && city_res.found_entry) {
            MMDB_entry_data_s data;
            if (MMDB_get_value(&city_res.entry, &data,
                "country", "names", "en", nullptr) == MMDB_SUCCESS && data.has_data) {
                info.country = std::string(data.utf8_string, data.data_size);
            }
            if (MMDB_get_value(&city_res.entry, &data,
                "country", "iso_code", nullptr) == MMDB_SUCCESS && data.has_data) {
                info.country_iso = std::string(data.utf8_string, data.data_size);
            }
            if (MMDB_get_value(&city_res.entry, &data,
                "city", "names", "en", nullptr) == MMDB_SUCCESS && data.has_data) {
                info.city = std::string(data.utf8_string, data.data_size);
            }
        }
    }

    if (m_asnOpen) {
        asn_res = MMDB_lookup_string(&m_asnDb, ip.c_str(), &gaiErr, nullptr);
        if (gaiErr == 0 && asn_res.found_entry) {
            MMDB_entry_data_s data;
            if (MMDB_get_value(&asn_res.entry, &data,
                "autonomous_system_number", nullptr) == MMDB_SUCCESS && data.has_data) {
                info.asn = data.uint32;
            }
            if (MMDB_get_value(&asn_res.entry, &data,
                "autonomous_system_organization", nullptr) == MMDB_SUCCESS && data.has_data) {
                info.org = std::string(data.utf8_string, data.data_size);
            }
        }
    }
    return info;
}

// ─── Node management ─────────────────────────────────────────────────────────

bool DbClient::nodeExists(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char* params[] = {node_id.c_str()};
    auto* res = execParams(
        "SELECT 1 FROM honeypot_nodes WHERE node_id=$1 LIMIT 1", 1, params);
    bool exists = PQntuples(res) > 0;
    PQclear(res);
    return exists;
}

void DbClient::registerNode(const std::string& node_id, const std::string& region,
                              const std::string& ip_address,
                              const std::string& api_key_hash) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char* params[] = {node_id.c_str(), region.c_str(),
                             ip_address.c_str(), api_key_hash.c_str()};
    auto* res = execParams(
        "INSERT INTO honeypot_nodes(node_id,region,ip_address,api_key_hash) "
        "VALUES($1,$2,NULLIF($3,'')::inet,$4) "
        "ON CONFLICT(node_id) DO UPDATE SET region=$2, ip_address=NULLIF($3,'')::inet, "
        "last_seen=NOW(), active=TRUE",
        4, params);
    PQclear(res);
}

void DbClient::updateNodeLastSeen(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char* params[] = {node_id.c_str()};
    auto* res = execParams(
        "UPDATE honeypot_nodes SET last_seen=NOW() WHERE node_id=$1", 1, params);
    PQclear(res);
}

std::vector<oatpp::Object<NodeDto>> DbClient::listNodes() {
    std::lock_guard<std::mutex> lock(m_mutex);
    ensureConnected();
    auto* res = PQexec(m_conn,
        "SELECT id,node_id,region,ip_address::text,registered_at,last_seen,active "
        "FROM honeypot_nodes ORDER BY registered_at DESC");
    checkResult(res, "listNodes");

    std::vector<oatpp::Object<NodeDto>> nodes;
    for (int i = 0; i < PQntuples(res); ++i) {
        auto dto          = NodeDto::createShared();
        dto->id           = safeStr(res, i, 0);
        dto->node_id      = safeStr(res, i, 1);
        dto->region       = safeStr(res, i, 2);
        dto->ip_address   = safeStr(res, i, 3);
        dto->registered_at = safeStr(res, i, 4);
        dto->last_seen    = safeStr(res, i, 5);
        dto->active       = std::string(PQgetvalue(res, i, 6)) == "t";
        nodes.push_back(dto);
    }
    PQclear(res);
    return nodes;
}

// ─── Session management ───────────────────────────────────────────────────────

std::string DbClient::upsertSession(const std::string& node_id,
                                     const std::string& protocol,
                                     const std::string& session_ref,
                                     const std::string& client_ip,
                                     int                client_port,
                                     const std::string& started_at,
                                     const GeoInfo&     geo) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string port_str  = std::to_string(client_port);
    std::string asn_str   = std::to_string(geo.asn);
    const char* params[] = {
        node_id.c_str(), protocol.c_str(), session_ref.c_str(),
        client_ip.c_str(), port_str.c_str(), started_at.c_str(),
        geo.country.c_str(), geo.country_iso.c_str(), geo.city.c_str(),
        asn_str.c_str(), geo.org.c_str()
    };
    auto* res = execParams(
        "INSERT INTO sessions"
        "  (node_id,protocol,session_ref,client_ip,client_port,started_at,"
        "   geo_country,geo_country_iso,geo_city,geo_asn,geo_org)"
        " VALUES($1,$2,$3,NULLIF($4,'')::inet,$5::int,"
        "        COALESCE(NULLIF($6,'')::timestamptz, NOW()),"
        "        $7,$8,$9,$10::int,$11)"
        " ON CONFLICT(node_id,session_ref) DO NOTHING"
        " RETURNING id",
        11, params);

    std::string uuid;
    if (PQntuples(res) > 0) {
        uuid = PQgetvalue(res, 0, 0);
    }
    PQclear(res);

    if (uuid.empty()) {
        // Session already existed – fetch the UUID
        const char* p2[] = {node_id.c_str(), session_ref.c_str()};
        auto* r2 = execParams(
            "SELECT id FROM sessions WHERE node_id=$1 AND session_ref=$2", 2, p2);
        if (PQntuples(r2) > 0) uuid = PQgetvalue(r2, 0, 0);
        PQclear(r2);
    }
    return uuid;
}

oatpp::Object<SessionDto> DbClient::getSession(const std::string& session_uuid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char* params[] = {session_uuid.c_str()};
    auto* res = execParams(
        "SELECT s.id, s.node_id, s.protocol, s.client_ip::text, s.client_port, "
        "  s.geo_country, s.geo_city, s.geo_org, s.started_at, s.ended_at, "
        "  s.duration_sec, s.event_count, bc.label, bc.confidence "
        "FROM sessions s "
        "LEFT JOIN bot_classifications bc ON bc.session_id=s.id "
        "WHERE s.id=$1::uuid",
        1, params);

    if (PQntuples(res) == 0) { PQclear(res); return nullptr; }

    auto dto           = SessionDto::createShared();
    dto->id            = safeStr(res, 0, 0);
    dto->node_id       = safeStr(res, 0, 1);
    dto->protocol      = safeStr(res, 0, 2);
    dto->client_ip     = safeStr(res, 0, 3);
    auto port_s        = safeStr(res, 0, 4);
    dto->client_port   = port_s.empty() ? 0 : std::stoi(port_s);
    dto->geo_country   = safeStr(res, 0, 5);
    dto->geo_city      = safeStr(res, 0, 6);
    dto->geo_org       = safeStr(res, 0, 7);
    dto->started_at    = safeStr(res, 0, 8);
    dto->ended_at      = safeStr(res, 0, 9);
    auto dur_s         = safeStr(res, 0, 10);
    dto->duration_sec  = dur_s.empty() ? 0.0 : std::stod(dur_s);
    auto cnt_s         = safeStr(res, 0, 11);
    dto->event_count   = cnt_s.empty() ? 0 : std::stoi(cnt_s);
    dto->classification = safeStr(res, 0, 12);
    auto conf_s        = safeStr(res, 0, 13);
    dto->confidence    = conf_s.empty() ? 0.0 : std::stod(conf_s);
    PQclear(res);
    return dto;
}

std::vector<oatpp::Object<SessionDto>>
DbClient::listSessions(const std::string& node_id, int limit, int offset) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string lim = std::to_string(limit);
    std::string off = std::to_string(offset);

    bool filter = !node_id.empty();
    std::string sql =
        "SELECT s.id, s.node_id, s.protocol, s.client_ip::text, s.client_port, "
        "  s.geo_country, s.geo_city, s.geo_org, s.started_at, s.ended_at, "
        "  s.duration_sec, s.event_count, bc.label, bc.confidence "
        "FROM sessions s "
        "LEFT JOIN bot_classifications bc ON bc.session_id=s.id ";
    if (filter) sql += "WHERE s.node_id=$1 ";
    sql += "ORDER BY s.started_at DESC LIMIT " + lim + " OFFSET " + off;

    PGresult* res;
    if (filter) {
        const char* params[] = {node_id.c_str()};
        ensureConnected();
        res = PQexecParams(m_conn, sql.c_str(), 1,
                            nullptr, params, nullptr, nullptr, 0);
    } else {
        ensureConnected();
        res = PQexec(m_conn, sql.c_str());
    }
    checkResult(res, "listSessions");

    std::vector<oatpp::Object<SessionDto>> result;
    for (int i = 0; i < PQntuples(res); ++i) {
        auto dto           = SessionDto::createShared();
        dto->id            = safeStr(res, i, 0);
        dto->node_id       = safeStr(res, i, 1);
        dto->protocol      = safeStr(res, i, 2);
        dto->client_ip     = safeStr(res, i, 3);
        auto ps            = safeStr(res, i, 4);
        dto->client_port   = ps.empty() ? 0 : std::stoi(ps);
        dto->geo_country   = safeStr(res, i, 5);
        dto->geo_city      = safeStr(res, i, 6);
        dto->geo_org       = safeStr(res, i, 7);
        dto->started_at    = safeStr(res, i, 8);
        dto->ended_at      = safeStr(res, i, 9);
        auto ds            = safeStr(res, i, 10);
        dto->duration_sec  = ds.empty() ? 0.0 : std::stod(ds);
        auto cs            = safeStr(res, i, 11);
        dto->event_count   = cs.empty() ? 0 : std::stoi(cs);
        dto->classification = safeStr(res, i, 12);
        auto cf            = safeStr(res, i, 13);
        dto->confidence    = cf.empty() ? 0.0 : std::stod(cf);
        result.push_back(dto);
    }
    PQclear(res);
    return result;
}

// ─── Event ingestion ──────────────────────────────────────────────────────────

void DbClient::insertEvent(const std::string& session_uuid,
                             const std::string& node_id,
                             const std::string& protocol,
                             const std::string& event_type,
                             const std::string& occurred_at,
                             const std::string& raw_json) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char* params[] = {
        session_uuid.c_str(), node_id.c_str(), protocol.c_str(),
        event_type.c_str(), occurred_at.c_str(), raw_json.c_str()
    };
    auto* res = execParams(
        "INSERT INTO events(session_id,node_id,protocol,event_type,occurred_at,raw) "
        "VALUES($1::uuid,$2,$3,$4,COALESCE(NULLIF($5,'')::timestamptz, NOW()),$6::jsonb) "
        "ON CONFLICT DO NOTHING",
        6, params);
    PQclear(res);

    // Increment event_count on session
    const char* p2[] = {session_uuid.c_str()};
    auto* r2 = execParams(
        "UPDATE sessions SET event_count=event_count+1 WHERE id=$1::uuid", 1, p2);
    PQclear(r2);
}

void DbClient::insertCredential(const std::string& session_uuid,
                                  const std::string& node_id,
                                  const std::string& protocol,
                                  const std::string& username,
                                  const std::string& password,
                                  const std::string& occurred_at,
                                  bool success) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char* s = success ? "true" : "false";
    const char* params[] = {
        session_uuid.c_str(), node_id.c_str(), protocol.c_str(),
        username.c_str(), password.c_str(), occurred_at.c_str(), s
    };
    auto* res = execParams(
        "INSERT INTO credentials(session_id,node_id,protocol,username,password,occurred_at,success) "
        "VALUES($1::uuid,$2,$3,$4,$5,COALESCE(NULLIF($6,'')::timestamptz, NOW()),$7::boolean)",
        7, params);
    PQclear(res);
}

void DbClient::insertHttpRequest(const std::string& session_uuid,
                                   const std::string& node_id,
                                   const std::string& method,
                                   const std::string& path,
                                   int status_code,
                                   const std::string& user_agent,
                                   const std::string& occurred_at) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string sc = std::to_string(status_code);
    const char* params[] = {
        session_uuid.c_str(), node_id.c_str(), method.c_str(),
        path.c_str(), sc.c_str(), user_agent.c_str(), occurred_at.c_str()
    };
    auto* res = execParams(
        "INSERT INTO http_requests(session_id,node_id,method,path,status_code,user_agent,occurred_at) "
        "VALUES($1::uuid,$2,$3,$4,$5::int,$6,COALESCE(NULLIF($7,'')::timestamptz, NOW()))",
        7, params);
    PQclear(res);
}

void DbClient::insertEventsBatch(const std::vector<ScanEventData>& events) {
    if (events.empty()) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    ensureConnected();
    PGresult* res = PQexec(m_conn, "BEGIN");
    PQclear(res);
    try {
        for (const auto& ev : events) {
            const char* e_params[] = {
                ev.session_uuid.c_str(), ev.node_id.c_str(), ev.protocol.c_str(),
                ev.event_type.c_str(), ev.occurred_at.c_str(), ev.raw_json.c_str()
            };
            res = PQexecParams(m_conn, 
                "INSERT INTO events(session_id,node_id,protocol,event_type,occurred_at,raw) "
                "VALUES($1::uuid,$2,$3,$4,COALESCE(NULLIF($5,'')::timestamptz, NOW()),$6::jsonb) "
                "ON CONFLICT DO NOTHING", 6, nullptr, e_params, nullptr, nullptr, 0);
            if (PQresultStatus(res) != PGRES_COMMAND_OK) throw std::runtime_error("insert event failed");
            PQclear(res);

            std::string port_str = std::to_string(ev.status_code);
            const char* h_params[] = {
                ev.session_uuid.c_str(), ev.node_id.c_str(), ev.method.c_str(),
                ev.path.c_str(), port_str.c_str(), ev.user_agent.c_str(), ev.occurred_at.c_str()
            };
            res = PQexecParams(m_conn,
                "INSERT INTO http_requests(session_id,node_id,method,path,status_code,user_agent,occurred_at) "
                "VALUES($1::uuid,$2,$3,$4,$5::int,$6,COALESCE(NULLIF($7,'')::timestamptz, NOW()))",
                7, nullptr, h_params, nullptr, nullptr, 0);
            if (PQresultStatus(res) != PGRES_COMMAND_OK) throw std::runtime_error("insert http_request failed");
            PQclear(res);
        }
        res = PQexec(m_conn, "COMMIT");
        PQclear(res);
    } catch (...) {
        res = PQexec(m_conn, "ROLLBACK");
        PQclear(res);
    }
}

// ─── Classification ───────────────────────────────────────────────────────────

void DbClient::upsertClassification(const std::string& session_uuid,
                                      const std::string& label,
                                      double             confidence,
                                      const std::string& method,
                                      const std::string& features_json,
                                      const std::vector<std::string>& triggered_rules) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string conf = std::to_string(confidence);

    // Build triggered_rules as PostgreSQL array literal
    std::string rules = "{";
    for (size_t i = 0; i < triggered_rules.size(); ++i) {
        if (i) rules += ",";
        rules += "\"" + triggered_rules[i] + "\"";
    }
    rules += "}";

    const char* params[] = {
        session_uuid.c_str(), label.c_str(), conf.c_str(),
        method.c_str(), features_json.c_str(), rules.c_str()
    };
    auto* res = execParams(
        "INSERT INTO bot_classifications(session_id,label,confidence,method,features,triggered_rules) "
        "VALUES($1::uuid,$2,$3::float8,$4,$5::jsonb,$6::text[]) "
        "ON CONFLICT(session_id) DO UPDATE "
        "SET label=$2, confidence=$3::float8, method=$4, features=$5::jsonb, "
        "    triggered_rules=$6::text[], classified_at=NOW()",
        6, params);
    PQclear(res);
}

std::vector<std::string> DbClient::getUnclassifiedSessionIds(int limit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string lim = std::to_string(limit);
    std::string sql =
        "SELECT s.id FROM sessions s "
        "LEFT JOIN bot_classifications bc ON bc.session_id=s.id "
        "WHERE bc.session_id IS NULL AND s.event_count>0 "
        "ORDER BY s.started_at DESC LIMIT " + lim;
    ensureConnected();
    auto* res = PQexec(m_conn, sql.c_str());
    checkResult(res, "getUnclassifiedSessionIds");
    std::vector<std::string> ids;
    for (int i = 0; i < PQntuples(res); ++i)
        ids.push_back(PQgetvalue(res, i, 0));
    PQclear(res);
    return ids;
}

std::vector<std::string> DbClient::getSessionEventJsons(
    const std::string& session_uuid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    const char* params[] = {session_uuid.c_str()};
    auto* res = execParams(
        "SELECT raw FROM events WHERE session_id=$1::uuid ORDER BY occurred_at",
        1, params);
    std::vector<std::string> jsons;
    for (int i = 0; i < PQntuples(res); ++i)
        jsons.push_back(PQgetvalue(res, i, 0));
    PQclear(res);
    return jsons;
}

// ─── Statistics ───────────────────────────────────────────────────────────────

oatpp::Object<StatsResponseDto> DbClient::getStats(const std::string& from_date,
                                                     const std::string& to_date) {
    std::lock_guard<std::mutex> lock(m_mutex);
    ensureConnected();

    auto* refresh = PQexec(m_conn, "REFRESH MATERIALIZED VIEW daily_stats");
    checkResult(refresh, "refreshDailyStats");
    PQclear(refresh);

    const char* params[] = {from_date.c_str(), to_date.c_str()};
    auto* res = execParams(
        "SELECT day::text, node_id, protocol, label, "
        "  session_count, unique_ips, unique_countries, avg_duration_sec, total_events "
        "FROM daily_stats "
        "WHERE day >= $1::date AND day <= $2::date "
        "ORDER BY day DESC, node_id",
        2, params);

    auto dto = StatsResponseDto::createShared();
    dto->daily = oatpp::List<oatpp::Object<DailyStatDto>>::createShared();
    int64_t bots=0, humans=0, unk=0, total=0;

    for (int i = 0; i < PQntuples(res); ++i) {
        auto row         = DailyStatDto::createShared();
        row->day         = safeStr(res, i, 0);
        row->node_id     = safeStr(res, i, 1);
        row->protocol    = safeStr(res, i, 2);
        row->label       = safeStr(res, i, 3);
        auto sc_s        = safeStr(res, i, 4);
        row->session_count = sc_s.empty() ? 0 : std::stoll(sc_s);
        auto ui_s        = safeStr(res, i, 5);
        row->unique_ips  = ui_s.empty() ? 0 : std::stoll(ui_s);
        auto uc_s        = safeStr(res, i, 6);
        row->unique_countries = uc_s.empty() ? 0 : std::stoll(uc_s);
        auto ad_s        = safeStr(res, i, 7);
        row->avg_duration_sec = ad_s.empty() ? 0.0 : std::stod(ad_s);
        auto te_s        = safeStr(res, i, 8);
        row->total_events = te_s.empty() ? 0 : std::stoll(te_s);
        dto->daily->push_back(row);

        total += row->session_count;
        auto lbl = row->label.getValue("");
        if (lbl == "bot")    bots   += row->session_count;
        else if (lbl == "human") humans += row->session_count;
        else                 unk    += row->session_count;
    }
    PQclear(res);

    dto->total_sessions = total;
    dto->total_bots     = bots;
    dto->total_humans   = humans;
    dto->total_unknown  = unk;

    // Count active nodes
    auto* r2 = PQexec(m_conn,
        "SELECT COUNT(*) FROM honeypot_nodes WHERE active=TRUE");
    checkResult(r2, "activeNodes");
    dto->active_nodes = PQntuples(r2) > 0 ?
        std::stoll(PQgetvalue(r2, 0, 0)) : 0;
    PQclear(r2);

    return dto;
}

// ─── Schema migration ─────────────────────────────────────────────────────────

void DbClient::runMigration(const std::string& sql_file_path) {
    std::ifstream f(sql_file_path);
    if (!f) throw std::runtime_error("Cannot open migration file: " + sql_file_path);
    std::ostringstream buf;
    buf << f.rdbuf();
    std::string sql = buf.str();

    std::lock_guard<std::mutex> lock(m_mutex);
    ensureConnected();
    auto* res = PQexec(m_conn, sql.c_str());
    checkResult(res, "runMigration");
    PQclear(res);
}

// ─── Size-based Pruning ───────────────────────────────────────────────────────

void DbClient::pruneBySize(int max_db_size_gb) {
    if (max_db_size_gb <= 0) return;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    ensureConnected();

    // 1. Get database size in bytes
    const char* size_sql = "SELECT pg_database_size(current_database());";
    auto* res = PQexec(m_conn, size_sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        std::cerr << "[DbClient] Failed to check database size: " << PQerrorMessage(m_conn) << "\n";
        PQclear(res);
        return;
    }
    
    long long db_size_bytes = std::stoll(PQgetvalue(res, 0, 0));
    PQclear(res);

    long long max_size_bytes = static_cast<long long>(max_db_size_gb) * 1024 * 1024 * 1024;
    
    if (db_size_bytes > max_size_bytes) {
        std::cout << "[DbClient] DB Size (" << db_size_bytes << " bytes) exceeds max size (" 
                  << max_size_bytes << " bytes). Pruning non-critical scan events...\n";

        // Delete scan events from sessions that do NOT have a credential or an attack/malicious label.
        // We delete from `events` and `http_requests` to free up space.
        // We delete in batches (e.g., sessions older than X, or just oldest sessions).
        const char* prune_sql = R"(
            WITH sessions_to_prune AS (
                SELECT session_uuid FROM sessions s
                WHERE NOT EXISTS (
                    SELECT 1 FROM credentials c WHERE c.session_uuid = s.session_uuid
                )
                AND NOT EXISTS (
                    SELECT 1 FROM session_classifications cl 
                    WHERE cl.session_uuid = s.session_uuid 
                      AND (cl.label = 'malicious_login' OR cl.label = 'attack')
                )
                ORDER BY s.started_at ASC
                LIMIT 10000
            ),
            deleted_events AS (
                DELETE FROM events 
                WHERE session_uuid IN (SELECT session_uuid FROM sessions_to_prune)
                RETURNING session_uuid
            )
            DELETE FROM http_requests 
            WHERE session_uuid IN (SELECT session_uuid FROM sessions_to_prune);
        )";
        
        auto* prune_res = PQexec(m_conn, prune_sql);
        if (PQresultStatus(prune_res) != PGRES_COMMAND_OK) {
            std::cerr << "[DbClient] Pruning failed: " << PQerrorMessage(m_conn) << "\n";
        } else {
            std::cout << "[DbClient] Successfully pruned oldest non-critical events.\n";
        }
        PQclear(prune_res);
    }
}
