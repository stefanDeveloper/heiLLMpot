#pragma once

#include <libpq-fe.h>
#include <maxminddb.h>

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "dto/Dtos.hpp"
#include "../ConfigComponent.hpp"

struct GeoInfo {
    std::string country;
    std::string country_iso;
    std::string city;
    int         asn  = 0;
    std::string org;
};

struct ScanEventData {
    std::string session_uuid;
    std::string node_id;
    std::string protocol;
    std::string event_type;
    std::string occurred_at;
    std::string raw_json;
    std::string method;
    std::string path;
    int status_code = 0;
    std::string user_agent;
};

/// PostgreSQL database client.
/// Wraps libpq with RAII connection management.
class DbClient {
public:
    explicit DbClient(const std::shared_ptr<OrchestratorConfig>& cfg);
    ~DbClient();

    // ── Node management ──────────────────────────────────────────────────────
    bool        nodeExists(const std::string& node_id);
    void        registerNode(const std::string& node_id,
                              const std::string& region,
                              const std::string& ip_address,
                              const std::string& api_key_hash);
    void        updateNodeLastSeen(const std::string& node_id);
    std::vector<oatpp::Object<NodeDto>> listNodes();

    // ── Session management ───────────────────────────────────────────────────
    /// Get or create a session row; returns the UUID.
    std::string upsertSession(const std::string& node_id,
                               const std::string& protocol,
                               const std::string& session_ref,
                               const std::string& client_ip,
                               int                client_port,
                               const std::string& started_at,
                               const GeoInfo&     geo);
    void        closeSession(const std::string& session_uuid,
                              const std::string& ended_at,
                              double             duration_sec);
    oatpp::Object<SessionDto> getSession(const std::string& session_uuid);
    std::vector<oatpp::Object<SessionDto>>
        listSessions(const std::string& node_id, int limit, int offset);

    // ── Event ingestion ──────────────────────────────────────────────────────
    void insertEvent(const std::string& session_uuid,
                      const std::string& node_id,
                      const std::string& protocol,
                      const std::string& event_type,
                      const std::string& occurred_at,
                      const std::string& raw_json);

    void insertCredential(const std::string& session_uuid,
                           const std::string& node_id,
                           const std::string& protocol,
                           const std::string& username,
                           const std::string& password,
                           const std::string& occurred_at,
                           bool               success);

    void insertHttpRequest(const std::string& session_uuid,
                            const std::string& node_id,
                            const std::string& method,
                            const std::string& path,
                            int                status_code,
                            const std::string& user_agent,
                            const std::string& occurred_at);

    void insertEventsBatch(const std::vector<ScanEventData>& events);

    // ── Classification ───────────────────────────────────────────────────────
    void upsertClassification(const std::string& session_uuid,
                               const std::string& label,
                               double             confidence,
                               const std::string& method,
                               const std::string& features_json,
                               const std::vector<std::string>& triggered_rules);

    /// Fetch sessions that have no classification entry yet.
    std::vector<std::string> getUnclassifiedSessionIds(int limit = 100);

    /// Fetch all events for a session (for feature extraction).
    std::vector<std::string> getSessionEventJsons(const std::string& session_uuid);

    // ── Statistics ───────────────────────────────────────────────────────────
    oatpp::Object<StatsResponseDto> getStats(const std::string& from_date,
                                               const std::string& to_date);
    void        pruneOldSessions(int retentionDays);
    void        pruneBySize(int max_db_size_gb);

    // ── GeoIP ────────────────────────────────────────────────────────────────
    GeoInfo geoLookup(const std::string& ip);

    // ── Schema migrations ────────────────────────────────────────────────────
    void runMigration(const std::string& sql_file_path);

private:
    std::shared_ptr<OrchestratorConfig> m_cfg;
    PGconn*   m_conn     = nullptr;
    MMDB_s    m_cityDb   = {};
    MMDB_s    m_asnDb    = {};
    bool      m_cityOpen = false;
    bool      m_asnOpen  = false;
    std::mutex m_mutex;

    void connect();
    void ensureConnected();

    /// Execute a parameterised query; throws on error.
    PGresult* execParams(const char* sql,
                          int         nParams,
                          const char* const* paramValues);

    std::string pgEscape(const std::string& s) const;
};
