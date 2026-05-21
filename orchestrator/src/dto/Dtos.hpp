#pragma once
#include "oatpp/core/Types.hpp"
#include "oatpp/core/macro/codegen.hpp"

// ─── DTO definitions ─────────────────────────────────────────────────────────
#include OATPP_CODEGEN_BEGIN(DTO)

// ---------------------------------------------------------------------------
// A single honeypot log event received from a node
// ---------------------------------------------------------------------------
class EventDto : public oatpp::DTO {
    DTO_INIT(EventDto, DTO)

    DTO_FIELD(String, node_id);           // "node-eu-west-1"
    DTO_FIELD(String, protocol);          // "http" | "ssh"
    DTO_FIELD(String, event_type);        // "request" | "credential" | "command" | …
    DTO_FIELD(String, timestamp);         // ISO-8601 from the honeypot logger
    DTO_FIELD(String, session_ref);       // session_id / connection_id
    DTO_FIELD(String, session_id);        // legacy/local HTTP field
    DTO_FIELD(String, connection_id);     // legacy/local SSH field
    DTO_FIELD(String, client_ip);
    DTO_FIELD(Int32,  client_port);

    // protocol-specific fields forwarded as sub-objects
    DTO_FIELD(String, username);
    DTO_FIELD(String, password);
    DTO_FIELD(String, path);
    DTO_FIELD(String, method);
    DTO_FIELD(Int32,  status_code);
    DTO_FIELD(String, user_agent);
    DTO_FIELD(String, command);
    DTO_FIELD(String, raw_json);          // full original JSON (stringified)
};

// Batch ingestion request
class EventBatchDto : public oatpp::DTO {
    DTO_INIT(EventBatchDto, DTO)
    DTO_FIELD(List<Object<EventDto>>, events);
};

// ---------------------------------------------------------------------------
// Honeypot node registration / status
// ---------------------------------------------------------------------------
class NodeDto : public oatpp::DTO {
    DTO_INIT(NodeDto, DTO)

    DTO_FIELD(String, id);
    DTO_FIELD(String, node_id);
    DTO_FIELD(String, region);
    DTO_FIELD(String, ip_address);
    DTO_FIELD(String, registered_at);
    DTO_FIELD(String, last_seen);
    DTO_FIELD(String, config_hash);
    DTO_FIELD(Boolean, active);
};

class NodeRegisterDto : public oatpp::DTO {
    DTO_INIT(NodeRegisterDto, DTO)
    DTO_FIELD(String, node_id,    "node_id");
    DTO_FIELD(String, region,     "region");
    DTO_FIELD(String, ip_address, "ip_address");
    DTO_FIELD(String, api_key,    "api_key");   // plain-text, stored as hash
};

class NodeRegisterResponseDto : public oatpp::DTO {
    DTO_INIT(NodeRegisterResponseDto, DTO)
    DTO_FIELD(String, node_id);
    DTO_FIELD(String, jwt_token);   // JWT for subsequent requests
    DTO_FIELD(String, message);
};

// ---------------------------------------------------------------------------
// Session detail
// ---------------------------------------------------------------------------
class SessionDto : public oatpp::DTO {
    DTO_INIT(SessionDto, DTO)

    DTO_FIELD(String, id);
    DTO_FIELD(String, node_id);
    DTO_FIELD(String, protocol);
    DTO_FIELD(String, client_ip);
    DTO_FIELD(Int32,  client_port);
    DTO_FIELD(String, geo_country);
    DTO_FIELD(String, geo_city);
    DTO_FIELD(String, geo_org);
    DTO_FIELD(String, started_at);
    DTO_FIELD(String, ended_at);
    DTO_FIELD(Float64, duration_sec);
    DTO_FIELD(Int32,  event_count);
    DTO_FIELD(String, classification);  // 'bot'|'human'|'unknown'
    DTO_FIELD(Float64, confidence);
};

// ---------------------------------------------------------------------------
// Bot/Human classification
// ---------------------------------------------------------------------------
class ClassificationDto : public oatpp::DTO {
    DTO_INIT(ClassificationDto, DTO)

    DTO_FIELD(String, session_id);
    DTO_FIELD(String, label);             // "bot"|"human"|"unknown"
    DTO_FIELD(Float64, confidence);
    DTO_FIELD(String, method);            // "rules"|"isolation_forest"|"custom_model"
    DTO_FIELD(String, features_json);     // JSON object with feature vector
    DTO_FIELD(List<String>, triggered_rules);
    DTO_FIELD(String, classified_at);
    DTO_FIELD(String, human_override);    // researcher's manual label
};

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------
class DailyStatDto : public oatpp::DTO {
    DTO_INIT(DailyStatDto, DTO)
    DTO_FIELD(String, day);
    DTO_FIELD(String, node_id);
    DTO_FIELD(String, protocol);
    DTO_FIELD(String, label);
    DTO_FIELD(Int64,  session_count);
    DTO_FIELD(Int64,  unique_ips);
    DTO_FIELD(Int64,  unique_countries);
    DTO_FIELD(Float64, avg_duration_sec);
    DTO_FIELD(Int64,  total_events);
};

class StatsResponseDto : public oatpp::DTO {
    DTO_INIT(StatsResponseDto, DTO)
    DTO_FIELD(List<Object<DailyStatDto>>, daily);
    DTO_FIELD(Int64, total_sessions);
    DTO_FIELD(Int64, total_bots);
    DTO_FIELD(Int64, total_humans);
    DTO_FIELD(Int64, total_unknown);
    DTO_FIELD(Int64, active_nodes);
};

// Generic response wrapper
class StatusDto : public oatpp::DTO {
    DTO_INIT(StatusDto, DTO)
    DTO_FIELD(String, status);
    DTO_FIELD(String, message);
    DTO_FIELD(Int32,  code);
};

#include OATPP_CODEGEN_END(DTO)
