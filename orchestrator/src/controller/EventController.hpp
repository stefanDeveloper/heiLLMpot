#pragma once

#include "../db/DbClient.hpp"
#include "../dto/Dtos.hpp"
#include "oatpp/core/macro/component.hpp"
#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"

#include <algorithm>
#include <cctype>
#include <initializer_list>

#include OATPP_CODEGEN_BEGIN(ApiController)

class EventController : public oatpp::web::server::api::ApiController {
public:
    EventController(OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper))
        : ApiController(objectMapper) {}

    static std::shared_ptr<EventController> createShared(
            OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper)) {
        return std::make_shared<EventController>(objectMapper);
    }

    // ── POST /api/v1/events ──────────────────────────────────────────────────

    ENDPOINT_INFO(ingestEvents) {
        info->summary     = "Ingest a batch of honeypot events";
        info->description =
            "Accepts a batch of log events from a honeypot node. Each event is "
            "upserted into a session, stored as a raw event, and (if applicable) "
            "decomposed into credential or HTTP-request sub-records.\n\n"
            "Requires the `X-Node-Id` header (set automatically by the auth "
            "interceptor after JWT validation) and a `Authorization: Bearer <token>` header.";
        info->tags.push_back("Events");
        info->addConsumes<Object<EventBatchDto>>("application/json");
        info->addResponse<Object<StatusDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<StatusDto>>(Status::CODE_400, "application/json");
        info->addResponse<Object<StatusDto>>(Status::CODE_401, "application/json");
    }
    ENDPOINT("POST", "/api/v1/events", ingestEvents,
             BODY_DTO(Object<EventBatchDto>, body),
             REQUEST(std::shared_ptr<IncomingRequest>, request)) {
        OATPP_COMPONENT(std::shared_ptr<DbClient>, db);
        auto nodeIdHdr = request->getHeader("X-Node-Id");
        if (!nodeIdHdr) {
            return createResponse(Status::CODE_400, "Missing X-Node-Id header");
        }
        std::string nid = nodeIdHdr->c_str();
        db->updateNodeLastSeen(nid);

        if (!body || !body->events) {
            return createResponse(Status::CODE_400, "Empty event batch");
        }

        int ingested = 0;
        int skipped = 0;
        for (auto& ev : *body->events) {
            if (!ev) continue;
            std::string proto      = normalizeProtocol(ev->protocol ? ev->protocol->c_str() : "");
            std::string etype      = normalizeEventType(ev->event_type ? ev->event_type->c_str() : "");
            std::string sessionRef = firstNonEmpty({
                ev->session_ref ? ev->session_ref->c_str() : "",
                ev->session_id ? ev->session_id->c_str() : "",
                ev->connection_id ? ev->connection_id->c_str() : ""
            });
            std::string clientIp   = ev->client_ip   ? ev->client_ip->c_str()   : "";
            int         port       = ev->client_port ? *ev->client_port         : 0;
            std::string ts         = ev->timestamp   ? ev->timestamp->c_str()   : "";

            if (sessionRef.empty()) {
                ++skipped;
                continue;
            }

            auto geo  = db->geoLookup(clientIp);
            auto uuid = db->upsertSession(nid, proto, sessionRef,
                                           clientIp, port, ts, geo);
            if (uuid.empty()) {
                ++skipped;
                continue;
            }

            std::string rawJson = ev->raw_json ? ev->raw_json->c_str() : "{}";
            db->insertEvent(uuid, nid, proto, etype, ts, rawJson);

            if (etype == "credential" || etype == "login") {
                std::string user = ev->username ? ev->username->c_str() : "";
                std::string pass = ev->password ? ev->password->c_str() : "";
                db->insertCredential(uuid, nid, proto, user, pass, ts, false);
            }
            if (etype == "request" && proto == "http") {
                std::string method = ev->method      ? ev->method->c_str()     : "";
                std::string path   = ev->path        ? ev->path->c_str()       : "";
                int         sc     = ev->status_code ? *ev->status_code        : 0;
                std::string ua     = ev->user_agent  ? ev->user_agent->c_str() : "";
                db->insertHttpRequest(uuid, nid, method, path, sc, ua, ts);
            }
            ++ingested;
        }

        auto resp    = StatusDto::createShared();
        resp->status  = "ok";
        resp->message = "Events ingested: " + std::to_string(ingested) +
                        ", skipped: " + std::to_string(skipped);
        resp->code    = 200;
        return createDtoResponse(Status::CODE_200, resp);
    }

    // ── GET /api/v1/sessions ─────────────────────────────────────────────────

    ENDPOINT_INFO(listSessions) {
        info->summary     = "List sessions (paginated)";
        info->description =
            "Returns a paginated list of attack sessions. Optionally filter by "
            "`node_id`. Use `limit` and `offset` for pagination (default: limit=50).";
        info->tags.push_back("Sessions");
        info->queryParams.add<String>("node_id").description  = "Filter by node ID (optional)";
        info->queryParams.add<UInt32>("limit").description    = "Max results (default 50)";
        info->queryParams.add<UInt32>("offset").description   = "Pagination offset (default 0)";
        info->addResponse<List<Object<SessionDto>>>(Status::CODE_200, "application/json");
    }
    ENDPOINT("GET", "/api/v1/sessions", listSessions,
             QUERY(String,  node_id, "node_id"),
             QUERY(UInt32,  limit,   "limit"),
             QUERY(UInt32,  offset,  "offset")) {
        OATPP_COMPONENT(std::shared_ptr<DbClient>, db);
        std::string nid = node_id ? node_id->c_str() : "";
        int lim = limit  ? (int)*limit  : 50;
        int off = offset ? (int)*offset : 0;
        auto sessions = db->listSessions(nid, lim, off);
        auto list = oatpp::List<oatpp::Object<SessionDto>>::createShared();
        for (auto& s : sessions) list->push_back(s);
        return createDtoResponse(Status::CODE_200, list);
    }

private:
    static std::string lower(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        return value;
    }

    static std::string normalizeProtocol(const std::string& value) {
        auto protocol = lower(value);
        if (protocol == "http" || protocol == "ssh") return protocol;
        return "unknown";
    }

    static std::string normalizeEventType(const std::string& value) {
        auto eventType = lower(value);
        if (eventType == "login") return "credential";
        return eventType.empty() ? "unknown" : eventType;
    }

    static std::string firstNonEmpty(std::initializer_list<std::string> values) {
        for (const auto& value : values) {
            if (!value.empty()) return value;
        }
        return "";
    }
};

#include OATPP_CODEGEN_END(ApiController)
