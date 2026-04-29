#pragma once

#include "../db/DbClient.hpp"
#include "../dto/Dtos.hpp"
#include "oatpp/core/macro/component.hpp"
#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"

#include OATPP_CODEGEN_BEGIN(ApiController)

class SessionController : public oatpp::web::server::api::ApiController {
public:
    SessionController(OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper))
        : ApiController(objectMapper) {}

    static std::shared_ptr<SessionController> createShared(
            OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper)) {
        return std::make_shared<SessionController>(objectMapper);
    }

    // ── GET /api/v1/sessions/{id} ────────────────────────────────────────────

    ENDPOINT_INFO(getSession) {
        info->summary     = "Get session details";
        info->description =
            "Retrieve a single session by its UUID, including GeoIP enrichment "
            "and the current bot/human classification result.";
        info->tags.push_back("Sessions");
        info->pathParams.add<String>("id").description = "Session UUID";
        info->addResponse<Object<SessionDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<StatusDto>>(Status::CODE_404, "application/json");
    }
    ENDPOINT("GET", "/api/v1/sessions/{id}", getSession,
             PATH(String, id)) {
        OATPP_COMPONENT(std::shared_ptr<DbClient>, db);
        auto session = db->getSession(id->c_str());
        if (!session) {
            auto err    = StatusDto::createShared();
            err->status  = "not_found";
            err->message = "Session not found";
            err->code    = 404;
            return createDtoResponse(Status::CODE_404, err);
        }
        return createDtoResponse(Status::CODE_200, session);
    }

    // ── PUT /api/v1/sessions/{id}/label ──────────────────────────────────────

    ENDPOINT_INFO(overrideLabel) {
        info->summary     = "Override session classification label";
        info->description =
            "Manually set the bot/human label for a session (researcher override). "
            "Accepted values for `human_override`: `\"bot\"` or `\"human\"`.";
        info->tags.push_back("Sessions");
        info->pathParams.add<String>("id").description = "Session UUID";
        info->addConsumes<Object<ClassificationDto>>("application/json");
        info->addResponse<Object<StatusDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<StatusDto>>(Status::CODE_400, "application/json");
    }
    ENDPOINT("PUT", "/api/v1/sessions/{id}/label", overrideLabel,
             PATH(String, id),
             BODY_DTO(Object<ClassificationDto>, body)) {
        OATPP_COMPONENT(std::shared_ptr<DbClient>, db);
        if (!body || !body->human_override) {
            return createResponse(Status::CODE_400, "label required");
        }
        std::string lbl = body->human_override->c_str();
        if (lbl != "bot" && lbl != "human") {
            return createResponse(Status::CODE_400, "label must be 'bot' or 'human'");
        }
        db->upsertClassification(id->c_str(), lbl, 1.0, "human_override", "{}", {});

        auto resp    = StatusDto::createShared();
        resp->status  = "ok";
        resp->message = "Label updated";
        resp->code    = 200;
        return createDtoResponse(Status::CODE_200, resp);
    }
};

#include OATPP_CODEGEN_END(ApiController)
