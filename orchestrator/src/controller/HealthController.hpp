#pragma once

#include "../dto/Dtos.hpp"
#include "oatpp/core/macro/component.hpp"
#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"

#include OATPP_CODEGEN_BEGIN(ApiController)

class HealthController : public oatpp::web::server::api::ApiController {
public:
    HealthController(OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper))
        : ApiController(objectMapper) {}

    static std::shared_ptr<HealthController> createShared(
            OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper)) {
        return std::make_shared<HealthController>(objectMapper);
    }

    ENDPOINT_INFO(getHealth) {
        info->summary = "Health check";
        info->description = "Returns ok when the orchestrator process is running.";
        info->tags.push_back("Health");
        info->addResponse<Object<StatusDto>>(Status::CODE_200, "application/json");
    }
    ENDPOINT("GET", "/health", getHealth) {
        auto resp = StatusDto::createShared();
        resp->status = "ok";
        resp->message = "orchestrator healthy";
        resp->code = 200;
        return createDtoResponse(Status::CODE_200, resp);
    }
};

#include OATPP_CODEGEN_END(ApiController)
