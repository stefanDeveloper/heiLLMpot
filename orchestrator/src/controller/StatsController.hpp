#pragma once

#include "../db/DbClient.hpp"
#include "../dto/Dtos.hpp"
#include "oatpp/core/macro/component.hpp"
#include "oatpp/web/server/api/ApiController.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"

#include OATPP_CODEGEN_BEGIN(ApiController)

class StatsController : public oatpp::web::server::api::ApiController {
public:
    StatsController(OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper))
        : ApiController(objectMapper) {}

    static std::shared_ptr<StatsController> createShared(
            OATPP_COMPONENT(std::shared_ptr<ObjectMapper>, objectMapper)) {
        return std::make_shared<StatsController>(objectMapper);
    }

    // ── GET /api/v1/stats ────────────────────────────────────────────────────

    ENDPOINT_INFO(getStats) {
        info->summary     = "Get aggregated honeypot statistics";
        info->description =
            "Returns daily aggregated statistics (session counts, unique IPs, "
            "bot/human breakdown) for the requested date range. "
            "Defaults: `from=1970-01-01`, `to=9999-12-31` (all time).";
        info->tags.push_back("Statistics");
        info->queryParams.add<String>("from").description = "Start date YYYY-MM-DD (inclusive)";
        info->queryParams.add<String>("to").description   = "End date YYYY-MM-DD (inclusive)";
        info->addResponse<Object<StatsResponseDto>>(Status::CODE_200, "application/json");
        info->addResponse<Object<StatusDto>>(Status::CODE_401, "application/json");
    }
    ENDPOINT("GET", "/api/v1/stats", getStats,
             QUERY(String, from, "from"),
             QUERY(String, to,   "to")) {
        OATPP_COMPONENT(std::shared_ptr<DbClient>, db);
        std::string fromDate = from ? from->c_str() : "1970-01-01";
        std::string toDate   = to   ? to->c_str()   : "9999-12-31";
        auto stats = db->getStats(fromDate, toDate);
        return createDtoResponse(Status::CODE_200, stats);
    }
};

#include OATPP_CODEGEN_END(ApiController)
