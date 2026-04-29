#pragma once

#include "oatpp/web/server/handler/ErrorHandler.hpp"
#include "oatpp/web/protocol/http/outgoing/ResponseFactory.hpp"
#include "oatpp/parser/json/mapping/ObjectMapper.hpp"

class ErrorHandler : public oatpp::web::server::handler::ErrorHandler {
public:
    explicit ErrorHandler(
        const std::shared_ptr<oatpp::data::mapping::ObjectMapper>& objectMapper);

    std::shared_ptr<oatpp::web::protocol::http::outgoing::Response>
    handleError(const oatpp::web::protocol::http::Status& status,
                const oatpp::String& message,
                const Headers& headers) override;

private:
    std::shared_ptr<oatpp::data::mapping::ObjectMapper> m_objectMapper;
};
