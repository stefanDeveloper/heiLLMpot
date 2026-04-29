#include "ErrorHandler.hpp"
#include "dto/Dtos.hpp"

#include "oatpp/web/protocol/http/Http.hpp"

ErrorHandler::ErrorHandler(
    const std::shared_ptr<oatpp::data::mapping::ObjectMapper>& objectMapper)
    : m_objectMapper(objectMapper) {}

std::shared_ptr<oatpp::web::protocol::http::outgoing::Response>
ErrorHandler::handleError(const oatpp::web::protocol::http::Status& status,
                          const oatpp::String& message,
                          const Headers& /*headers*/) {
    auto dto    = StatusDto::createShared();
    dto->code   = status.code;
    dto->status = status.description;
    dto->message = message;

    return oatpp::web::protocol::http::outgoing::ResponseFactory::createResponse(
        status, dto, m_objectMapper);
}
