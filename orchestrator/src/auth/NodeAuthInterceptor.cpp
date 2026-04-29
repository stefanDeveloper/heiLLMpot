#include "NodeAuthInterceptor.hpp"
#include "oatpp/web/protocol/http/Http.hpp"
#include "oatpp/web/protocol/http/outgoing/ResponseFactory.hpp"

#include <string>

NodeAuthInterceptor::NodeAuthInterceptor()
    : m_jwtService(std::make_unique<JwtService>()) {}

bool NodeAuthInterceptor::isPublicPath(const std::string& path) const {
    // Exact public endpoints
    if (path == "/api/v1/nodes/register") return true;
    if (path == "/health")               return true;

    // Swagger UI, static resources, and OpenAPI spec (prefix match)
    if (path.rfind("/swagger", 0) == 0)   return true;  // /swagger/ui/...
    if (path.rfind("/api/docs", 0) == 0)  return true;  // /api/docs/swagger
    if (path.rfind("/api-docs", 0) == 0)  return true;  // /api-docs/oas-3.0.0.json

    return false;
}

std::shared_ptr<NodeAuthInterceptor::OutgoingResponse>
NodeAuthInterceptor::unauthorized(const std::string& message) const {
    return oatpp::web::protocol::http::outgoing::ResponseFactory::createResponse(
        oatpp::web::protocol::http::Status::CODE_401, message.c_str());
}

std::shared_ptr<NodeAuthInterceptor::OutgoingResponse>
NodeAuthInterceptor::intercept(
    const std::shared_ptr<IncomingRequest>& request) {
    // Allow public endpoints through
    auto path = request->getStartingLine().path.toString();
    if (isPublicPath(path)) return nullptr;

    // ── 1. Extract Bearer JWT ────────────────────────────────────────────────
    auto authHeader = request->getHeader("Authorization");
    if (!authHeader || authHeader->size() < 8) {
        return unauthorized("Missing Authorization header");
    }
    std::string authStr = authHeader->c_str();
    if (authStr.rfind("Bearer ", 0) != 0) {
        return unauthorized("Authorization header must use Bearer scheme");
    }
    std::string token = authStr.substr(7);

    auto decoded = m_jwtService->validateToken(token);
    if (!decoded.valid) {
        return unauthorized("Invalid or expired token: " + decoded.error);
    }

    // ── 2. Cross-check mTLS client CN (set by Nginx after mTLS handshake) ──
    auto cnHeader = request->getHeader("X-Client-CN");
    if (cnHeader) {
        std::string cn = cnHeader->c_str();
        if (cn != decoded.node_id) {
            return unauthorized("Client certificate CN does not match JWT node_id");
        }
    }
    // (If Nginx is not configured for mTLS the header will be absent;
    //  the JWT alone is still accepted for development/testing.)

    // Store node_id for downstream controllers via custom header
    request->putOrReplaceHeader("X-Node-Id", decoded.node_id.c_str());
    return nullptr;  // continue to controller
}
