#pragma once

#include "JwtService.hpp"
#include "oatpp/web/server/interceptor/RequestInterceptor.hpp"

#include <memory>
#include <string>

/// Request interceptor that validates:
///   1. Bearer JWT from Authorization header (issued by orchestrator at node registration)
/// The mTLS client certificate validation is handled upstream at the Nginx level;
/// the orchestrator trusts the X-Client-CN header set by Nginx after mTLS handshake.
/// Both node_id from the JWT and the CN from X-Client-CN must match.
///
/// Public paths (no auth required): /api/v1/nodes/register, /health,
///   /swagger/*, /api/docs/*
class NodeAuthInterceptor
    : public oatpp::web::server::interceptor::RequestInterceptor {
public:
    NodeAuthInterceptor();

    std::shared_ptr<OutgoingResponse>
    intercept(const std::shared_ptr<IncomingRequest>& request) override;

private:
    std::unique_ptr<JwtService> m_jwtService;

    bool isPublicPath(const std::string& path) const;

    std::shared_ptr<OutgoingResponse>
    unauthorized(const std::string& message) const;
};
