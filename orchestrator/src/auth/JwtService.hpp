#pragma once

#include "../ConfigComponent.hpp"
#include "oatpp/core/macro/component.hpp"

#include <chrono>
#include <optional>
#include <string>

/// Decoded JWT claims for a honeypot node.
struct NodeToken {
    bool        valid       = false;
    std::string node_id;
    std::string region;
    std::string error;
};

/// Lightweight JWT service for signing and validating node tokens.
/// Uses HMAC-SHA256 (HS256) via jwt-cpp.
class JwtService {
public:
    JwtService();

    /// Create a signed JWT for a freshly registered node.
    std::string createNodeToken(const std::string& node_id,
                                 const std::string& region);

    /// Validate a Bearer token; returns decoded payload or marks invalid.
    NodeToken   validateToken(const std::string& token);

private:
    OATPP_COMPONENT(std::shared_ptr<OrchestratorConfig>, m_config);
};
