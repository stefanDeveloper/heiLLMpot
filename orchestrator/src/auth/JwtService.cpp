#include "JwtService.hpp"

#include <jwt-cpp/jwt.h>
#include <chrono>
#include <stdexcept>

JwtService::JwtService() {}

std::string JwtService::createNodeToken(const std::string& node_id,
                                         const std::string& region) {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(m_config->jwt_expiry_hours);

    return jwt::create()
        .set_issuer("honeypot-orchestrator")
        .set_type("JWT")
        .set_subject(node_id)
        .set_issued_at(now)
        .set_expires_at(exp)
        .set_payload_claim("node_id", jwt::claim(node_id))
        .set_payload_claim("region",  jwt::claim(region))
        .sign(jwt::algorithm::hs256{m_config->jwt_secret});
}

NodeToken JwtService::validateToken(const std::string& token) {
    NodeToken result;
    try {
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{m_config->jwt_secret})
            .with_issuer("honeypot-orchestrator");

        auto decoded = jwt::decode(token);
        verifier.verify(decoded);

        result.valid   = true;
        result.node_id = decoded.get_payload_claim("node_id").as_string();
        result.region  = decoded.get_payload_claim("region").as_string();
    } catch (const std::exception& e) {
        result.valid = false;
        result.error = e.what();
    }
    return result;
}
