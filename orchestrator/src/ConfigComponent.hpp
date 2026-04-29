#pragma once

#include "oatpp/core/Types.hpp"
#include "oatpp/core/macro/component.hpp"

#include <string>

/// Orchestrator application configuration loaded from JSON file.
struct OrchestratorConfig {
    // HTTP server
    std::string listen_addr  = "0.0.0.0";
    int         port         = 8080;

    // mTLS/JWT auth
    std::string jwt_secret;                 // HMAC-SHA256 secret for node JWTs
    int         jwt_expiry_hours = 24;

    // PostgreSQL
    std::string db_host      = "localhost";
    int         db_port      = 5432;
    std::string db_name      = "honeypot_db";
    std::string db_user      = "orchestrator_app";
    std::string db_password;

    // GeoIP
    std::string geoip_db_path   = "/usr/share/GeoIP/GeoLite2-City.mmdb";
    std::string geoip_asn_path  = "/usr/share/GeoIP/GeoLite2-ASN.mmdb";

    // Worker
    int worker_interval_sec = 30;
};

/// Global config singleton – loaded once at startup.
class ConfigComponent {
public:
    OATPP_CREATE_COMPONENT(std::shared_ptr<OrchestratorConfig>, config)([] {
        // Default config – will be populated from JSON in App.cpp
        return std::make_shared<OrchestratorConfig>();
    }());
};
