#pragma once
#include <string>
#include <map>
#include <vector>

/// A server fingerprint profile defines the HTTP headers that mimic
/// a specific real-world web server software.
struct ServerFingerprint {
    std::string name;
    std::string cookie_name;  ///< Session cookie name for this server type
    std::map<std::string, std::string> headers;

    /// Get predefined fingerprint profiles.
    static const std::map<std::string, ServerFingerprint>& profiles() {
        static const std::map<std::string, ServerFingerprint> p = {
            {"apache_2_4", {
                "Apache/2.4.62 (Ubuntu)",
                "PHPSESSID",
                {
                    {"Server", "Apache/2.4.62 (Ubuntu)"},
                    {"X-Powered-By", "PHP/8.2.27"},
                    {"X-Content-Type-Options", "nosniff"},
                    {"X-Frame-Options", "SAMEORIGIN"},
                    {"Accept-Ranges", "bytes"},
                    {"Vary", "Accept-Encoding"},
                }
            }},
            {"nginx_1_24", {
                "nginx/1.24.0",
                "session_id",
                {
                    {"Server", "nginx/1.24.0"},
                    {"X-Content-Type-Options", "nosniff"},
                    {"X-Frame-Options", "DENY"},
                    {"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
                    {"Vary", "Accept-Encoding"},
                }
            }},
            {"iis_10", {
                "Microsoft-IIS/10.0",
                "ASP.NET_SessionId",
                {
                    {"Server", "Microsoft-IIS/10.0"},
                    {"X-Powered-By", "ASP.NET"},
                    {"X-AspNet-Version", "4.0.30319"},
                    {"X-Content-Type-Options", "nosniff"},
                    {"X-Frame-Options", "SAMEORIGIN"},
                }
            }},
            {"exchange_2019", {
                "Microsoft-IIS/10.0 (Exchange)",
                "ASP.NET_SessionId",
                {
                    {"Server", "Microsoft-IIS/10.0"},
                    {"X-Powered-By", "ASP.NET"},
                    {"X-OWA-Version", "15.2.1544.11"},
                    {"X-FEServer", "EX-MBX01"},
                    {"X-Content-Type-Options", "nosniff"},
                    {"X-Frame-Options", "SAMEORIGIN"},
                    {"request-id", "00000000-0000-0000-0000-000000000000"},
                }
            }},
            {"tomcat_9", {
                "Apache Tomcat/9.0.97",
                "JSESSIONID",
                {
                    {"Server", "Apache-Coyote/1.1"},
                    {"X-Content-Type-Options", "nosniff"},
                    {"X-Frame-Options", "DENY"},
                }
            }},
        };
        return p;
    }

    /// Lookup by name. Falls back to nginx if not found.
    static const ServerFingerprint& get(const std::string& profile_name) {
        auto& p = profiles();
        auto it = p.find(profile_name);
        if (it != p.end()) return it->second;
        return p.at("nginx_1_24");  // safe default
    }
};
