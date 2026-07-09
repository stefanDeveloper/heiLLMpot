#pragma once
#include "honeypot_protocol.h"
#include "server_fingerprint.h"
#include "logger.h"

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <string>
#include <map>
#include <mutex>
#include <random>
#include <atomic>
#include <memory>

/// HTTP/HTTPS honeypot that serves LLM-generated site content
/// with realistic server fingerprinting.
class HttpHoneypot : public HoneypotProtocol {
public:
    struct Config {
        std::string listen_addr = "0.0.0.0";
        int http_port = 80;
        int https_port = 443;
        bool enable_https = true;
        std::string cert_path;         // empty = auto-generate
        std::string key_path;          // empty = auto-generate
        std::string sites_dir = "./generated_sites";
        std::string fingerprint_profile = "apache_2_4";
        int jitter_min_ms = 20;
        int jitter_max_ms = 200;

        /// When true, rotate through all loaded sites round-robin
        /// instead of picking one at startup.
        bool rotate_sites = false;

        // TLS certificate metadata (from site JSON, no hardcoded defaults)
        std::string tls_cn = "";
        std::string tls_org = "";
        std::string tls_country = "";
        std::string tls_state = "";
        std::string tls_locality = "";
        std::string active_site = "";
    };

    explicit HttpHoneypot(const Config& config);
    ~HttpHoneypot() override;

    std::string name() const override { return "HTTP"; }
    void start() override;
    void stop() override;
    bool is_running() const override { return running_.load(); }

    /// Return the SSH profile JSON for the currently active site,
    /// so main.cpp can align the SSH honeypot to the same identity.
    nlohmann::json get_active_ssh_profile() const;

private:
    // ─── Types ──────────────────────────────────────────────────────────
    struct SiteData {
        std::string site_id;
        std::string model;
        nlohmann::json app_spec;
        std::string server_profile;  // e.g., "apache_2_4"
        nlohmann::json tls_meta;     // TLS cert metadata from generator
        nlohmann::json ssh_profile;  // SSH profile for paired SSH honeypot
        // routes[path][method] = HTML body
        std::map<std::string, std::map<std::string, std::string>> routes;
        // routes[path] = auth_required (true/false)
        std::map<std::string, bool> auth_required;

        // REST API endpoint data (loaded from api_routes.json)
        nlohmann::json api_routes;   // full parsed api_routes.json
        // Valid user credentials for login validation (from users.json)
        std::map<std::string, std::string> valid_users;  // username -> password
        // MFA verification page HTML (from mfa_page.html)
        std::string mfa_page_html;
    };

    struct SessionState {
        bool authenticated = false;
        std::string username;
        std::string session_cookie;
        bool mfa_required = false;    // true after correct password, awaiting 2FA
        bool mfa_completed = false;   // true after any 2FA code submitted
        int login_attempts = 0;       // track brute-force count per session
        int mfa_attempts = 0;         // track MFA attempts per session
    };

    // ─── Methods ────────────────────────────────────────────────────────
    void load_sites();
    /// Apply site-specific fingerprint/TLS metadata to config_.
    void apply_site_config(SiteData& site);
    void setup_routes(httplib::Server& server);
    void handle_request(const httplib::Request& req, httplib::Response& res,
                        const std::string& method);
    void handle_api_request(const httplib::Request& req, httplib::Response& res,
                            const std::string& method, SiteData* site,
                            const std::string& session_id);
    void handle_login_post(const httplib::Request& req, httplib::Response& res,
                           SiteData* site, const std::string& session_id);
    void handle_mfa_request(const httplib::Request& req, httplib::Response& res,
                            const std::string& method, SiteData* site,
                            const std::string& session_id);
    void apply_fingerprint(httplib::Response& res);
    void add_adaptive_jitter(const std::string& path, const std::string& method,
                             int login_attempts = 0);
    void add_timing_jitter();
    std::string generate_session_id();
    std::string get_or_create_session(const httplib::Request& req,
                                      httplib::Response& res);
    std::string inject_dynamic_content(const std::string& body,
                                       const std::string& session_id);
    std::string generate_error_page(int code, const std::string& message);

    /// Return active site pointer, advancing the rotation index if enabled.
    SiteData* get_active_site();

    // Auto-SSL certificate generation
    static bool generate_self_signed_cert(const std::string& cert_path,
                                          const std::string& key_path,
                                          const Config& config);

    // ─── Data ───────────────────────────────────────────────────────────
    Config config_;
    ServerFingerprint fingerprint_;
    std::vector<SiteData> sites_;
    /// Index of the currently active site (for rotation mode).
    size_t site_index_ = 0;
    std::mutex site_mutex_;
    std::map<std::string, SessionState> sessions_;
    std::mutex session_mutex_;
    std::atomic<bool> running_{false};
    std::unique_ptr<httplib::Server> http_server_;
    std::unique_ptr<httplib::SSLServer> https_server_;
    std::mt19937 rng_;
};
