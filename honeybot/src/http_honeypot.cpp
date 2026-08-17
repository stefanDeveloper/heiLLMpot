#include "http_honeypot.h"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>
#include <chrono>
#include <thread>
#include <algorithm>
#include <ctime>
#include <iomanip>

namespace fs = std::filesystem;

// Thread-safe gmtime wrapper
static struct tm gmtime_safe(const time_t* t) {
    struct tm result{};
#ifdef _WIN32
    gmtime_s(&result, t);
#else
    gmtime_r(t, &result);
#endif
    return result;
}

// ─── Constructor ────────────────────────────────────────────────────────────

HttpHoneypot::HttpHoneypot(const Config& config)
    : config_(config),
      fingerprint_(ServerFingerprint::get(config.fingerprint_profile)),
      rng_(std::random_device{}()) {
    load_sites();
}

HttpHoneypot::~HttpHoneypot() {
    stop();
}

// ─── Site loading ───────────────────────────────────────────────────────────

void HttpHoneypot::load_sites() {
    if (!fs::exists(config_.sites_dir)) {
        Logger::instance().log("HTTP", "error", {
            {"message", "Sites directory not found: " + config_.sites_dir}
        });
        return;
    }

    for (const auto& entry : fs::directory_iterator(config_.sites_dir)) {
        try {
            if (entry.is_directory()) {
                // ── New folder-based format ──────────────────────────────
                // Each site is a subdirectory containing:
                //   metadata.json, routes.json, tls.json, ssh_profile.json
                auto meta_path   = entry.path() / "metadata.json";
                auto routes_path = entry.path() / "routes.json";
                if (!fs::exists(meta_path) || !fs::exists(routes_path)) continue;

                SiteData site;

                // Load metadata
                {
                    std::ifstream f(meta_path);
                    nlohmann::json meta;
                    f >> meta;
                    site.site_id = meta.value("site_id", "unknown");
                    site.model   = meta.value("model", "unknown");
                    site.server_profile = meta.value("server_profile", "");
                    site.mfa_enabled = meta.value("mfa_enabled", true);

                    // Build app_spec from metadata fields
                    site.app_spec = nlohmann::json::object();
                    site.app_spec["app_name"]     = meta.value("app_name", "");
                    site.app_spec["description"]  = meta.value("description", "");
                    site.app_spec["organization"] = meta.value("organization", "");
                    site.app_spec["domain"]       = meta.value("domain", "");
                }

                // Load routes — generator format: routes[path].responses[method] = html
                {
                    std::ifstream f(routes_path);
                    nlohmann::json routes_json;
                    f >> routes_json;

                    if (routes_json.is_object()) {
                        for (auto& [path, route_info] : routes_json.items()) {
                            if (!route_info.is_object()) continue;

                            // New format: HTML is in "responses" sub-object
                            nlohmann::json responses;
                            site.auth_required[path] = route_info.value("auth_required", false);
                            if (route_info.contains("responses") &&
                                route_info["responses"].is_object()) {
                                responses = route_info["responses"];
                            } else {
                                // Fallback: treat the whole object as method->html
                                responses = route_info;
                            }

                            for (auto& [method, response] : responses.items()) {
                                if (!response.is_string()) continue;
                                std::string body = response.get<std::string>();

                                // Strip LLM artifacts: remove markdown fences
                                size_t pos;
                                while ((pos = body.find("```")) != std::string::npos) {
                                    size_t end = body.find('\n', pos);
                                    if (end == std::string::npos) end = body.size();
                                    body.erase(pos, end - pos + 1);
                                }

                                // Split headers from body if HTTP status line present
                                if (body.substr(0, 5) == "HTTP/") {
                                    auto sep = body.find("\n\n");
                                    if (sep != std::string::npos) {
                                        body = body.substr(sep + 2);
                                    }
                                }

                                site.routes[path][method] = body;
                            }
                        }
                    }
                }

                // Load TLS metadata
                {
                    auto tls_path = entry.path() / "tls.json";
                    if (fs::exists(tls_path)) {
                        std::ifstream f(tls_path);
                        f >> site.tls_meta;
                    }
                }

                // Load SSH profile
                {
                    auto ssh_path = entry.path() / "ssh_profile.json";
                    if (fs::exists(ssh_path)) {
                        std::ifstream f(ssh_path);
                        f >> site.ssh_profile;
                    }
                }

                // Load API routes data
                {
                    auto api_path = entry.path() / "api_routes.json";
                    if (fs::exists(api_path)) {
                        std::ifstream f(api_path);
                        f >> site.api_routes;
                        Logger::instance().log("HTTP", "startup", {
                            {"message", "Loaded API routes"},
                            {"count", site.api_routes.size()}
                        });
                    }
                }

                // Load valid user credentials from users.json
                {
                    auto users_path = entry.path() / "users.json";
                    if (fs::exists(users_path)) {
                        std::ifstream f(users_path);
                        nlohmann::json users_json;
                        f >> users_json;
                        if (users_json.is_array()) {
                            for (auto& user : users_json) {
                                if (user.contains("username") && user.contains("password")) {
                                    site.valid_users[user["username"].get<std::string>()] =
                                        user["password"].get<std::string>();
                                }
                            }
                        }
                        Logger::instance().log("HTTP", "startup", {
                            {"message", "Loaded valid users for auth"},
                            {"count", site.valid_users.size()}
                        });
                    }
                }

                // Load MFA page HTML
                {
                    auto mfa_path = entry.path() / "mfa_page.html";
                    if (fs::exists(mfa_path)) {
                        std::ifstream f(mfa_path);
                        std::ostringstream ss;
                        ss << f.rdbuf();
                        site.mfa_page_html = ss.str();
                        Logger::instance().log("HTTP", "startup", {
                            {"message", "Loaded MFA page"},
                            {"bytes", site.mfa_page_html.size()}
                        });
                    }
                }

                sites_.push_back(std::move(site));

            } else if (entry.is_regular_file() && entry.path().extension() == ".json") {
                // ── Legacy flat single-JSON format ───────────────────────
                std::ifstream f(entry.path());
                nlohmann::json j;
                f >> j;

                SiteData site;
                site.site_id = j.value("site_id", "unknown");
                site.model = j.value("model", "unknown");
                site.app_spec = j.value("app_spec", nlohmann::json::object());
                site.server_profile = j.value("server_profile", "");
                site.tls_meta = j.value("tls", nlohmann::json::object());
                site.ssh_profile = j.value("ssh_profile", nlohmann::json::object());

                // Parse routes
                if (j.contains("routes") && j["routes"].is_object()) {
                    for (auto& [path, methods] : j["routes"].items()) {
                        if (!methods.is_object()) continue;

                        // Check if this is the new format with "responses" key
                        nlohmann::json responses;
                        site.auth_required[path] = methods.value("auth_required", false);
                        if (methods.contains("responses") &&
                            methods["responses"].is_object()) {
                            responses = methods["responses"];
                        } else {
                            responses = methods;
                        }

                        for (auto& [method, response] : responses.items()) {
                            if (!response.is_string()) continue;
                            std::string body = response.get<std::string>();

                            // Strip LLM artifacts: remove markdown fences
                            size_t pos;
                            while ((pos = body.find("```")) != std::string::npos) {
                                size_t end = body.find('\n', pos);
                                if (end == std::string::npos) end = body.size();
                                body.erase(pos, end - pos + 1);
                            }

                            // Split headers from body if HTTP status line present
                            if (body.substr(0, 5) == "HTTP/") {
                                auto sep = body.find("\n\n");
                                if (sep != std::string::npos) {
                                    body = body.substr(sep + 2);
                                }
                            }

                            site.routes[path][method] = body;
                        }
                    }
                }

                sites_.push_back(std::move(site));
            }
        } catch (const std::exception& e) {
            Logger::instance().log("HTTP", "error", {
                {"message", "Failed to load site: " + entry.path().string()},
                {"error", e.what()}
            });
        }
    }

    Logger::instance().log("HTTP", "startup", {
        {"sites_loaded", sites_.size()},
        {"sites_dir", config_.sites_dir},
        {"rotation_mode", config_.rotate_sites}
    });

    if (sites_.empty()) return;

    if (!config_.active_site.empty()) {
        bool found = false;
        for (size_t i = 0; i < sites_.size(); ++i) {
            std::string app_name = sites_[i].app_spec.value("app_name", "");
            if (app_name == config_.active_site || sites_[i].site_id == config_.active_site) {
                site_index_ = i;
                found = true;
                break;
            }
        }
        if (!found) {
            Logger::instance().log("HTTP", "warn", {
                {"message", "Active site not found in generated sites, falling back to random site"},
                {"active_site", config_.active_site}
            });
            std::uniform_int_distribution<size_t> dist(0, sites_.size() - 1);
            site_index_ = dist(rng_);
        }
        apply_site_config(sites_[site_index_]);
    } else if (!config_.rotate_sites) {
        // Pick a random site at startup (original behaviour)
        std::uniform_int_distribution<size_t> dist(0, sites_.size() - 1);
        site_index_ = dist(rng_);
        apply_site_config(sites_[site_index_]);
    } else {
        // Rotation: start from 0, but still apply the first site's metadata
        // for TLS cert generation (picked up on first request thereafter)
        site_index_ = 0;
        apply_site_config(sites_[site_index_]);
    }
}

void HttpHoneypot::apply_site_config(SiteData& site) {
    Logger::instance().log("HTTP", "startup", {
        {"active_site", site.site_id},
        {"app_name", site.app_spec.value("app_name", "unknown")},
        {"model", site.model}
    });

    // Override fingerprint profile from site if provided
    if (!site.server_profile.empty()) {
        config_.fingerprint_profile = site.server_profile;
        fingerprint_ = ServerFingerprint::get(config_.fingerprint_profile);
        Logger::instance().log("HTTP", "startup", {
            {"message", "Fingerprint overridden by site profile"},
            {"profile", config_.fingerprint_profile}
        });
    }

    // Apply TLS metadata from site if not already set via config
    if (config_.tls_cn.empty() && site.tls_meta.contains("cn")) {
        config_.tls_cn = site.tls_meta["cn"].get<std::string>();
    }
    if (config_.tls_org.empty() && site.tls_meta.contains("organization")) {
        config_.tls_org = site.tls_meta["organization"].get<std::string>();
    }
    if (config_.tls_country.empty() && site.tls_meta.contains("country")) {
        config_.tls_country = site.tls_meta["country"].get<std::string>();
    }
    if (config_.tls_state.empty() && site.tls_meta.contains("state")) {
        config_.tls_state = site.tls_meta["state"].get<std::string>();
    }
    if (config_.tls_locality.empty() && site.tls_meta.contains("locality")) {
        config_.tls_locality = site.tls_meta["locality"].get<std::string>();
    }

    // Fallback CN to avoid empty TLS subject
    if (config_.tls_cn.empty()) {
        config_.tls_cn = site.app_spec.value("domain", "honeypot.local");
    }
}

// ─── Active site access ─────────────────────────────────────────────────────

HttpHoneypot::SiteData* HttpHoneypot::get_active_site() {
    if (sites_.empty()) return nullptr;

    std::lock_guard<std::mutex> lock(site_mutex_);

    if (config_.rotate_sites) {
        // Round-robin: advance on each call
        site_index_ = (site_index_ + 1) % sites_.size();
        Logger::instance().log("HTTP", "rotation", {
            {"site_index", site_index_},
            {"site_id", sites_[site_index_].site_id}
        });
    }

    return &sites_[site_index_];
}

nlohmann::json HttpHoneypot::get_active_ssh_profile() const {
    if (sites_.empty()) return nlohmann::json();
    // site_mutex_ not needed here since we read site_index_ which was
    // set during load_sites() before any threads start.
    if (site_index_ < sites_.size()) {
        return sites_[site_index_].ssh_profile;
    }
    return nlohmann::json();
}

// ─── Route setup ────────────────────────────────────────────────────────────

void HttpHoneypot::setup_routes(httplib::Server& server) {
    // Catch-all handler for all GET requests
    server.Get(".*", [this](const httplib::Request& req, httplib::Response& res) {
        handle_request(req, res, "GET");
    });

    // Catch-all handler for all POST requests
    server.Post(".*", [this](const httplib::Request& req, httplib::Response& res) {
        handle_request(req, res, "POST");
    });

    server.Put(".*", [this](const httplib::Request& req, httplib::Response& res) {
        handle_request(req, res, "PUT");
    });

    server.Patch(".*", [this](const httplib::Request& req, httplib::Response& res) {
        handle_request(req, res, "PATCH");
    });

    server.Delete(".*", [this](const httplib::Request& req, httplib::Response& res) {
        handle_request(req, res, "DELETE");
    });

    // Also handle OPTIONS for realism
    server.Options(".*", [this](const httplib::Request& req, httplib::Response& res) {
        apply_fingerprint(res);
        res.set_header("Allow", "GET, POST, HEAD, OPTIONS");
        res.status = 200;
    });
}

// ─── Request handling ───────────────────────────────────────────────────────

void HttpHoneypot::handle_request(const httplib::Request& req,
                                   httplib::Response& res,
                                   const std::string& method) {
    std::string session_id = get_or_create_session(req, res);

    // Add adaptive timing jitter based on request type
    int login_attempts_count = 0;
    {
        std::lock_guard<std::mutex> lock(session_mutex_);
        if (sessions_.count(session_id)) {
            login_attempts_count = sessions_[session_id].login_attempts;
        }
    }
    add_adaptive_jitter(req.path, method, login_attempts_count);
    apply_fingerprint(res);

    SiteData* active_site = get_active_site();
    if (!active_site) {
        res.status = 503;
        res.set_content(generate_error_page(503, "Service Temporarily Unavailable"),
                        "text/html; charset=utf-8");
        Logger::instance().log("HTTP", "request", {
            {"client_ip",   req.remote_addr},
            {"method",      method},
            {"path",        req.path},
            {"user_agent",  req.get_header_value("User-Agent")},
            {"session_id",  session_id},
            {"status_code", res.status}
        });
        return;
    }

    // Route to API handler for /api/* paths
    if (req.path.substr(0, 5) == "/api/") {
        handle_api_request(req, res, method, active_site, session_id);
        return;
    }

    // Route to MFA handler
    if (req.path == "/mfa") {
        handle_mfa_request(req, res, method, active_site, session_id);
        return;
    }

    // Handle login POST with credential validation and MFA redirect
    if (req.path == "/login" && method == "POST") {
        handle_login_post(req, res, active_site, session_id);
        return;
    }

    // Look up the route in the active site
    std::string path = req.path;
    
    // Auth Check: If the path requires auth but session is not authenticated, redirect to /login
    bool needs_auth = false;
    {
        auto auth_it = active_site->auth_required.find(path);
        if (auth_it != active_site->auth_required.end()) {
            needs_auth = auth_it->second;
        }
    }
    
    bool is_auth = false;
    {
        std::lock_guard<std::mutex> lock(session_mutex_);
        if (sessions_.count(session_id)) {
            is_auth = sessions_[session_id].authenticated;
        }
    }
    
    if (needs_auth && !is_auth) {
        res.status = 302;
        res.set_header("Location", "/login");
        res.set_content("Redirecting to login...", "text/plain");
        Logger::instance().log("HTTP", "unauthorized_redirect", {
            {"client_ip",   req.remote_addr},
            {"path",        req.path},
            {"session_id",  session_id},
            {"site_id",     active_site->site_id}
        });
        return;
    }

    auto route_it = active_site->routes.find(path);
    if (route_it == active_site->routes.end() && !path.empty()) {
        // Try without trailing slash or with it
        if (path.back() == '/' && path.size() > 1) {
            route_it = active_site->routes.find(path.substr(0, path.size() - 1));
        } else {
            route_it = active_site->routes.find(path + "/");
        }
    }

    if (route_it == active_site->routes.end()) {
        res.status = 404;
        res.set_content(generate_error_page(404, "Not Found"),
                        "text/html; charset=utf-8");
        Logger::instance().log("HTTP", "request", {
            {"client_ip",   req.remote_addr},
            {"method",      method},
            {"path",        req.path},
            {"user_agent",  req.get_header_value("User-Agent")},
            {"session_id",  session_id},
            {"site_id",     active_site->site_id},
            {"status_code", res.status}
        });
        return;
    }

    // Find the method response
    auto& methods_map = route_it->second;
    auto method_it = methods_map.find(method);
    if (method_it == methods_map.end()) {
        method_it = methods_map.find("GET");
    }
    if (method_it == methods_map.end()) {
        res.status = 405;
        res.set_content(generate_error_page(405, "Method Not Allowed"),
                        "text/html; charset=utf-8");
        Logger::instance().log("HTTP", "request", {
            {"client_ip",   req.remote_addr},
            {"method",      method},
            {"path",        req.path},
            {"user_agent",  req.get_header_value("User-Agent")},
            {"session_id",  session_id},
            {"site_id",     active_site->site_id},
            {"status_code", res.status}
        });
        return;
    }

    // Inject dynamic content
    std::string body = inject_dynamic_content(method_it->second, session_id);

    res.status = 200;
    res.set_content(body, "text/html; charset=utf-8");

    // Log request with final status and site context
    nlohmann::json req_log = {
        {"client_ip",   req.remote_addr},
        {"method",      method},
        {"path",        req.path},
        {"user_agent",  req.get_header_value("User-Agent")},
        {"session_id",  session_id},
        {"site_id",     active_site->site_id},
        {"status_code", res.status}
    };
    if (!req.body.empty()) {
        req_log["post_body"] = req.body.substr(0, 512);
    }
    Logger::instance().log("HTTP", "request", req_log);
}

// ─── API request handler (IDOR simulation) ──────────────────────────────────

void HttpHoneypot::handle_api_request(const httplib::Request& req,
                                       httplib::Response& res,
                                       const std::string& method,
                                       SiteData* site,
                                       const std::string& session_id) {
    // Check authentication for API requests
    bool is_auth = false;
    {
        std::lock_guard<std::mutex> lock(session_mutex_);
        if (sessions_.count(session_id)) {
            is_auth = sessions_[session_id].authenticated;
        }
    }

    // Check if this API route requires auth
    bool route_requires_auth = true;  // default: API routes need auth
    std::string matched_route;
    nlohmann::json route_data;

    // Try exact match first
    if (site->api_routes.contains(req.path)) {
        matched_route = req.path;
        route_data = site->api_routes[req.path];
        if (route_data.contains("auth_required")) {
            route_requires_auth = route_data["auth_required"].get<bool>();
        }
    } else {
        // Try pattern matching for /api/v1/resource/{id} style routes
        // Extract the base path and check if a template route exists
        std::string base_path = req.path;
        std::string id_value;

        // Find the last segment and check if it's numeric
        auto last_slash = base_path.rfind('/');
        if (last_slash != std::string::npos && last_slash < base_path.size() - 1) {
            std::string last_segment = base_path.substr(last_slash + 1);
            bool is_numeric = !last_segment.empty() &&
                std::all_of(last_segment.begin(), last_segment.end(), ::isdigit);

            if (is_numeric) {
                id_value = last_segment;
                std::string template_path = base_path.substr(0, last_slash) + "/{id}";

                if (site->api_routes.contains(template_path)) {
                    matched_route = template_path;
                    route_data = site->api_routes[template_path];
                    if (route_data.contains("auth_required")) {
                        route_requires_auth = route_data["auth_required"].get<bool>();
                    }
                }
            }
        }

        // If still no match, try broader patterns
        if (matched_route.empty()) {
            for (auto& [pattern, data] : site->api_routes.items()) {
                // Check if the request path starts with the pattern base
                if (pattern.find("{id}") != std::string::npos) {
                    std::string pattern_base = pattern.substr(0, pattern.find("{id}"));
                    if (req.path.substr(0, pattern_base.size()) == pattern_base) {
                        matched_route = pattern;
                        route_data = data;
                        // Extract the ID from the remaining path
                        id_value = req.path.substr(pattern_base.size());
                        // Remove trailing slash if present
                        if (!id_value.empty() && id_value.back() == '/') {
                            id_value.pop_back();
                        }
                        break;
                    }
                }
            }
        }

        // Handle IDOR: if we matched a template route with an ID
        if (!matched_route.empty() && !id_value.empty() &&
            route_data.contains("idor_enabled") &&
            route_data["idor_enabled"].get<bool>()) {

            if (route_requires_auth && !is_auth) {
                res.status = 401;
                nlohmann::json err = {
                    {"error", "Unauthorized"},
                    {"message", "Authentication required"},
                    {"status", 401}
                };
                res.set_content(err.dump(2), "application/json");
            } else if (route_data.contains("user_responses") &&
                       route_data["user_responses"].contains(id_value)) {
                res.status = 200;
                res.set_content(route_data["user_responses"][id_value].dump(2),
                                "application/json");
            } else {
                res.status = 404;
                nlohmann::json err = {
                    {"error", "Not Found"},
                    {"message", "Resource with ID " + id_value + " not found"},
                    {"status", 404}
                };
                res.set_content(err.dump(2), "application/json");
            }

            Logger::instance().log("HTTP", "api_request", {
                {"client_ip",    req.remote_addr},
                {"method",       method},
                {"path",         req.path},
                {"matched_route", matched_route},
                {"id_param",     id_value},
                {"idor",         true},
                {"session_id",   session_id},
                {"site_id",      site->site_id},
                {"status_code",  res.status},
                {"authenticated", is_auth}
            });
            return;
        }
    }

    // No route matched at all
    if (matched_route.empty()) {
        res.status = 404;
        nlohmann::json err = {
            {"error", "Not Found"},
            {"message", "The requested endpoint does not exist"},
            {"status", 404}
        };
        res.set_content(err.dump(2), "application/json");
        Logger::instance().log("HTTP", "api_request", {
            {"client_ip",   req.remote_addr},
            {"method",      method},
            {"path",        req.path},
            {"session_id",  session_id},
            {"site_id",     site->site_id},
            {"status_code", 404}
        });
        return;
    }

    // Verify the HTTP method is allowed for this API route
    bool method_allowed = false;
    if (route_data.contains("methods") && route_data["methods"].is_array()) {
        for (const auto& m : route_data["methods"]) {
            if (m == method) {
                method_allowed = true;
                break;
            }
        }
    } else {
        // Fallback to GET if not specified
        if (method == "GET") method_allowed = true;
    }

    if (!method_allowed) {
        res.status = 405;
        nlohmann::json err = {
            {"error", "Method Not Allowed"},
            {"message", "The method " + method + " is not supported for this endpoint."},
            {"status", 405}
        };
        res.set_content(err.dump(2), "application/json");
        Logger::instance().log("HTTP", "api_request", {
            {"client_ip",   req.remote_addr},
            {"method",      method},
            {"path",        req.path},
            {"session_id",  session_id},
            {"site_id",     site->site_id},
            {"status_code", 405}
        });
        return;
    }

    // JSON Validation for POST/PUT/PATCH
    if ((method == "POST" || method == "PUT" || method == "PATCH") && !req.body.empty()) {
        try {
            auto parsed_body = nlohmann::json::parse(req.body);
        } catch (const nlohmann::json::parse_error& e) {
            res.status = 400;
            nlohmann::json err = {
                {"error", "Bad Request"},
                {"message", "Invalid JSON payload: " + std::string(e.what())},
                {"status", 400}
            };
            res.set_content(err.dump(2), "application/json");
            Logger::instance().log("HTTP", "api_request", {
                {"client_ip",   req.remote_addr},
                {"method",      method},
                {"path",        req.path},
                {"session_id",  session_id},
                {"site_id",     site->site_id},
                {"status_code", 400},
                {"reason",      "json_parse_error"}
            });
            return;
        }
    }

    // Auth check for matched route
    if (route_requires_auth && !is_auth) {
        res.status = 401;
        nlohmann::json err = {
            {"error", "Unauthorized"},
            {"message", "Authentication required. Please provide a valid session."},
            {"status", 401}
        };
        res.set_content(err.dump(2), "application/json");
        Logger::instance().log("HTTP", "api_request", {
            {"client_ip",   req.remote_addr},
            {"method",      method},
            {"path",        req.path},
            {"session_id",  session_id},
            {"site_id",     site->site_id},
            {"status_code", 401},
            {"authenticated", false}
        });
        return;
    }

    // Serve the static response for this API endpoint
    if (route_data.contains("response")) {
        res.status = 200;
        res.set_content(route_data["response"].dump(2), "application/json");
    } else {
        res.status = 200;
        res.set_content(route_data.dump(2), "application/json");
    }

    Logger::instance().log("HTTP", "api_request", {
        {"client_ip",    req.remote_addr},
        {"method",       method},
        {"path",         req.path},
        {"matched_route", matched_route},
        {"session_id",   session_id},
        {"site_id",      site->site_id},
        {"status_code",  res.status},
        {"authenticated", is_auth}
    });
}

// ─── Login POST handler (credential validation + MFA redirect) ──────────────

void HttpHoneypot::handle_login_post(const httplib::Request& req,
                                      httplib::Response& res,
                                      SiteData* site,
                                      const std::string& session_id) {
    // Parse form fields
    std::string login_user, login_pass, next_url;
    auto u_it = req.params.find("username");
    if (u_it != req.params.end()) login_user = u_it->second;
    auto p_it = req.params.find("password");
    if (p_it != req.params.end()) login_pass = p_it->second;
    auto n_it = req.params.find("next");
    if (n_it != req.params.end()) next_url = n_it->second;

    // Fallback: Check if credentials were submitted as JSON (common for automated scripts/bots)
    if (login_user.empty() && login_pass.empty() && !req.body.empty()) {
        auto content_type = req.get_header_value("Content-Type");
        if (content_type.find("application/json") != std::string::npos) {
            try {
                auto body_json = nlohmann::json::parse(req.body);
                if (body_json.contains("username") && body_json["username"].is_string()) {
                    login_user = body_json["username"].get<std::string>();
                }
                if (body_json.contains("password") && body_json["password"].is_string()) {
                    login_pass = body_json["password"].get<std::string>();
                }
            } catch (...) {
                // Ignore JSON parse errors
            }
        }
    }

    // Check for SQL injection leak
    if (check_sqli_leak(login_user, res, site)) {
        // SQL injection handled (response already populated)
        Logger::instance().log("HTTP", "sqli_detected", {
            {"client_ip",  req.remote_addr},
            {"session_id", session_id},
            {"site_id",    site->site_id},
            {"payload",    login_user},
            {"result",     "leaked_credentials"}
        });
        return;
    }

    // Log the attempt (always log credentials for honeypot intelligence)
    nlohmann::json login_log = {
        {"client_ip",  req.remote_addr},
        {"session_id", session_id},
        {"site_id",    site->site_id},
        {"username",   login_user},
        {"password",   login_pass}
    };
    if (!req.body.empty()) {
        login_log["post_body"] = req.body.substr(0, 512);
    }

    // Validate credentials against site's user database
    bool valid_user = site->valid_users.count(login_user) > 0;
    bool valid_pass = valid_user && site->valid_users[login_user] == login_pass;

    // Increment login attempt counter
    {
        std::lock_guard<std::mutex> lock(session_mutex_);
        if (sessions_.count(session_id)) {
            sessions_[session_id].login_attempts++;
        }
    }

    if (valid_pass) {
        if (site->mfa_enabled) {
            // Correct credentials → redirect to MFA verification
            login_log["result"] = "valid_credentials_mfa_redirect";
            Logger::instance().log("HTTP", "login", login_log);

            {
                std::lock_guard<std::mutex> lock(session_mutex_);
                if (sessions_.count(session_id)) {
                    sessions_[session_id].username = login_user;
                    sessions_[session_id].mfa_required = true;
                    sessions_[session_id].mfa_completed = false;
                    sessions_[session_id].next_url = next_url;
                }
            }

            // Redirect to MFA page
            res.status = 302;
            res.set_header("Location", "/mfa");
            res.set_content("Redirecting to verification...", "text/plain");
        } else {
            // MFA disabled, redirect straight to the first authenticated route
            login_log["result"] = "valid_credentials_login_success";
            Logger::instance().log("HTTP", "login", login_log);

            {
                std::lock_guard<std::mutex> lock(session_mutex_);
                if (sessions_.count(session_id)) {
                    sessions_[session_id].username = login_user;
                    sessions_[session_id].mfa_required = false;
                    sessions_[session_id].mfa_completed = false;
                    sessions_[session_id].authenticated = true;
                    sessions_[session_id].next_url = next_url;
                }
            }

            // Find the first authenticated route to redirect to
            std::string redirect_target = "/dashboard"; // Fallback to /dashboard
            if (!next_url.empty()) {
                redirect_target = (next_url == "/") ? "/dashboard" : next_url;
            } else {
                for (const auto& [r_path, r_auth] : site->auth_required) {
                    if (r_auth && r_path != "/login") {
                        redirect_target = r_path;
                        break;
                    }
                }
            }

            res.status = 302;
            res.set_header("Location", redirect_target);
            res.set_content("Redirecting to " + redirect_target + "...", "text/plain");
        }
    } else {
        // Invalid credentials → serve login page with error message
        login_log["result"] = valid_user ? "wrong_password" : "unknown_user";
        Logger::instance().log("HTTP", "login", login_log);

        // Find the login page HTML and inject an error banner
        std::string login_html;
        auto route_it = site->routes.find("/login");
        if (route_it != site->routes.end()) {
            auto method_it = route_it->second.find("GET");
            if (method_it == route_it->second.end()) {
                method_it = route_it->second.begin();
            }
            if (method_it != route_it->second.end()) {
                login_html = method_it->second;
            }
        }

        if (login_html.empty()) {
            login_html = generate_error_page(401, "Authentication Failed");
        } else {
            // Inject error alert after <body> or at start of main content
            std::string error_banner =
                "<div class=\"alert alert-danger alert-dismissible fade show\" "
                "role=\"alert\" style=\"position:fixed;top:20px;left:50%;"
                "transform:translateX(-50%);z-index:9999;max-width:400px;"
                "box-shadow:0 4px 12px rgba(0,0,0,0.15);\">"
                "<strong>Authentication Failed.</strong> "
                "Invalid username or password. Please try again."
                "<button type=\"button\" class=\"btn-close\" "
                "data-bs-dismiss=\"alert\"></button></div>";

            auto body_pos = login_html.find("<body");
            if (body_pos != std::string::npos) {
                auto body_close = login_html.find(">", body_pos);
                if (body_close != std::string::npos) {
                    login_html.insert(body_close + 1, error_banner);
                }
            }
        }

        res.status = 200;
        res.set_content(login_html, "text/html; charset=utf-8");
    }
}

// ─── SQL Injection Credential Leak handler ──────────────────────────────────

bool HttpHoneypot::check_sqli_leak(const std::string& input, httplib::Response& res, SiteData* site) {
    if (input.empty()) return false;
    
    // Basic SQL injection patterns
    std::string lower_input = input;
    std::transform(lower_input.begin(), lower_input.end(), lower_input.begin(), ::tolower);
    
    bool is_sqli = (lower_input.find("' or '1'='1") != std::string::npos ||
                    lower_input.find("'or'1'='1") != std::string::npos ||
                    lower_input.find("\" or \"1\"=\"1") != std::string::npos ||
                    lower_input.find("union select") != std::string::npos ||
                    lower_input.find("';--") != std::string::npos ||
                    lower_input.find("' --") != std::string::npos);

    if (!is_sqli) return false;

    // Generate fake database dump leaking valid credentials in a highly realistic raw PHP Exception format
    // This simulates a sloppy developer throwing an Exception with print_r($results, true) when count($results) > 1
    std::ostringstream html;
    
    // Sanitize input to prevent breaking the HTML too badly, but keep the payload visible
    std::string safe_input = input;
    size_t pos;
    while ((pos = safe_input.find("<")) != std::string::npos) safe_input.replace(pos, 1, "&lt;");
    while ((pos = safe_input.find(">")) != std::string::npos) safe_input.replace(pos, 1, "&gt;");
    
    html << "<br />\n"
         << "<b>Fatal error</b>:  Uncaught Exception: Authentication failed: multiple records found for username lookup. Result dump: Array\n"
         << "(\n";
         
    int id = 1;
    for (const auto& [user, pass] : site->valid_users) {
        html << "    [" << (id - 1) << "] =&gt; Array\n"
             << "        (\n"
             << "            [id] =&gt; " << id << "\n"
             << "            [username] =&gt; " << user << "\n"
             << "            [password] =&gt; " << pass << "\n"
             << "            [role] =&gt; " << (user.find("admin") != std::string::npos || user.find("m.") != std::string::npos ? "admin" : "user") << "\n"
             << "            [status] =&gt; active\n"
             << "            [last_login] =&gt; " << "2023-11-" << (10 + (id % 15)) << " 08:33:12\n"
             << "        )\n\n";
        id++;
    }
    
    html << ")\n"
         << " in /var/www/html/models/Auth.php:58\n"
         << "Stack trace:\n"
         << "#0 /var/www/html/controllers/Login.php(32): AuthModel-&gt;authenticate('" << safe_input << "', '***')\n"
         << "#1 {main}\n"
         << "  thrown in <b>/var/www/html/models/Auth.php</b> on line <b>58</b><br />\n";

    res.status = 500;
    res.set_content(html.str(), "text/html; charset=utf-8");
    return true;
}

// ─── MFA verification handler ───────────────────────────────────────────────

void HttpHoneypot::handle_mfa_request(const httplib::Request& req,
                                       httplib::Response& res,
                                       const std::string& method,
                                       SiteData* site,
                                       const std::string& session_id) {
    // Check if session has MFA pending
    bool mfa_pending = false;
    {
        std::lock_guard<std::mutex> lock(session_mutex_);
        if (sessions_.count(session_id)) {
            mfa_pending = sessions_[session_id].mfa_required &&
                          !sessions_[session_id].mfa_completed;
        }
    }

    if (!mfa_pending) {
        // No MFA pending — redirect to login
        res.status = 302;
        res.set_header("Location", "/login");
        res.set_content("Redirecting to login...", "text/plain");
        return;
    }

    if (method == "GET") {
        // Serve the MFA page
        if (!site->mfa_page_html.empty()) {
            res.status = 200;
            res.set_content(site->mfa_page_html, "text/html; charset=utf-8");
        } else {
            // Minimal fallback if no MFA page was generated
            res.status = 200;
            res.set_content(
                "<html><body><h1>Verification Required</h1>"
                "<form action='/mfa' method='POST'>"
                "<input name='mfa_code' maxlength='6' placeholder='000000'>"
                "<button type='submit'>Verify</button>"
                "</form></body></html>",
                "text/html; charset=utf-8");
        }

        Logger::instance().log("HTTP", "mfa_page_served", {
            {"client_ip",  req.remote_addr},
            {"session_id", session_id},
            {"site_id",    site->site_id}
        });
    } else if (method == "POST") {
        std::string mfa_code;
        auto code_it = req.params.find("mfa_code");
        if (code_it != req.params.end()) mfa_code = code_it->second;

        bool accept_mfa = false;
        {
            std::lock_guard<std::mutex> lock(session_mutex_);
            if (sessions_.count(session_id)) {
                sessions_[session_id].mfa_attempts++;
                // Reject the first attempt to mimic real MFA failure behavior
                if (sessions_[session_id].mfa_attempts >= 2) {
                    accept_mfa = true;
                    sessions_[session_id].authenticated = true;
                    sessions_[session_id].mfa_completed = true;
                }
            }
        }

        if (!accept_mfa) {
            Logger::instance().log("HTTP", "mfa_attempt", {
                {"client_ip",  req.remote_addr},
                {"session_id", session_id},
                {"site_id",    site->site_id},
                {"mfa_code",   mfa_code},
                {"result",     "rejected"}
            });
            
            // Serve the MFA page again with an error message
            std::string html = site->mfa_page_html;
            if (html.empty()) {
                html = "<html><body><h1>Verification Required</h1><p style='color:red;'>Invalid code. Please try again.</p>"
                       "<form action='/mfa' method='POST'>"
                       "<input name='mfa_code' maxlength='6' placeholder='000000'>"
                       "<button type='submit'>Verify</button>"
                       "</form></body></html>";
            } else {
                // Inject an error banner
                std::string error_banner = "<div style='color:red; text-align:center; padding:10px;'>Invalid code. Please try again.</div>";
                auto body_pos = html.find("<body");
                if (body_pos != std::string::npos) {
                    auto body_close = html.find(">", body_pos);
                    if (body_close != std::string::npos) {
                        html.insert(body_close + 1, error_banner);
                    }
                }
            }
            res.status = 200;
            res.set_content(html, "text/html; charset=utf-8");
            return;
        }

        Logger::instance().log("HTTP", "mfa_attempt", {
            {"client_ip",  req.remote_addr},
            {"session_id", session_id},
            {"site_id",    site->site_id},
            {"mfa_code",   mfa_code},
            {"result",     "accepted"}
        });

        // Find the first authenticated route to redirect to
        std::string redirect_target;
        {
            std::lock_guard<std::mutex> lock(session_mutex_);
            if (sessions_.count(session_id) && !sessions_[session_id].next_url.empty()) {
                redirect_target = sessions_[session_id].next_url;
            }
        }
        
        if (redirect_target.empty()) {
            redirect_target = "/dashboard"; // Fallback to dashboard instead of /
            for (const auto& [r_path, r_auth] : site->auth_required) {
                if (r_auth && r_path != "/login") {
                    redirect_target = r_path;
                    break;
                }
            }
        }

        res.status = 302;
        res.set_header("Location", redirect_target);
        res.set_content("Redirecting to " + redirect_target + "...", "text/plain");
    }
}

// ─── Anti-fingerprinting: apply realistic headers ───────────────────────────

void HttpHoneypot::apply_fingerprint(httplib::Response& res) {
    for (auto& [key, value] : fingerprint_.headers) {
        res.set_header(key, value);
    }

    // Dynamic Date header (RFC 7231 format)
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf = gmtime_safe(&t);
    char buf[128];
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm_buf);
    res.set_header("Date", buf);

    res.set_header("Cache-Control", "no-cache, no-store, must-revalidate");
    res.set_header("Pragma", "no-cache");
    res.set_header("Connection", "keep-alive");
    res.set_header("Keep-Alive", "timeout=5, max=100");
}

// ─── Timing jitter ──────────────────────────────────────────────────────────

void HttpHoneypot::add_adaptive_jitter(const std::string& path, const std::string& method, int login_attempts) {
    std::uniform_int_distribution<int> dist(config_.jitter_min_ms,
                                             config_.jitter_max_ms);
    int delay;
    {
        std::lock_guard<std::mutex> lock(site_mutex_);  // protect rng_
        delay = dist(rng_);
    }
    if (login_attempts > 0) {
        int base_penalty = std::min(login_attempts * 500, 3000);
        // Add random noise (+/- 20%) to the penalty to avoid a predictable linear curve
        std::uniform_int_distribution<int> noise_dist(-base_penalty / 5, base_penalty / 5);
        int noise;
        {
            std::lock_guard<std::mutex> lock(site_mutex_);
            noise = noise_dist(rng_);
        }
        delay += base_penalty + noise;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
}

// ─── Session management ─────────────────────────────────────────────────────

std::string HttpHoneypot::generate_session_id() {
    static const char hex[] = "0123456789abcdef";
    std::string sid;
    sid.reserve(32);
    std::uniform_int_distribution<int> dist(0, 15);
    std::lock_guard<std::mutex> lock(site_mutex_);  // protect rng_
    for (int i = 0; i < 32; ++i) {
        sid += hex[dist(rng_)];
    }
    return sid;
}

std::string HttpHoneypot::get_or_create_session(const httplib::Request& req,
                                                  httplib::Response& res) {
    // Cookie name comes from the fingerprint profile — no hardcoded strings
    const std::string& cookie_name = fingerprint_.cookie_name;

    std::string cookie_header = req.get_header_value("Cookie");
    std::string session_id;

    size_t pos = cookie_header.find(cookie_name + "=");
    if (pos != std::string::npos) {
        size_t start = pos + cookie_name.size() + 1;
        size_t end = cookie_header.find(';', start);
        session_id = cookie_header.substr(
            start, end == std::string::npos ? std::string::npos : end - start);
    }

    std::lock_guard<std::mutex> lock(session_mutex_);

    if (!session_id.empty() && sessions_.count(session_id)) {
        return session_id;
    }

    // Create new session
    session_id = generate_session_id();
    sessions_[session_id] = SessionState{false, "", session_id};

    std::string cookie_value = cookie_name + "=" + session_id +
                               "; Path=/; HttpOnly; SameSite=Lax";
    if (config_.enable_https) {
        cookie_value += "; Secure";
    }
    res.set_header("Set-Cookie", cookie_value);

    return session_id;
}

// ─── Dynamic content injection ──────────────────────────────────────────────

std::string HttpHoneypot::inject_dynamic_content(const std::string& body,
                                                   const std::string& session_id) {
    std::string result = body;

    // Remove template placeholders: {{ user_data.name }}, etc.
    std::regex tmpl_re(R"(\{\{\s*[\w.]+\s*\}\})");
    result = std::regex_replace(result, tmpl_re, "");

    // Replace any stale session IDs from the generated HTML with our live one.
    // Use the fingerprint's cookie name — no hardcoded profile comparisons.
    const std::string& cookie_name = fingerprint_.cookie_name;
    std::regex session_re(
        R"(PHPSESSID=[\w.-]+|JSESSIONID=[\w.-]+|ASP\.NET_SessionId=[\w.-]+|session_id=[\w.-]+)");
    result = std::regex_replace(result, session_re,
                                cookie_name + "=" + session_id);

    // Replace localhost references
    std::regex localhost_re(R"(http://localhost:\d+)");
    result = std::regex_replace(result, localhost_re, "");

    // Removed honeypot artifact injection for evasion

    return result;
}

// ─── Error pages ────────────────────────────────────────────────────────────

std::string HttpHoneypot::generate_error_page(int code,
                                                const std::string& message) {
    // Use the configured hostname/CN so we don't hardcode "localhost"
    const std::string server_host = config_.tls_cn.empty()
                                    ? config_.listen_addr
                                    : config_.tls_cn;
    const std::string server_name = fingerprint_.name;
    const std::string port_str = std::to_string(config_.http_port);
    const std::string code_str = std::to_string(code);

    // Code-specific descriptions for realism
    std::string description;
    if (code == 404) {
        description = "The requested URL was not found on this server.";
    } else if (code == 403) {
        description = "You don't have permission to access this resource.";
    } else if (code == 405) {
        description = "The request method is not allowed for the requested URL.";
    } else if (code == 500) {
        description = "The server encountered an internal error and was unable "
                      "to complete your request.";
    } else if (code == 503) {
        description = "The server is temporarily unable to service your request "
                      "due to maintenance downtime or capacity problems.";
    } else {
        description = "The server was unable to complete your request.";
    }

    if (config_.fingerprint_profile == "apache_2_4") {
        return "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
               "<html><head>\n"
               "<title>" + code_str + " " + message + "</title>\n"
               "</head><body>\n"
               "<h1>" + message + "</h1>\n"
               "<p>" + description + "</p>\n"
               "<p>Additionally, a " + code_str + " error was encountered while "
               "trying to use an ErrorDocument to handle the request.</p>\n"
               "<hr>\n"
               "<address>" + server_name + " at " + server_host +
               " Port " + port_str + "</address>\n"
               "</body></html>\n";
    }
    if (config_.fingerprint_profile == "nginx_1_24") {
        return "<html>\r\n<head><title>" + code_str + " " +
               message + "</title></head>\r\n"
               "<body>\r\n<center><h1>" + code_str + " " +
               message + "</h1></center>\r\n"
               "<hr><center>" + server_name + "</center>\r\n"
               "</body>\r\n</html>\r\n";
    }
    if (config_.fingerprint_profile.find("iis") != std::string::npos ||
        config_.fingerprint_profile.find("exchange") != std::string::npos) {
        std::string iis_detail;
        if (code == 404) {
            iis_detail = "The resource you are looking for might have been "
                         "removed, had its name changed, or is temporarily "
                         "unavailable.";
        } else if (code == 403) {
            iis_detail = "You do not have permission to view this directory "
                         "or page using the credentials that you supplied.";
        } else if (code == 500) {
            iis_detail = "There is a problem with the resource you are looking "
                         "for, and it cannot be displayed.";
        } else {
            iis_detail = description;
        }

        return "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" "
               "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\r\n"
               "<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n"
               "<head><title>IIS " + code_str + " - " + message + "</title>\r\n"
               "<style type=\"text/css\">\r\n"
               "body{margin:0;font-size:.7em;font-family:Verdana,Arial,"
               "Helvetica,sans-serif;background:#EEEEEE;}\r\n"
               "fieldset{padding:0 15px 10px 15px;}\r\n"
               "h1{font-size:2.4em;margin:0;color:#FFF;}\r\n"
               "h2{font-size:1.7em;margin:0;color:#CC0000;}\r\n"
               "h3{font-size:1.2em;margin:10px 0 0 0;color:#000000;}\r\n"
               "#header{width:96%;margin:0 0 0 0;padding:6px 2% 6px 2%;"
               "font-family:\"trebuchet MS\",Verdana,sans-serif;"
               "color:#FFF;background-color:#555555;}\r\n"
               "#content{margin:0 0 0 2%;position:relative;}\r\n"
               ".content-container{background:#FFF;width:96%;margin-top:8px;"
               "padding:10px;position:relative;}\r\n"
               "</style></head>\r\n"
               "<body>\r\n"
               "<div id=\"header\"><h1>Server Error</h1></div>\r\n"
               "<div id=\"content\">\r\n"
               "<div class=\"content-container\">\r\n"
               "<fieldset><h2>" + code_str + " - " + message +
               "</h2>\r\n<h3>" + iis_detail + "</h3></fieldset>\r\n"
               "</div>\r\n</div>\r\n</body></html>\r\n";
    }
    if (config_.fingerprint_profile == "tomcat_9") {
        return "<!doctype html><html lang=\"en\"><head>"
               "<title>HTTP Status " + code_str + " \xe2\x80\x93 " +
               message + "</title>"
               "<style type=\"text/css\">"
               "body {font-family:Tahoma,Arial,sans-serif;}"
               "h1, h2, h3, b {color:white;background-color:#525D76;}"
               "h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;}"
               "p {font-size:12px;} a {color:black;}"
               ".line {height:1px;background-color:#525D76;border:none;}"
               "</style></head><body>"
               "<h1>HTTP Status " + code_str +
               " \xe2\x80\x93 " + message + "</h1>"
               "<hr class=\"line\" />"
               "<p><b>Type</b> Status Report</p>"
               "<p><b>Message</b> " + description + "</p>"
               "<p><b>Description</b> " + description + "</p>"
               "<hr class=\"line\" />"
               "<h3>Apache Tomcat/9.0.97</h3>"
               "</body></html>\n";
    }

    // Generic fallback
    return "<html><body><h1>" + code_str + " " +
           message + "</h1></body></html>\n";
}

// ─── Auto-SSL certificate generation ────────────────────────────────────────

bool HttpHoneypot::generate_self_signed_cert(const std::string& cert_path,
                                               const std::string& key_path,
                                               const Config& config) {
    Logger::instance().log("HTTP", "startup", {
        {"message", "Generating self-signed TLS certificate"},
        {"cn", config.tls_cn},
        {"org", config.tls_org},
        {"country", config.tls_country}
    });

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) return false;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) { EVP_PKEY_free(pkey); return false; }

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    X509* x509 = X509_new();
    if (!x509) { EVP_PKEY_free(pkey); return false; }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600);

    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    // All fields from config — no hardcoded values
    if (!config.tls_country.empty())
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
            (unsigned char*)config.tls_country.c_str(), -1, -1, 0);
    if (!config.tls_state.empty())
        X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC,
            (unsigned char*)config.tls_state.c_str(), -1, -1, 0);
    if (!config.tls_locality.empty())
        X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC,
            (unsigned char*)config.tls_locality.c_str(), -1, -1, 0);
    if (!config.tls_org.empty())
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
            (unsigned char*)config.tls_org.c_str(), -1, -1, 0);
    // CN is required
    const std::string cn = config.tls_cn.empty() ? "honeypot.local" : config.tls_cn;
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (unsigned char*)cn.c_str(), -1, -1, 0);

    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }

    FILE* key_file = fopen(key_path.c_str(), "w");
    if (key_file) {
        PEM_write_PrivateKey(key_file, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(key_file);
    }

    FILE* cert_file = fopen(cert_path.c_str(), "w");
    if (cert_file) {
        PEM_write_X509(cert_file, x509);
        fclose(cert_file);
    }

    X509_free(x509);
    EVP_PKEY_free(pkey);

    Logger::instance().log("HTTP", "startup", {
        {"message", "TLS certificate generated"},
        {"cert_path", cert_path},
        {"key_path", key_path}
    });

    return true;
}

// ─── Server start/stop ──────────────────────────────────────────────────────

void HttpHoneypot::start() {
    running_ = true;

    // Auto-generate TLS certificate if needed
    if (config_.enable_https) {
        if (config_.cert_path.empty()) config_.cert_path = "honeypot_cert.pem";
        if (config_.key_path.empty())  config_.key_path = "honeypot_key.pem";

        if (!fs::exists(config_.cert_path) || !fs::exists(config_.key_path)) {
            generate_self_signed_cert(config_.cert_path, config_.key_path, config_);
        }
    }

    // Start HTTP server in a thread
    http_server_ = std::make_unique<httplib::Server>();
    setup_routes(*http_server_);

    std::thread http_thread([this]() {
        Logger::instance().log("HTTP", "startup", {
            {"message", "HTTP server starting"},
            {"address", config_.listen_addr},
            {"port", config_.http_port},
            {"fingerprint", config_.fingerprint_profile},
            {"rotate_sites", config_.rotate_sites}
        });
        http_server_->listen(config_.listen_addr, config_.http_port);
    });
    http_thread.detach();

    // Start HTTPS server if enabled
    if (config_.enable_https) {
        https_server_ = std::make_unique<httplib::SSLServer>(
            config_.cert_path.c_str(), config_.key_path.c_str());
        setup_routes(*https_server_);

        std::thread https_thread([this]() {
            Logger::instance().log("HTTP", "startup", {
                {"message", "HTTPS server starting"},
                {"address", config_.listen_addr},
                {"port", config_.https_port},
                {"cert", config_.cert_path}
            });
            https_server_->listen(config_.listen_addr, config_.https_port);
        });
        https_thread.detach();
    }

    Logger::instance().log("HTTP", "startup", {
        {"message", "HTTP honeypot started successfully"}
    });
}

void HttpHoneypot::stop() {
    if (!running_.exchange(false)) return;

    if (http_server_) http_server_->stop();
    if (https_server_) https_server_->stop();

    Logger::instance().log("HTTP", "shutdown", {
        {"message", "HTTP honeypot stopped"}
    });
}
