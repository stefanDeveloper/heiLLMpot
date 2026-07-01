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
    // Add realistic timing jitter
    add_timing_jitter();

    std::string session_id = get_or_create_session(req, res);

    // Apply server fingerprint headers
    apply_fingerprint(res);

    SiteData* active_site = get_active_site();
    if (!active_site) {
        res.status = 503;
        res.set_content(generate_error_page(503, "Service Temporarily Unavailable"),
                        "text/html; charset=utf-8");
        // Log with status now known
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

    // Handle login POST — update session state and log credentials
    if (req.path == "/login" && method == "POST") {
        // Parse individual form fields from URL-encoded body
        std::string login_user, login_pass;
        auto u_it = req.params.find("username");
        if (u_it != req.params.end()) login_user = u_it->second;
        auto p_it = req.params.find("password");
        if (p_it != req.params.end()) login_pass = p_it->second;

        {
            std::lock_guard<std::mutex> lock(session_mutex_);
            if (sessions_.count(session_id)) {
                sessions_[session_id].authenticated = true;
                sessions_[session_id].username = login_user;
            }
        }

        nlohmann::json login_log = {
            {"client_ip",  req.remote_addr},
            {"session_id", session_id},
            {"site_id",    active_site->site_id},
            {"username",   login_user},
            {"password",   login_pass}
        };
        // Keep raw body as fallback for non-standard encodings
        if (!req.body.empty()) {
            login_log["post_body"] = req.body.substr(0, 512);
        }
        Logger::instance().log("HTTP", "login", login_log);

        // Redirect on successful login POST to the first authenticated route
        std::string redirect_target = "/";
        for (const auto& [r_path, r_auth] : active_site->auth_required) {
            if (r_auth) {
                redirect_target = r_path;
                break;
            }
        }
        res.status = 302;
        res.set_header("Location", redirect_target);
        res.set_content("Redirecting to " + redirect_target + "...", "text/plain");
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

void HttpHoneypot::add_timing_jitter() {
    std::uniform_int_distribution<int> dist(config_.jitter_min_ms,
                                             config_.jitter_max_ms);
    int delay;
    {
        std::lock_guard<std::mutex> lock(site_mutex_);  // protect rng_
        delay = dist(rng_);
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

    // Inject a dynamic timestamp comment (makes each response unique)
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf = gmtime_safe(&t);
    char timebuf[64];
    std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_buf);

    size_t body_close = result.rfind("</body>");
    if (body_close != std::string::npos) {
        std::string comment = "<!-- generated " + std::string(timebuf) +
                              " sid:" + session_id.substr(0, 8) + " -->\n";
        result.insert(body_close, comment);
    }

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
