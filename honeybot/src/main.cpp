#include "http_honeypot.h"
#include "ssh_honeypot.h"
#include "logger.h"
#include "orchestrator_forwarder.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <memory>
#include <csignal>
#include <atomic>
#include <filesystem>

namespace fs = std::filesystem;

static std::atomic<bool> g_running{true};
static std::vector<std::unique_ptr<HoneypotProtocol>> g_protocols;

namespace {

const char* envValue(const char* name) {
    const char* value = std::getenv(name);
    return (value && value[0] != '\0') ? value : nullptr;
}

void ensureSection(nlohmann::json& config, const char* section) {
    if (!config.contains(section) || !config[section].is_object()) {
        config[section] = nlohmann::json::object();
    }
}

void setRootString(nlohmann::json& config, const char* key, const char* envName) {
    if (const char* value = envValue(envName)) config[key] = value;
}

void setString(nlohmann::json& config, const char* section,
               const char* key, const char* envName) {
    if (const char* value = envValue(envName)) {
        ensureSection(config, section);
        config[section][key] = value;
    }
}

void setInt(nlohmann::json& config, const char* section,
            const char* key, const char* envName) {
    const char* value = envValue(envName);
    if (!value) return;
    try {
        ensureSection(config, section);
        config[section][key] = std::stoi(value);
    } catch (...) {
        std::cerr << "[!] Ignoring invalid integer env var " << envName
                  << "=" << value << "\n";
    }
}

void setBool(nlohmann::json& config, const char* section,
             const char* key, const char* envName) {
    const char* value = envValue(envName);
    if (!value) return;
    std::string normalized = value;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    ensureSection(config, section);
    if (normalized == "1" || normalized == "true" ||
        normalized == "yes" || normalized == "on") {
        config[section][key] = true;
    } else if (normalized == "0" || normalized == "false" ||
               normalized == "no" || normalized == "off") {
        config[section][key] = false;
    } else {
        std::cerr << "[!] Ignoring invalid boolean env var " << envName
                  << "=" << value << "\n";
    }
}

void applyEnvOverrides(nlohmann::json& config) {
    setRootString(config, "log_file", "HONEYPOT_LOG_FILE");

    setBool(config, "http", "enabled", "HTTP_ENABLED");
    setString(config, "http", "listen_addr", "HTTP_LISTEN_ADDR");
    setInt(config, "http", "http_port", "HTTP_PORT");
    setInt(config, "http", "https_port", "HTTPS_PORT");
    setBool(config, "http", "enable_https", "HTTP_ENABLE_HTTPS");
    setString(config, "http", "cert_path", "HTTP_CERT_PATH");
    setString(config, "http", "key_path", "HTTP_KEY_PATH");
    setString(config, "http", "sites_dir", "SITES_DIR");
    setBool(config, "http", "rotate_sites", "HTTP_ROTATE_SITES");
    setString(config, "http", "active_site", "HTTP_ACTIVE_SITE");

    setBool(config, "ssh", "enabled", "SSH_ENABLED");
    setString(config, "ssh", "listen_addr", "SSH_LISTEN_ADDR");
    setInt(config, "ssh", "port", "SSH_PORT");
    setString(config, "ssh", "host_key_path", "SSH_HOST_KEY_PATH");

    setBool(config, "orchestrator", "enabled", "ORCHESTRATOR_ENABLED");
    setString(config, "orchestrator", "url", "ORCHESTRATOR_URL");
    setString(config, "orchestrator", "node_id", "NODE_ID");
    setString(config, "orchestrator", "jwt_token", "JWT_TOKEN");
    setString(config, "orchestrator", "client_cert", "CLIENT_CERT");
    setString(config, "orchestrator", "client_key", "CLIENT_KEY");
    setString(config, "orchestrator", "ca_cert", "CA_CERT");
    setInt(config, "orchestrator", "batch_size", "FORWARDER_BATCH_SIZE");
    setInt(config, "orchestrator", "flush_interval_sec", "FORWARDER_FLUSH_INTERVAL_SEC");
    setInt(config, "orchestrator", "max_retries", "FORWARDER_MAX_RETRIES");
}

}  // namespace

static void signal_handler(int sig) {
    (void)sig;
    std::cerr << "\n[!] Caught signal, shutting down...\n";
    g_running = false;
    for (auto& p : g_protocols) {
        p->stop();
    }
}

int main(int argc, char* argv[]) {
    // Determine config path
    std::string config_path = "config/honeypot.json";
    if (argc > 1) {
        config_path = argv[1];
    }

    // Load configuration
    nlohmann::json config;
    if (fs::exists(config_path)) {
        std::ifstream f(config_path);
        try {
            f >> config;
        } catch (const std::exception& e) {
            std::cerr << "[!] Failed to parse config: " << e.what() << "\n";
            return 1;
        }
    } else {
        std::cerr << "[*] No config file found at " << config_path
                  << ", using defaults.\n";
        config = nlohmann::json::object();
    }

    applyEnvOverrides(config);

    // Setup logging
    std::string log_file = config.value("log_file", "honeypot.log");
    Logger::instance().set_output_file(log_file);

    Logger::instance().log("MAIN", "startup", {
        {"message", "Honeypot system starting"},
        {"config_path", config_path},
        {"log_file", log_file}
    });

    // ─── Orchestrator Forwarder ──────────────────────────────────────────────
    std::unique_ptr<OrchestratorForwarder> forwarder;
    auto orc_cfg_json = config.value("orchestrator", nlohmann::json::object());
    if (orc_cfg_json.value("enabled", false)) {
        OrchestratorConfig orc_cfg;
        orc_cfg.enabled            = true;
        orc_cfg.url                = orc_cfg_json.value("url", "");
        orc_cfg.node_id            = orc_cfg_json.value("node_id", "");
        orc_cfg.jwt_token          = orc_cfg_json.value("jwt_token", "");
        orc_cfg.client_cert        = orc_cfg_json.value("client_cert", "");
        orc_cfg.client_key         = orc_cfg_json.value("client_key", "");
        orc_cfg.ca_cert            = orc_cfg_json.value("ca_cert", "");
        orc_cfg.batch_size         = orc_cfg_json.value("batch_size", 50);
        orc_cfg.flush_interval_sec = orc_cfg_json.value("flush_interval_sec", 10);
        orc_cfg.max_retries        = orc_cfg_json.value("max_retries", 3);
        forwarder = std::make_unique<OrchestratorForwarder>(orc_cfg);
        Logger::instance().set_forwarder(forwarder.get());
        Logger::instance().log("MAIN", "startup", {
            {"message", "Orchestrator forwarder enabled"},
            {"url",     orc_cfg.url},
            {"node_id", orc_cfg.node_id}
        });
    }

    // ─── HTTP Honeypot ──────────────────────────────────────────────────
    auto http_config_json = config.value("http", nlohmann::json::object());
    std::string sites_dir = http_config_json.value("sites_dir", "./generated_sites");

    // HTTP honeypot pointer so we can query its active SSH profile later
    HttpHoneypot* http_ptr = nullptr;

    if (http_config_json.value("enabled", true)) {
        HttpHoneypot::Config http_cfg;
        http_cfg.listen_addr = http_config_json.value("listen_addr", "0.0.0.0");
        http_cfg.http_port   = http_config_json.value("http_port", 8080);
        http_cfg.https_port  = http_config_json.value("https_port", 8443);
        http_cfg.enable_https = http_config_json.value("enable_https", true);
        http_cfg.cert_path   = http_config_json.value("cert_path", "");
        http_cfg.key_path    = http_config_json.value("key_path", "");
        http_cfg.sites_dir   = sites_dir;
        http_cfg.fingerprint_profile = http_config_json.value(
            "fingerprint_profile", "apache_2_4");
        http_cfg.jitter_min_ms = http_config_json.value("jitter_min_ms", 20);
        http_cfg.jitter_max_ms = http_config_json.value("jitter_max_ms", 200);
        http_cfg.rotate_sites  = http_config_json.value("rotate_sites", false);
        http_cfg.active_site   = http_config_json.value("active_site", "");

        // TLS metadata defaults from config (site JSON fills in the rest)
        auto tls_json = http_config_json.value("tls", nlohmann::json::object());
        http_cfg.tls_cn       = tls_json.value("cn", "");
        http_cfg.tls_org      = tls_json.value("organization", "");
        http_cfg.tls_country  = tls_json.value("country", "");
        http_cfg.tls_state    = tls_json.value("state", "");
        http_cfg.tls_locality = tls_json.value("locality", "");

        auto http_honeypot = std::make_unique<HttpHoneypot>(http_cfg);
        http_ptr = http_honeypot.get();
        g_protocols.push_back(std::move(http_honeypot));
    }

    // ─── SSH Honeypot ───────────────────────────────────────────────────
    auto ssh_config_json = config.value("ssh", nlohmann::json::object());
    if (ssh_config_json.value("enabled", true)) {
        // Build base config from config file
        SshHoneypot::Config ssh_cfg;
        ssh_cfg.listen_addr   = ssh_config_json.value("listen_addr", "0.0.0.0");
        ssh_cfg.port          = ssh_config_json.value("port", 2222);
        ssh_cfg.host_key_path = ssh_config_json.value("host_key_path", "");
        ssh_cfg.banner        = ssh_config_json.value("banner", "");
        ssh_cfg.hostname      = ssh_config_json.value("hostname", "");
        ssh_cfg.os_version    = ssh_config_json.value("os_version", "");
        ssh_cfg.admin_user    = ssh_config_json.value("admin_user", "");
        ssh_cfg.ip_address    = ssh_config_json.value("ip_address", "");
        ssh_cfg.domain        = ssh_config_json.value("domain", "");
        ssh_cfg.organization  = ssh_config_json.value("organization", "");

        // Override with the SSH profile from the HTTP honeypot's active site,
        // so both honeypots present a consistent server identity.
        if (http_ptr) {
            auto ssh_profile = http_ptr->get_active_ssh_profile();
            if (!ssh_profile.is_null() && ssh_profile.is_object()) {
                ssh_cfg = SshHoneypot::config_from_json(ssh_profile, ssh_cfg);
                Logger::instance().log("MAIN", "startup", {
                    {"message", "SSH config loaded from active HTTP site"},
                    {"hostname", ssh_cfg.hostname},
                    {"admin_user", ssh_cfg.admin_user}
                });
            }
        }

        g_protocols.push_back(std::make_unique<SshHoneypot>(ssh_cfg));
    }

    if (g_protocols.empty()) {
        std::cerr << "[!] No protocols enabled. Exiting.\n";
        return 1;
    }

    // Start all protocols in their own threads
    std::vector<std::thread> threads;
    for (auto& protocol : g_protocols) {
        Logger::instance().log("MAIN", "startup", {
            {"message", "Starting " + protocol->name() + " honeypot"}
        });
        threads.emplace_back([&protocol]() {
            protocol->start();
        });
    }

    // Register signal handlers for graceful shutdown
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Wait for shutdown signal
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Stop all protocols
    for (auto& protocol : g_protocols) {
        protocol->stop();
    }

    // Wait for threads to finish
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    Logger::instance().log("MAIN", "shutdown", {
        {"message", "Honeypot system stopped"}
    });

    return 0;
}
