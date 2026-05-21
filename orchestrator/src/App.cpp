/**
 * Honeypot Orchestrator — Main Application
 *
 * Central collection point for worldwide honeypot nodes.
 * Built with Oat++ REST framework + PostgreSQL.
 */

#include "AppComponent.hpp"
#include "ConfigComponent.hpp"
#include "DatabaseComponent.hpp"
#include "ErrorHandler.hpp"
#include "SwaggerComponent.hpp"

#include "auth/NodeAuthInterceptor.hpp"
#include "controller/EventController.hpp"
#include "controller/HealthController.hpp"
#include "controller/NodeController.hpp"
#include "controller/StatsController.hpp"
#include "controller/SessionController.hpp"
#include "db/DbClient.hpp"
#include "worker/ClassificationWorker.hpp"

#include "oatpp-swagger/Controller.hpp"
#include "oatpp/network/Server.hpp"

#include <nlohmann/json.hpp>
#include <fstream>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <atomic>

std::atomic<bool> g_running{true};

void signalHandler(int sig) {
    OATPP_LOGI("App", "Received signal %d, shutting down...", sig);
    g_running = false;
}

namespace {

std::string envString(const char* name, const std::string& current) {
    const char* value = std::getenv(name);
    if (!value || value[0] == '\0') return current;
    return value;
}

int envInt(const char* name, int current) {
    const char* value = std::getenv(name);
    if (!value || value[0] == '\0') return current;
    try {
        return std::stoi(value);
    } catch (...) {
        std::cerr << "[!] Ignoring invalid integer env var " << name
                  << "=" << value << "\n";
        return current;
    }
}

void applyEnvOverrides(const std::shared_ptr<OrchestratorConfig>& cfg) {
    cfg->listen_addr         = envString("LISTEN_ADDR", cfg->listen_addr);
    cfg->port                = envInt("PORT", cfg->port);
    cfg->jwt_secret          = envString("JWT_SECRET", cfg->jwt_secret);
    cfg->jwt_expiry_hours    = envInt("JWT_EXPIRY_HOURS", cfg->jwt_expiry_hours);
    cfg->db_host             = envString("DB_HOST", cfg->db_host);
    cfg->db_port             = envInt("DB_PORT", cfg->db_port);
    cfg->db_name             = envString("DB_NAME", cfg->db_name);
    cfg->db_user             = envString("DB_USER", cfg->db_user);
    cfg->db_password         = envString("DB_PASSWORD", cfg->db_password);
    cfg->geoip_db_path       = envString("GEOIP_DB_PATH", cfg->geoip_db_path);
    cfg->geoip_asn_path      = envString("GEOIP_ASN_PATH", cfg->geoip_asn_path);
    cfg->worker_interval_sec = envInt("WORKER_INTERVAL_SEC", cfg->worker_interval_sec);
}

}  // namespace

void loadConfig(const std::string& path,
                const std::shared_ptr<OrchestratorConfig>& cfg) {
    std::ifstream f(path);
    if (!f) {
        std::cerr << "[!] Config file not found: " << path
                  << " — using defaults and environment overrides\n";
        applyEnvOverrides(cfg);
        return;
    }
    nlohmann::json j;
    f >> j;

    cfg->listen_addr          = j.value("listen_addr",           cfg->listen_addr);
    cfg->port                 = j.value("port",                  cfg->port);
    cfg->jwt_secret           = j.value("jwt_secret",            cfg->jwt_secret);
    cfg->jwt_expiry_hours     = j.value("jwt_expiry_hours",      cfg->jwt_expiry_hours);
    cfg->db_host              = j.value("db_host",               cfg->db_host);
    cfg->db_port              = j.value("db_port",               cfg->db_port);
    cfg->db_name              = j.value("db_name",               cfg->db_name);
    cfg->db_user              = j.value("db_user",               cfg->db_user);
    cfg->db_password          = j.value("db_password",           cfg->db_password);
    cfg->geoip_db_path        = j.value("geoip_db_path",         cfg->geoip_db_path);
    cfg->geoip_asn_path       = j.value("geoip_asn_path",        cfg->geoip_asn_path);
    cfg->worker_interval_sec  = j.value("worker_interval_sec",   cfg->worker_interval_sec);

    applyEnvOverrides(cfg);
}

void run(const std::string& configPath) {
    std::signal(SIGINT,  signalHandler);
    std::signal(SIGTERM, signalHandler);

    // ── DI Components ─────────────────────────────────────────────────────────
    ConfigComponent configComponent;
    OATPP_COMPONENT(std::shared_ptr<OrchestratorConfig>, cfg);
    loadConfig(configPath, cfg);

    AppComponent appComponent;   // uses cfg->listen_addr / cfg->port

    // ── Database ──────────────────────────────────────────────────────────────────────────────────
    DatabaseComponent dbComponent;  // registers DbClient, runs migration
    OATPP_COMPONENT(std::shared_ptr<DbClient>, db);
    OATPP_LOGI("App", "Database connected and schema applied");

    // ── Swagger components (must be before swagger controller) ────────────────────────────────────
    SwaggerComponent swaggerComponent;

    // ── Router ────────────────────────────────────────────────────────────────
    OATPP_COMPONENT(std::shared_ptr<oatpp::web::server::HttpRouter>, router);

    oatpp::web::server::api::Endpoints docEndpoints;

    auto healthController = HealthController::createShared();
    router->addController(healthController);
    docEndpoints.append(healthController->getEndpoints());

    auto nodeController    = NodeController::createShared();
    router->addController(nodeController);
    docEndpoints.append(nodeController->getEndpoints());

    auto eventController   = EventController::createShared();
    router->addController(eventController);
    docEndpoints.append(eventController->getEndpoints());

    auto statsController   = StatsController::createShared();
    router->addController(statsController);
    docEndpoints.append(statsController->getEndpoints());

    auto sessionController = SessionController::createShared();
    router->addController(sessionController);
    docEndpoints.append(sessionController->getEndpoints());

    // Swagger UI
    auto swaggerController = oatpp::swagger::Controller::createShared(docEndpoints);
    router->addController(swaggerController);

    // ── Connection handler with auth interceptor ───────────────────────────────
    auto authInterceptor = std::make_shared<NodeAuthInterceptor>();
    auto connectionHandler = oatpp::web::server::HttpConnectionHandler::createShared(router);
    connectionHandler->addRequestInterceptor(authInterceptor);

    OATPP_COMPONENT(std::shared_ptr<oatpp::data::mapping::ObjectMapper>, mapper);
    connectionHandler->setErrorHandler(std::make_shared<ErrorHandler>(mapper));

    // ── Background classification worker ──────────────────────────────────────
    ClassificationWorker worker(db);
    worker.start();

    // ── Server ────────────────────────────────────────────────────────────────
    OATPP_COMPONENT(std::shared_ptr<oatpp::network::ServerConnectionProvider>, provider);
    oatpp::network::Server server(provider, connectionHandler);

    OATPP_LOGI("App", "=======================================================");
    OATPP_LOGI("App", "  Honeybot Orchestrator v1.0.0");
    OATPP_LOGI("App", "=======================================================");
    OATPP_LOGI("App", "  Listening on http://%s:%d",
               cfg->listen_addr.c_str(), cfg->port);
    OATPP_LOGI("App", "  Swagger UI: http://%s:%d/swagger/ui",
               cfg->listen_addr.c_str(), cfg->port);
    OATPP_LOGI("App", "=======================================================");
    OATPP_LOGI("App", "  POST /api/v1/nodes/register  (public)");
    OATPP_LOGI("App", "  GET  /api/v1/nodes            (auth)");
    OATPP_LOGI("App", "  POST /api/v1/events           (auth)");
    OATPP_LOGI("App", "  GET  /api/v1/stats            (auth)");
    OATPP_LOGI("App", "  GET  /api/v1/sessions         (auth)");
    OATPP_LOGI("App", "=======================================================");

    std::thread serverThread([&server]() { server.run(); });

    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    worker.stop();
    server.stop();
    provider->stop();

    if (serverThread.joinable()) serverThread.join();
    OATPP_LOGI("App", "Orchestrator stopped gracefully");
}

int main(int argc, const char* argv[]) {
    std::string configPath = "config/orchestrator.json";
    if (argc > 1) configPath = argv[1];

    oatpp::base::Environment::init();
    try {
        run(configPath);
    } catch (const std::exception& e) {
        OATPP_LOGE("App", "Fatal error: %s", e.what());
        oatpp::base::Environment::destroy();
        return 1;
    }
    oatpp::base::Environment::destroy();
    return 0;
}
