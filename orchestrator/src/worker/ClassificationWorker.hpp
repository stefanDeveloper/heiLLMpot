#pragma once

#include "../db/DbClient.hpp"
#include "../ConfigComponent.hpp"
#include "oatpp/core/macro/component.hpp"

#include <atomic>
#include <thread>
#include <memory>

/// Background worker thread that periodically:
///  1. Fetches sessions that have no classification yet.
///  2. Loads their events from the DB.
///  3. Applies simple heuristic rules to classify each session as bot/human/unknown.
///  4. Stores the result back to bot_classifications.
class ClassificationWorker {
public:
    explicit ClassificationWorker(std::shared_ptr<DbClient> db);
    ~ClassificationWorker();

    void start();
    void stop();

private:
    void loop();
    void processSession(const std::string& session_uuid);

    std::shared_ptr<DbClient>  m_db;
    std::atomic<bool>          m_running{false};
    std::thread                m_thread;
    OATPP_COMPONENT(std::shared_ptr<OrchestratorConfig>, m_config);
};
