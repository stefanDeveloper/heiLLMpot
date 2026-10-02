#include "ClassificationWorker.hpp"
#include "oatpp/core/base/Environment.hpp"

#include <chrono>
#include <nlohmann/json.hpp>

ClassificationWorker::ClassificationWorker(std::shared_ptr<DbClient> db)
    : m_db(std::move(db)) {}

ClassificationWorker::~ClassificationWorker() { stop(); }

void ClassificationWorker::start() {
    m_running = true;
    m_thread  = std::thread(&ClassificationWorker::loop, this);
    OATPP_LOGI("Worker", "ClassificationWorker started (interval=%ds)",
               m_config->worker_interval_sec);
}

void ClassificationWorker::stop() {
    m_running = false;
    if (m_thread.joinable()) m_thread.join();
}

void ClassificationWorker::loop() {
    int iterCount = 0;
    while (m_running) {
        try {
            if (iterCount % 10 == 0 && m_config->retention_days > 0) {
                m_db->pruneOldSessions(m_config->retention_days);
                m_db->pruneBySize(m_config->max_db_size_gb);
            }
            iterCount++;

            auto ids = m_db->getUnclassifiedSessionIds(100);
            for (auto& uuid : ids) {
                if (!m_running) break;
                processSession(uuid);
            }
            if (!ids.empty()) {
                OATPP_LOGI("Worker", "Classified %zu sessions", ids.size());
            }
        } catch (const std::exception& e) {
            OATPP_LOGE("Worker", "Error during classification loop: %s", e.what());
        }

        // Sleep in 1-second intervals so we can stop cleanly
        for (int i = 0; i < m_config->worker_interval_sec && m_running; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void ClassificationWorker::processSession(const std::string& session_uuid) {
    auto events = m_db->getSessionEventJsons(session_uuid);
    if (events.empty()) return;

    // Simple heuristic rules:
    //  - >= 10 events in a session → likely bot (high-frequency scanning)
    //  - credential events present → bot (automated brute-force)
    //  - otherwise → unknown
    std::string label  = "unknown";
    double      conf   = 0.5;
    std::string method = "rules";
    std::vector<std::string> triggered;

    int credCount = 0;
    for (auto& raw : events) {
        try {
            auto j = nlohmann::json::parse(raw);
            if (j.value("event_type", "") == "credential") ++credCount;
        } catch (...) {}
    }

    if ((int)events.size() >= 10) {
        label = "bot";
        conf  = 0.75;
        triggered.push_back("high_event_count");
    }
    if (credCount > 0) {
        label = "bot";
        conf  = std::max(conf, 0.80);
        triggered.push_back("credential_attempt");
    }

    nlohmann::json features = {
        {"event_count",  (int)events.size()},
        {"cred_count",   credCount}
    };

    m_db->upsertClassification(session_uuid, label, conf, method,
                                features.dump(), triggered);
}
