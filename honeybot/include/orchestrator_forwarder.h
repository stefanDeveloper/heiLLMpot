#pragma once

#include <nlohmann/json.hpp>
#include <httplib.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <variant>

/// Configuration for the forwarding agent.
struct OrchestratorConfig {
    bool        enabled          = false;
    std::string url;                             // "http://host:port" or "https://host:port"
    std::string node_id;                         // e.g. "node-eu-west-1"
    std::string jwt_token;                       // Bearer token from node registration
    std::string client_cert;                     // path to mTLS client cert (https only)
    std::string client_key;                      // path to mTLS client key  (https only)
    std::string ca_cert;                         // path to CA cert for server verification
    int         batch_size         = 50;         // flush when queue reaches this size
    int         flush_interval_sec = 10;         // flush at least every N seconds
    int         max_retries        = 3;
};

/// Thread-safe async forwarder.
/// Collects JSONL log entries from the Logger and ships them in batches
/// to the central orchestrator via HTTP or HTTPS (mTLS + JWT).
class OrchestratorForwarder {
public:
    explicit OrchestratorForwarder(const OrchestratorConfig& cfg);
    ~OrchestratorForwarder();

    /// Enqueue a single log entry; returns immediately (non-blocking).
    void enqueue(const nlohmann::json& entry);

    /// Flush any remaining entries and stop the background thread.
    void stop();

private:
    void loop();
    void flush(std::deque<nlohmann::json>& batch);
    bool postBatch(const nlohmann::json& payload, int attempt = 1);

    OrchestratorConfig              m_cfg;
    std::deque<nlohmann::json>      m_queue;
    std::mutex                      m_mutex;
    std::condition_variable         m_cv;
    std::atomic<bool>               m_running{false};
    std::thread                     m_thread;

    // Holds either a plain HTTP client or an HTTPS/mTLS client.
    // httplib::Client (HTTP) and httplib::SSLClient (HTTPS) are not
    // related by inheritance from the user's perspective, so we use
    // a variant and dispatch via a lambda.
    using PostFn = std::function<httplib::Result(
        const std::string& path,
        const httplib::Headers& headers,
        const std::string& body,
        const std::string& content_type)>;

    PostFn m_post;
    void   buildClient();
};
