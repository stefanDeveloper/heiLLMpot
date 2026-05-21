#include "orchestrator_forwarder.h"
#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>

namespace {

struct ParsedUrl {
    bool https = false;
    std::string host;
    int port = 80;
};

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return value;
}

std::string normalizeProtocol(const std::string& value) {
    auto protocol = lower(value);
    if (protocol == "http" || protocol == "ssh") return protocol;
    return "unknown";
}

std::string normalizeEventType(const std::string& value) {
    auto eventType = lower(value);
    if (eventType == "login") return "credential";
    return eventType;
}

bool isForwardableEvent(const std::string& eventType) {
    return eventType == "request" ||
           eventType == "credential" ||
           eventType == "command" ||
           eventType == "connect" ||
           eventType == "disconnect";
}

std::string stringField(const nlohmann::json& value, const char* key) {
    auto it = value.find(key);
    if (it == value.end() || !it->is_string()) return "";
    return it->get<std::string>();
}

std::string firstSessionRef(const nlohmann::json& value) {
    for (const char* key : {"session_ref", "session_id", "connection_id"}) {
        auto candidate = stringField(value, key);
        if (!candidate.empty()) return candidate;
    }
    return "";
}

int parsePort(const std::string& value, int fallback) {
    try {
        size_t parsed = 0;
        int port = std::stoi(value, &parsed);
        if (parsed == value.size() && port > 0 && port <= 65535) {
            return port;
        }
    } catch (...) {
    }
    return fallback;
}

ParsedUrl parseOrchestratorUrl(const std::string& url) {
    ParsedUrl parsed;
    std::string rest = url;

    if (rest.rfind("https://", 0) == 0) {
        parsed.https = true;
        parsed.port = 443;
        rest = rest.substr(8);
    } else if (rest.rfind("http://", 0) == 0) {
        rest = rest.substr(7);
    }

    auto slash = rest.find('/');
    if (slash != std::string::npos) {
        rest = rest.substr(0, slash);
    }

    if (!rest.empty() && rest.front() == '[') {
        auto close = rest.find(']');
        if (close != std::string::npos) {
            parsed.host = rest.substr(1, close - 1);
            if (close + 1 < rest.size() && rest[close + 1] == ':') {
                parsed.port = parsePort(rest.substr(close + 2), parsed.port);
            }
            return parsed;
        }
    }

    auto colon = rest.rfind(':');
    if (colon != std::string::npos && rest.find(':') == colon) {
        parsed.host = rest.substr(0, colon);
        parsed.port = parsePort(rest.substr(colon + 1), parsed.port);
    } else {
        parsed.host = rest;
    }

    return parsed;
}

}  // namespace

// ─── Construction / destruction ───────────────────────────────────────────────

OrchestratorForwarder::OrchestratorForwarder(const OrchestratorConfig& cfg)
    : m_cfg(cfg) {
    if (!cfg.enabled) return;
    buildClient();
    m_running = true;
    m_thread  = std::thread(&OrchestratorForwarder::loop, this);
}

OrchestratorForwarder::~OrchestratorForwarder() { stop(); }

void OrchestratorForwarder::stop() {
    if (!m_running.exchange(false)) return;
    m_cv.notify_all();
    if (m_thread.joinable()) m_thread.join();
}

// ─── Build the HTTP/HTTPS post function ───────────────────────────────────────

void OrchestratorForwarder::buildClient() {
    const std::string& url = m_cfg.url;
    const auto endpoint = parseOrchestratorUrl(url);

    if (endpoint.https) {
        // Build an SSLClient and capture it in the lambda.
        auto ssl = [&]() -> std::shared_ptr<httplib::SSLClient> {
            std::shared_ptr<httplib::SSLClient> c;
            if (!m_cfg.client_cert.empty() && !m_cfg.client_key.empty()) {
                c = std::make_shared<httplib::SSLClient>(
                    endpoint.host, endpoint.port, m_cfg.client_cert, m_cfg.client_key);
            } else {
                c = std::make_shared<httplib::SSLClient>(endpoint.host, endpoint.port);
            }
            if (!m_cfg.ca_cert.empty()) {
                c->set_ca_cert_path(m_cfg.ca_cert.c_str());
                c->enable_server_certificate_verification(true);
            } else {
                c->enable_server_certificate_verification(false);
            }
            c->set_connection_timeout(10);
            c->set_read_timeout(15);
            return c;
        }();

        m_post = [ssl](const std::string& path,
                       const httplib::Headers& headers,
                       const std::string& body,
                       const std::string& content_type) -> httplib::Result {
            return ssl->Post(path, headers, body, content_type);
        };
    } else {
        // Plain HTTP — used for local development.
        auto cli = std::make_shared<httplib::Client>(endpoint.host, endpoint.port);
        cli->set_connection_timeout(10);
        cli->set_read_timeout(15);

        m_post = [cli](const std::string& path,
                       const httplib::Headers& headers,
                       const std::string& body,
                       const std::string& content_type) -> httplib::Result {
            return cli->Post(path, headers, body, content_type);
        };
    }
}

// ─── Enqueue ──────────────────────────────────────────────────────────────────

void OrchestratorForwarder::enqueue(const nlohmann::json& entry) {
    if (!m_running) return;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push_back(entry);
    }
    if ((int)m_queue.size() >= m_cfg.batch_size) {
        m_cv.notify_one();  // wake flusher immediately
    }
}

// ─── Background loop ──────────────────────────────────────────────────────────

void OrchestratorForwarder::loop() {
    while (m_running) {
        std::deque<nlohmann::json> batch;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait_for(lock,
                std::chrono::seconds(m_cfg.flush_interval_sec),
                [this] {
                    return !m_running ||
                           (int)m_queue.size() >= m_cfg.batch_size;
                });
            if (m_queue.empty()) continue;
            batch.swap(m_queue);
        }
        flush(batch);
    }

    // Drain remaining entries on shutdown
    std::deque<nlohmann::json> remaining;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        remaining.swap(m_queue);
    }
    if (!remaining.empty()) flush(remaining);
}

// ─── Flush ────────────────────────────────────────────────────────────────────

void OrchestratorForwarder::flush(std::deque<nlohmann::json>& batch) {
    if (batch.empty()) return;

    nlohmann::json payload = nlohmann::json::object();
    payload["events"] = nlohmann::json::array();

    for (auto& entry : batch) {
        nlohmann::json ev = entry.value("data", nlohmann::json::object());
        if (!ev.is_object()) continue;

        const auto protocol = normalizeProtocol(entry.value("protocol", "unknown"));
        const auto eventType = normalizeEventType(entry.value("event", ""));
        const auto sessionRef = firstSessionRef(ev);

        if (!isForwardableEvent(eventType) || sessionRef.empty()) {
            continue;
        }

        ev["node_id"]    = m_cfg.node_id;
        ev["protocol"]   = protocol;
        ev["event_type"] = eventType;
        ev["timestamp"]  = entry.value("timestamp", "");
        ev["session_ref"] = sessionRef;
        ev["raw_json"]   = entry.dump();
        payload["events"].push_back(std::move(ev));
    }

    if (payload["events"].empty()) return;

    if (!postBatch(payload)) {
        // Re-queue on failure (drop oldest if queue is huge to avoid OOM)
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto& e : batch) {
            if ((int)m_queue.size() < 5000) {
                m_queue.push_front(e);
            }
        }
    }
}

// ─── HTTP POST ────────────────────────────────────────────────────────────────

bool OrchestratorForwarder::postBatch(const nlohmann::json& payload, int attempt) {
    if (!m_post) return false;

    httplib::Headers headers = {
        {"Content-Type",  "application/json"},
        {"Authorization", "Bearer " + m_cfg.jwt_token}
    };

    auto res = m_post("/api/v1/events", headers, payload.dump(), "application/json");
    if (res && res->status == 200) return true;

    int status = res ? res->status : -1;
    std::cerr << "[OrchestratorForwarder] POST /api/v1/events failed"
              << " (attempt " << attempt << "/" << m_cfg.max_retries
              << ", status=" << status << ")\n";

    if (attempt < m_cfg.max_retries) {
        std::this_thread::sleep_for(
            std::chrono::seconds(1 << attempt));  // exponential back-off
        return postBatch(payload, attempt + 1);
    }
    return false;
}
