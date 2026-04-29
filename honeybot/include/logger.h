#pragma once
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>

// Full include needed because log() calls forwarder_->enqueue()
#include "orchestrator_forwarder.h"

/// Thread-safe structured JSON logger.
/// Writes one JSON object per line (JSONL format) for easy parsing.
class Logger {
public:
    static Logger& instance() {
        static Logger logger;
        return logger;
    }

    void set_output_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (file_.is_open()) file_.close();
        file_.open(path, std::ios::app);
        if (!file_.is_open()) {
            std::cerr << "[!] Failed to open log file: " << path << "\n";
        }
    }

    /// Set the orchestrator forwarder to ship events remotely.
    /// Pass nullptr to disable forwarding.
    void set_forwarder(OrchestratorForwarder* fwd) {
        std::lock_guard<std::mutex> lock(mtx_);
        forwarder_ = fwd;
    }

    /// Log a structured event.
    void log(const std::string& protocol,
             const std::string& event_type,
             const nlohmann::json& data = {}) {
        nlohmann::json entry;
        entry["timestamp"] = now_iso8601();
        entry["protocol"] = protocol;
        entry["event"] = event_type;
        if (!data.empty()) {
            entry["data"] = data;
        }

        std::lock_guard<std::mutex> lock(mtx_);
        std::string line = entry.dump();

        // Write to file
        if (file_.is_open()) {
            file_ << line << "\n";
            file_.flush();
        }

        // Forward to orchestrator (non-blocking enqueue)
        if (forwarder_) {
            forwarder_->enqueue(entry);
        }

        // Write to stderr (colorized one-liner)
        std::cerr << color_for(event_type) << "[" << protocol << "] "
                  << event_type << "\033[0m";
        if (data.contains("client_ip")) {
            std::cerr << " from " << data["client_ip"].get<std::string>();
        }
        if (data.contains("path")) {
            std::cerr << " " << data["path"].get<std::string>();
        }
        if (data.contains("status_code")) {
            std::cerr << " " << data["status_code"].get<int>();
        }
        if (data.contains("username")) {
            std::cerr << " user=" << data["username"].get<std::string>();
        }
        if (data.contains("password")) {
            std::cerr << " pass=" << data["password"].get<std::string>();
        }
        if (data.contains("connection_id")) {
            std::cerr << " conn=" << data["connection_id"].get<std::string>().substr(0, 8);
        } else if (data.contains("session_id")) {
            std::cerr << " sess=" << data["session_id"].get<std::string>().substr(0, 8);
        }
        if (data.contains("command")) {
            std::cerr << " $ " << data["command"].get<std::string>();
        }
        if (data.contains("message")) {
            std::cerr << " " << data["message"].get<std::string>();
        }
        std::cerr << "\n";
    }

private:
    Logger() = default;
    std::mutex mtx_;
    std::ofstream file_;
    OrchestratorForwarder* forwarder_ = nullptr;

    static std::string now_iso8601() {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        struct tm tm_buf;
        gmtime_r(&t, &tm_buf);
        std::ostringstream ss;
        ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S")
           << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
        return ss.str();
    }

    static const char* color_for(const std::string& event) {
        if (event == "request")      return "\033[36m";   // cyan
        if (event == "login")        return "\033[33m";   // yellow
        if (event == "credential")   return "\033[31m";   // red
        if (event == "command")      return "\033[35m";   // magenta
        if (event == "startup")      return "\033[32m";   // green
        if (event == "shutdown")     return "\033[32m";   // green
        if (event == "disconnect")   return "\033[90m";   // dark grey
        if (event == "rotation")     return "\033[34m";   // blue
        if (event == "error")        return "\033[91m";   // bright red
        return "\033[0m";
    }
};
