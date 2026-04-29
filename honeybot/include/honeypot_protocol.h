#pragma once
#include <string>
#include <atomic>

/// Abstract base class for all honeypot protocol implementations.
/// Subclass this to add new protocols (HTTP, SSH, FTP, SMTP, ...).
class HoneypotProtocol {
public:
    virtual ~HoneypotProtocol() = default;

    /// Human-readable protocol name (e.g., "HTTP", "SSH")
    virtual std::string name() const = 0;

    /// Start the honeypot (blocking). Call from a dedicated thread.
    virtual void start() = 0;

    /// Signal the honeypot to stop gracefully.
    virtual void stop() = 0;

    /// Returns true if the honeypot is currently running.
    virtual bool is_running() const = 0;
};
