// ssh_honeypot.cpp — Stub implementation.
// The SSH honeypot requires a full libssh-based implementation that has not
// yet been written. This stub satisfies the linker so the rest of the
// honeybot (HTTP honeypot + orchestrator forwarder) can be built and run.
// The SSH section in honeypot.json should be set to "enabled": false until
// a real implementation is provided.

#include "ssh_honeypot.h"
#include <iostream>
#include <stdexcept>

SshHoneypot::SshHoneypot(const Config& config) : config_(config) {
    // Not implemented yet.
}

SshHoneypot::~SshHoneypot() {
    stop();
}

void SshHoneypot::start() {
    std::cerr << "[SshHoneypot] SSH honeypot is not yet implemented. "
                 "Set \"ssh\": {\"enabled\": false} in honeypot.json.\n";
}

void SshHoneypot::stop() {
    running_ = false;
}

SshHoneypot::Config SshHoneypot::config_from_json(
    const nlohmann::json& ssh_profile,
    const Config& defaults) {
    Config cfg = defaults;
    cfg.hostname     = ssh_profile.value("hostname",     defaults.hostname);
    cfg.os_version   = ssh_profile.value("os_version",   defaults.os_version);
    cfg.admin_user   = ssh_profile.value("admin_user",   defaults.admin_user);
    cfg.ip_address   = ssh_profile.value("ip_address",   defaults.ip_address);
    cfg.domain       = ssh_profile.value("domain",       defaults.domain);
    cfg.organization = ssh_profile.value("organization", defaults.organization);
    return cfg;
}

// Private methods are not used by the stub but must be present
// (they are called only within start(), which immediately returns).
void SshHoneypot::handle_client(int)         {}
std::string SshHoneypot::execute_command(
    const std::string&, const std::string&, std::string&) { return ""; }
void SshHoneypot::build_fake_filesystem()    {}
const SshHoneypot::FsEntry* SshHoneypot::resolve_path(const std::string&) const { return nullptr; }
std::string SshHoneypot::format_ls_entry(const FsEntry&) const { return ""; }
bool SshHoneypot::generate_host_key(const std::string&) { return false; }
std::string SshHoneypot::current_timestamp() const { return ""; }
