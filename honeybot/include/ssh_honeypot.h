#pragma once
#include "honeypot_protocol.h"
#include "logger.h"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <thread>

/// SSH honeypot using libssh.
/// Accepts all credentials (logs them), provides a fake shell
/// with a small set of commands and an in-memory filesystem.
class SshHoneypot : public HoneypotProtocol {
public:
    struct Config {
        std::string listen_addr = "0.0.0.0";
        int port = 22;
        std::string host_key_path;  // Empty = auto-generate RSA key
        std::string banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5";

        // System identity — all configurable, no hardcoded values
        std::string hostname = "webserver01";
        std::string os_version = "Ubuntu 24.04.1 LTS";
        std::string os_codename = "Noble Numbat";
        std::string kernel = "6.8.0-45-generic";
        std::string ip_address = "10.0.1.42";
        std::string netmask = "255.255.255.0";
        std::string broadcast = "10.0.1.255";
        std::string gateway = "10.0.1.1";
        std::string mac_address = "52:54:00:ab:cd:ef";
        std::vector<std::string> dns_servers = {"8.8.8.8", "8.8.4.4"};
        std::string dns_search = "example.com";

        // User identity
        std::string admin_user = "admin";
        std::string admin_display = "System Admin";
        std::string admin_home = "/home/admin";
        int admin_uid = 1000;
        int admin_gid = 1000;
        std::vector<std::string> admin_groups = {"sudo", "www-data", "adm"};

        // Services and context
        std::vector<std::string> services = {"sshd", "apache2", "mysql"};
        std::vector<std::string> installed_packages = {};
        std::string organization = "Example Organization";
        std::string domain = "example.com";
        std::string last_login_ip = "10.0.0.1";
        std::string last_login_date = "Mon Mar 17 09:15:23 2026";
        std::vector<std::string> recent_auth_entries = {};
        std::vector<std::string> motd_extra = {};

        // Filesystem customization
        std::vector<std::string> admin_bash_history = {
            "sudo apt update", "sudo systemctl status apache2",
            "df -h", "htop", "ss -tlnp"
        };
        std::string admin_notes = "";
    };

    explicit SshHoneypot(const Config& config);
    ~SshHoneypot() override;

    std::string name() const override { return "SSH"; }
    void start() override;
    void stop() override;
    bool is_running() const override { return running_.load(); }

    /// Load configuration from a site JSON's ssh_profile section
    static Config config_from_json(const nlohmann::json& ssh_profile,
                                    const Config& defaults);

private:
    // ─── Fake filesystem ────────────────────────────────────────────────
    struct FsEntry {
        std::string name;
        bool is_dir = false;
        std::string content;  // For files
        std::string owner = "root";
        std::string group = "root";
        std::string perms = "-rw-r--r--";
        size_t size = 0;
        std::vector<FsEntry> children;  // For directories
    };

    // ─── Methods ────────────────────────────────────────────────────────
    void handle_client(int client_fd);
    std::string execute_command(const std::string& cmd,
                                const std::string& cwd,
                                std::string& new_cwd);
    void build_fake_filesystem();
    const FsEntry* resolve_path(const std::string& path) const;
    std::string format_ls_entry(const FsEntry& entry) const;
    bool generate_host_key(const std::string& path);
    std::string current_timestamp() const;

    // ─── Data ───────────────────────────────────────────────────────────
    Config config_;
    FsEntry fs_root_;
    std::atomic<bool> running_{false};
    int server_fd_ = -1;
    std::vector<std::thread> client_threads_;
    std::mutex threads_mutex_;
};
