#pragma once

#include <memory>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <condition_variable>
#include <queue>
#include <string>

namespace nosql_db::network {

/**
 * Session information for client connections
 */
struct ClientSession {
    std::string session_id;
    std::string client_address;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_activity;
    std::atomic<uint64_t> total_requests{0};
    std::atomic<uint64_t> total_responses{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<bool> authenticated{false};
    std::unordered_map<std::string, std::string> metadata;
    
    ClientSession(const std::string& id, const std::string& addr)
        : session_id(id), client_address(addr),
          created_at(std::chrono::steady_clock::now()),
          last_activity(std::chrono::steady_clock::now()) {}
};

/**
 * Connection pool with session management and resource limits
 */
class ConnectionPool {
public:
    struct PoolConfig {
        size_t max_connections = 1000;
        std::chrono::seconds session_timeout{300};     // 5 minutes
        std::chrono::seconds idle_timeout{60};         // 1 minute
        std::chrono::seconds cleanup_interval{30};     // 30 seconds
        size_t max_connections_per_ip = 100;
        bool enable_rate_limiting = true;
        size_t requests_per_second_limit = 1000;
        size_t burst_limit = 100;
    };

    explicit ConnectionPool(const PoolConfig& config);
    ~ConnectionPool();

    // Disable copy/move
    ConnectionPool(const ConnectionPool&) = delete;
    ConnectionPool& operator=(const ConnectionPool&) = delete;

    // Connection management
    bool can_accept_connection(const std::string& client_ip) const;
    std::string create_session(int socket_fd, const std::string& client_address);
    bool remove_session(const std::string& session_id);
    std::shared_ptr<ClientSession> get_session(const std::string& session_id);
    
    // Activity tracking
    void update_session_activity(const std::string& session_id);
    void record_request(const std::string& session_id, size_t bytes_received);
    void record_response(const std::string& session_id, size_t bytes_sent);
    
    // Rate limiting
    bool check_rate_limit(const std::string& client_ip);
    void reset_rate_limits();
    
    // Statistics and monitoring
    struct PoolStats {
        std::atomic<size_t> total_sessions{0};
        std::atomic<size_t> active_sessions{0};
        std::atomic<size_t> expired_sessions{0};
        std::atomic<size_t> rate_limited_requests{0};
        std::atomic<uint64_t> total_bytes_sent{0};
        std::atomic<uint64_t> total_bytes_received{0};
    };
    
    const PoolStats& stats() const { return stats_; }
    std::vector<std::string> get_active_session_ids() const;
    size_t get_connections_by_ip(const std::string& client_ip) const;
    
    // Configuration
    const PoolConfig& config() const { return config_; }
    void set_max_connections(size_t max_conn);
    void set_session_timeout(std::chrono::seconds timeout);
    
    // Lifecycle
    void start_cleanup();
    void stop_cleanup();
    
    // Utility methods (public for ManagedConnection)
    std::string extract_ip_from_address(const std::string& address) const;

private:
    PoolConfig config_;
    mutable std::shared_mutex sessions_mutex_;
    std::unordered_map<std::string, std::shared_ptr<ClientSession>> sessions_;
    std::unordered_map<int, std::string> fd_to_session_;
    
    // Rate limiting
    struct RateLimitInfo {
        std::chrono::steady_clock::time_point window_start;
        std::atomic<size_t> request_count{0};
        std::atomic<size_t> burst_tokens{0};
    };
    
    mutable std::mutex rate_limit_mutex_;
    std::unordered_map<std::string, RateLimitInfo> rate_limits_;
    
    // IP-based connection tracking
    mutable std::shared_mutex ip_connections_mutex_;
    std::unordered_map<std::string, size_t> connections_per_ip_;
    
    // Statistics
    PoolStats stats_;
    
    // Cleanup thread
    std::thread cleanup_thread_;
    std::atomic<bool> cleanup_running_{false};
    std::condition_variable cleanup_cv_;
    std::mutex cleanup_mutex_;
    
private:
    std::string generate_session_id() const;
    void cleanup_expired_sessions();
    void cleanup_rate_limits();
    bool is_session_expired(const std::shared_ptr<ClientSession>& session) const;
};

/**
 * Session-aware connection wrapper
 */
class ManagedConnection {
public:
    ManagedConnection(int socket_fd, std::shared_ptr<ClientSession> session,
                     std::shared_ptr<ConnectionPool> pool);
    ~ManagedConnection();

    // Disable copy/move
    ManagedConnection(const ManagedConnection&) = delete;
    ManagedConnection& operator=(const ManagedConnection&) = delete;

    // Connection info
    int socket() const { return socket_fd_; }
    const std::string& session_id() const { return session_->session_id; }
    const std::string& client_address() const { return session_->client_address; }
    
    // Session access
    std::shared_ptr<ClientSession> session() const { return session_; }
    
    // Activity tracking
    void record_request(size_t bytes);
    void record_response(size_t bytes);
    void update_activity();
    
    // Rate limiting
    bool check_rate_limit();
    
    // Connection state
    bool is_active() const { return active_.load(); }
    void mark_inactive() { active_.store(false); }

private:
    int socket_fd_;
    std::shared_ptr<ClientSession> session_;
    std::shared_ptr<ConnectionPool> pool_;
    std::atomic<bool> active_{true};
};

} // namespace nosql_db::network