#include "network/connection_pool.hpp"
#include <spdlog/spdlog.h>
#include <random>
#include <sstream>
#include <algorithm>
#include <shared_mutex>

namespace ishikura::network {

ConnectionPool::ConnectionPool(const PoolConfig& config)
    : config_(config), cleanup_running_(false) {
    spdlog::info("ConnectionPool initialized - max_connections: {}, session_timeout: {}s, "
                "rate_limit: {} req/s",
                config_.max_connections, config_.session_timeout.count(),
                config_.requests_per_second_limit);
}

ConnectionPool::~ConnectionPool() {
    stop_cleanup();
}

bool ConnectionPool::can_accept_connection(const std::string& client_ip) const {
    std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
    
    // Check global connection limit
    if (sessions_.size() >= config_.max_connections) {
        return false;
    }
    
    // Check per-IP connection limit
    std::shared_lock<std::shared_mutex> ip_lock(ip_connections_mutex_);
    auto it = connections_per_ip_.find(client_ip);
    if (it != connections_per_ip_.end() && it->second >= config_.max_connections_per_ip) {
        return false;
    }
    
    return true;
}

std::string ConnectionPool::create_session(int socket_fd, const std::string& client_address) {
    std::string client_ip = extract_ip_from_address(client_address);
    
    if (!can_accept_connection(client_ip)) {
        return ""; // Connection rejected
    }
    
    std::string session_id = generate_session_id();
    auto session = std::make_shared<ClientSession>(session_id, client_address);
    
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        sessions_[session_id] = session;
        fd_to_session_[socket_fd] = session_id;
        stats_.total_sessions.fetch_add(1);
        stats_.active_sessions.fetch_add(1);
    }
    
    // Update per-IP connection count
    {
        std::unique_lock<std::shared_mutex> ip_lock(ip_connections_mutex_);
        connections_per_ip_[client_ip]++;
    }
    
    spdlog::debug("Created session {} for {}", session_id, client_address);
    return session_id;
}

bool ConnectionPool::remove_session(const std::string& session_id) {
    std::shared_ptr<ClientSession> session;
    int socket_fd = -1;
    
    {
        std::unique_lock<std::shared_mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            return false;
        }
        
        session = it->second;
        sessions_.erase(it);
        
        // Find and remove fd mapping
        for (auto fd_it = fd_to_session_.begin(); fd_it != fd_to_session_.end(); ++fd_it) {
            if (fd_it->second == session_id) {
                socket_fd = fd_it->first;
                fd_to_session_.erase(fd_it);
                break;
            }
        }
        
        stats_.active_sessions.fetch_sub(1);
    }
    
    // Update per-IP connection count
    if (session) {
        std::string client_ip = extract_ip_from_address(session->client_address);
        std::unique_lock<std::shared_mutex> ip_lock(ip_connections_mutex_);
        auto it = connections_per_ip_.find(client_ip);
        if (it != connections_per_ip_.end()) {
            if (--it->second == 0) {
                connections_per_ip_.erase(it);
            }
        }
        
        // Update global stats
        stats_.total_bytes_sent.fetch_add(session->bytes_sent.load());
        stats_.total_bytes_received.fetch_add(session->bytes_received.load());
    }
    
    spdlog::debug("Removed session {} (socket {})", session_id, socket_fd);
    return true;
}

std::shared_ptr<ClientSession> ConnectionPool::get_session(const std::string& session_id) {
    std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
    auto it = sessions_.find(session_id);
    return (it != sessions_.end()) ? it->second : nullptr;
}

void ConnectionPool::update_session_activity(const std::string& session_id) {
    auto session = get_session(session_id);
    if (session) {
        session->last_activity = std::chrono::steady_clock::now();
    }
}

void ConnectionPool::record_request(const std::string& session_id, size_t bytes_received) {
    auto session = get_session(session_id);
    if (session) {
        session->total_requests.fetch_add(1);
        session->bytes_received.fetch_add(bytes_received);
        update_session_activity(session_id);
    }
}

void ConnectionPool::record_response(const std::string& session_id, size_t bytes_sent) {
    auto session = get_session(session_id);
    if (session) {
        session->total_responses.fetch_add(1);
        session->bytes_sent.fetch_add(bytes_sent);
        update_session_activity(session_id);
    }
}

bool ConnectionPool::check_rate_limit(const std::string& client_ip) {
    if (!config_.enable_rate_limiting) {
        return true;
    }
    
    std::unique_lock<std::mutex> lock(rate_limit_mutex_);
    auto now = std::chrono::steady_clock::now();
    
    auto& rate_info = rate_limits_[client_ip];
    
    // Reset window if enough time has passed
    auto window_duration = std::chrono::seconds(1);
    if (now - rate_info.window_start >= window_duration) {
        rate_info.window_start = now;
        rate_info.request_count.store(0);
        rate_info.burst_tokens.store(config_.burst_limit);
    }
    
    // Check rate limit
    if (rate_info.request_count.load() >= config_.requests_per_second_limit) {
        // Check burst tokens
        if (rate_info.burst_tokens.load() > 0) {
            rate_info.burst_tokens.fetch_sub(1);
            rate_info.request_count.fetch_add(1);
            return true;
        }
        
        stats_.rate_limited_requests.fetch_add(1);
        return false;
    }
    
    rate_info.request_count.fetch_add(1);
    return true;
}

void ConnectionPool::reset_rate_limits() {
    std::unique_lock<std::mutex> lock(rate_limit_mutex_);
    rate_limits_.clear();
}

std::vector<std::string> ConnectionPool::get_active_session_ids() const {
    std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
    std::vector<std::string> session_ids;
    session_ids.reserve(sessions_.size());
    
    for (const auto& [session_id, session] : sessions_) {
        session_ids.push_back(session_id);
    }
    
    return session_ids;
}

size_t ConnectionPool::get_connections_by_ip(const std::string& client_ip) const {
    std::shared_lock<std::shared_mutex> lock(ip_connections_mutex_);
    auto it = connections_per_ip_.find(client_ip);
    return (it != connections_per_ip_.end()) ? it->second : 0;
}

void ConnectionPool::set_max_connections(size_t max_conn) {
    config_.max_connections = max_conn;
    spdlog::info("Updated max_connections to {}", max_conn);
}

void ConnectionPool::set_session_timeout(std::chrono::seconds timeout) {
    config_.session_timeout = timeout;
    spdlog::info("Updated session_timeout to {}s", timeout.count());
}

void ConnectionPool::start_cleanup() {
    if (cleanup_running_.load()) {
        return;
    }
    
    cleanup_running_.store(true);
    cleanup_thread_ = std::thread([this]() {
        while (cleanup_running_.load()) {
            std::unique_lock<std::mutex> lock(cleanup_mutex_);
            if (cleanup_cv_.wait_for(lock, config_.cleanup_interval, 
                                   [this] { return !cleanup_running_.load(); })) {
                break; // Shutdown requested
            }
            
            cleanup_expired_sessions();
            cleanup_rate_limits();
        }
    });
    
    spdlog::debug("Connection pool cleanup started");
}

void ConnectionPool::stop_cleanup() {
    if (!cleanup_running_.load()) {
        return;
    }
    
    cleanup_running_.store(false);
    cleanup_cv_.notify_all();
    
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
    
    spdlog::debug("Connection pool cleanup stopped");
}

std::string ConnectionPool::generate_session_id() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    
    std::ostringstream oss;
    oss << std::hex << dis(gen);
    return oss.str();
}

void ConnectionPool::cleanup_expired_sessions() {
    std::vector<std::string> expired_sessions;
    
    {
        std::shared_lock<std::shared_mutex> lock(sessions_mutex_);
        for (const auto& [session_id, session] : sessions_) {
            if (is_session_expired(session)) {
                expired_sessions.push_back(session_id);
            }
        }
    }
    
    for (const auto& session_id : expired_sessions) {
        if (remove_session(session_id)) {
            stats_.expired_sessions.fetch_add(1);
            spdlog::debug("Expired session {}", session_id);
        }
    }
    
    if (!expired_sessions.empty()) {
        spdlog::info("Cleaned up {} expired sessions", expired_sessions.size());
    }
}

void ConnectionPool::cleanup_rate_limits() {
    std::unique_lock<std::mutex> lock(rate_limit_mutex_);
    auto now = std::chrono::steady_clock::now();
    auto cleanup_threshold = std::chrono::minutes(5);
    
    for (auto it = rate_limits_.begin(); it != rate_limits_.end(); ) {
        if (now - it->second.window_start > cleanup_threshold) {
            it = rate_limits_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string ConnectionPool::extract_ip_from_address(const std::string& address) const {
    size_t colon_pos = address.find_last_of(':');
    return (colon_pos != std::string::npos) ? address.substr(0, colon_pos) : address;
}

bool ConnectionPool::is_session_expired(const std::shared_ptr<ClientSession>& session) const {
    if (!session) return true;
    
    auto now = std::chrono::steady_clock::now();
    return (now - session->last_activity) > config_.session_timeout;
}

// ManagedConnection implementation
ManagedConnection::ManagedConnection(int socket_fd, std::shared_ptr<ClientSession> session,
                                   std::shared_ptr<ConnectionPool> pool)
    : socket_fd_(socket_fd), session_(std::move(session)), pool_(std::move(pool)) {
}

ManagedConnection::~ManagedConnection() {
    if (active_.load() && pool_ && session_) {
        pool_->remove_session(session_->session_id);
    }
}

void ManagedConnection::record_request(size_t bytes) {
    if (pool_ && session_) {
        pool_->record_request(session_->session_id, bytes);
    }
}

void ManagedConnection::record_response(size_t bytes) {
    if (pool_ && session_) {
        pool_->record_response(session_->session_id, bytes);
    }
}

void ManagedConnection::update_activity() {
    if (pool_ && session_) {
        pool_->update_session_activity(session_->session_id);
    }
}

bool ManagedConnection::check_rate_limit() {
    if (!pool_ || !session_) {
        return false;
    }
    
    std::string client_ip = pool_->extract_ip_from_address(session_->client_address);
    return pool_->check_rate_limit(client_ip);
}

} // namespace ishikura::network