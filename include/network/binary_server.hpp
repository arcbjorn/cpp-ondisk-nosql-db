#pragma once

#include "network/binary_protocol.hpp"
#include "network/connection_pool.hpp"
#include "network/metrics.hpp"
#include "storage/storage_engine.hpp"
#include "query/query_engine.hpp"
#include <memory>
#include <thread>
#include <atomic>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <functional>

namespace nosql_db::network {

/**
 * High-performance binary protocol server
 * 
 * Features:
 * - Custom binary protocol for maximum performance
 * - Asynchronous I/O using epoll (Linux) / kqueue (macOS) / IOCP (Windows)
 * - Connection pooling and session management
 * - Request batching and pipelining
 * - Streaming query results
 */

class BinaryServer {
public:
    struct ServerConfig {
        std::string host = "0.0.0.0";
        uint16_t port = 9090;
        size_t worker_threads = std::thread::hardware_concurrency();
        size_t max_message_size = MAX_MESSAGE_SIZE;
        bool enable_compression = false;
        bool enable_batching = true;
        
        // Connection pool configuration
        ConnectionPool::PoolConfig pool_config;
    };

    explicit BinaryServer(std::shared_ptr<storage::StorageEngine> storage);
    explicit BinaryServer(std::shared_ptr<storage::StorageEngine> storage,
                         const ServerConfig& config);
    ~BinaryServer();

    // Disable copy/move construction
    BinaryServer(const BinaryServer&) = delete;
    BinaryServer& operator=(const BinaryServer&) = delete;
    BinaryServer(BinaryServer&&) = delete;
    BinaryServer& operator=(BinaryServer&&) = delete;

    // Server lifecycle
    bool start();
    void stop();
    bool is_running() const { return running_.load(); }

    // Configuration
    const ServerConfig& config() const { return config_; }
    ConnectionPool& connection_pool() { return *connection_pool_; }
    const ConnectionPool& connection_pool() const { return *connection_pool_; }
    
    // Metrics access
    std::shared_ptr<NetworkMetrics> metrics() { return metrics_; }
    const NetworkMetrics& metrics() const { return *metrics_; }
    void start_metrics_monitoring();
    void stop_metrics_monitoring();

    // Statistics
    struct ServerStats {
        std::atomic<uint64_t> total_connections{0};
        std::atomic<uint64_t> active_connections{0};
        std::atomic<uint64_t> total_requests{0};
        std::atomic<uint64_t> total_responses{0};
        std::atomic<uint64_t> bytes_sent{0};
        std::atomic<uint64_t> bytes_received{0};
        std::atomic<uint64_t> errors{0};
        std::atomic<uint64_t> timeouts{0};
    };

    const ServerStats& stats() const { return stats_; }
    void reset_stats();

private:
    // Enhanced connection with session management
    struct SessionConnection {
        std::unique_ptr<ManagedConnection> managed_conn;
        std::vector<uint8_t> read_buffer;
        std::vector<uint8_t> write_buffer;
        
        SessionConnection(std::unique_ptr<ManagedConnection> conn) 
            : managed_conn(std::move(conn)) {
            read_buffer.reserve(64 * 1024);  // 64KB read buffer
            write_buffer.reserve(64 * 1024); // 64KB write buffer
        }
    };

    using SessionConnectionPtr = std::shared_ptr<SessionConnection>;
    
    ServerConfig config_;
    std::shared_ptr<storage::StorageEngine> storage_;
    std::unique_ptr<query::QueryEngine> query_engine_;
    std::shared_ptr<ConnectionPool> connection_pool_;
    
    // Network state
    std::atomic<bool> running_{false};
    int server_socket_{-1};
    int epoll_fd_{-1}; // Linux-specific, would be kqueue on macOS
    
    // Threading
    std::vector<std::thread> worker_threads_;
    std::thread accept_thread_;
    
    // Session-based connection tracking
    std::unordered_map<int, SessionConnectionPtr> connections_;
    std::mutex connections_mutex_;
    
    // Statistics and monitoring
    mutable ServerStats stats_;
    std::shared_ptr<NetworkMetrics> metrics_;
    std::unique_ptr<MetricsMonitor> metrics_monitor_;
    
    // Core server functions
    void accept_loop();
    void worker_loop();
    
    // Connection handling
    bool setup_server_socket();
    void cleanup_server_socket();
    SessionConnectionPtr accept_connection();
    void close_connection(SessionConnectionPtr conn);
    void handle_client_data(SessionConnectionPtr conn);
    
    // Message processing
    bool read_message(SessionConnectionPtr conn, BinaryMessage& message);
    bool write_message(SessionConnectionPtr conn, const BinaryMessage& message);
    void process_message(SessionConnectionPtr conn, const BinaryMessage& request);
    
    // Operation handlers
    void handle_put_request(SessionConnectionPtr conn, const BinaryMessage& request);
    void handle_get_request(SessionConnectionPtr conn, const BinaryMessage& request);
    void handle_delete_request(SessionConnectionPtr conn, const BinaryMessage& request);
    void handle_query_request(SessionConnectionPtr conn, const BinaryMessage& request);
    void handle_batch_request(SessionConnectionPtr conn, const BinaryMessage& request);
    void handle_ping_request(SessionConnectionPtr conn, const BinaryMessage& request);
    
    // Utility functions
    void send_error_response(SessionConnectionPtr conn, uint64_t message_id, 
                           StatusCode status, const std::string& error = "");
    
    // Platform-specific I/O
    bool setup_epoll();
    void cleanup_epoll();
    bool add_to_epoll(int fd, uint32_t events);
    bool remove_from_epoll(int fd);
};

/**
 * Simple binary client for testing and client libraries
 */
class BinaryClient {
public:
    struct ClientConfig {
        std::string host = "localhost";
        uint16_t port = 9090;
        std::chrono::seconds connection_timeout{10};
        std::chrono::seconds request_timeout{30};
        bool enable_keepalive = true;
        size_t max_retries = 3;
    };

    BinaryClient();
    explicit BinaryClient(const ClientConfig& config);
    ~BinaryClient();

    // Disable copy/move construction
    BinaryClient(const BinaryClient&) = delete;
    BinaryClient& operator=(const BinaryClient&) = delete;
    BinaryClient(BinaryClient&&) = delete;  
    BinaryClient& operator=(BinaryClient&&) = delete;

    // Connection management
    bool connect();
    void disconnect();
    bool is_connected() const { return connected_.load(); }

    // Basic operations
    bool put(const std::string& key, const std::string& value);
    std::optional<std::string> get(const std::string& key);
    bool delete_key(const std::string& key);
    
    // Query operations
    std::vector<std::pair<std::string, std::string>> query(const std::string& query_str);
    
    // Batch operations
    struct BatchOperation {
        enum Type { PUT, GET, DELETE } type;
        std::string key;
        std::string value; // Only used for PUT
    };
    
    std::vector<StatusCode> batch_execute(const std::vector<BatchOperation>& operations);
    
    // Utility operations
    bool ping();
    
    // Configuration
    const ClientConfig& config() const { return config_; }

private:
    ClientConfig config_;
    int socket_fd_{-1};
    std::atomic<bool> connected_{false};
    std::atomic<uint64_t> next_message_id_{1};
    std::mutex socket_mutex_;
    
    // Message I/O
    bool send_message(const BinaryMessage& message);
    bool receive_message(BinaryMessage& message);
    
    // Request-response handling
    std::optional<BinaryMessage> send_request(const BinaryMessage& request);
    
    // Socket operations
    bool create_socket();
    void close_socket();
    bool set_socket_options();
};

} // namespace nosql_db::network