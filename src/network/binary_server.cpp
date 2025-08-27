#include "network/binary_server.hpp"
#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>

namespace nosql_db::network {

BinaryServer::BinaryServer(std::shared_ptr<storage::StorageEngine> storage)
    : BinaryServer(std::move(storage), ServerConfig{}) {
}

BinaryServer::BinaryServer(std::shared_ptr<storage::StorageEngine> storage,
                          const ServerConfig& config)
    : config_(config), storage_(std::move(storage)),
      query_engine_(std::make_unique<query::QueryEngine>(storage_)),
      connection_pool_(std::make_shared<ConnectionPool>(config_.pool_config)),
      metrics_(std::make_shared<NetworkMetrics>()) {
    
    if (!storage_) {
        throw std::invalid_argument("Storage engine cannot be null");
    }
    
    spdlog::info("BinaryServer initialized - host: {}:{}, max_connections: {}, workers: {}",
                config_.host, config_.port, config_.pool_config.max_connections, config_.worker_threads);
}

BinaryServer::~BinaryServer() {
    stop();
    stop_metrics_monitoring();
}

bool BinaryServer::start() {
    if (running_.load()) {
        spdlog::warn("BinaryServer already running");
        return false;
    }
    
    if (!setup_server_socket()) {
        spdlog::error("Failed to setup server socket");
        return false;
    }
    
    if (!setup_epoll()) {
        spdlog::error("Failed to setup epoll");
        cleanup_server_socket();
        return false;
    }
    
    running_.store(true);
    
    // Start connection pool cleanup
    connection_pool_->start_cleanup();
    
    // Start worker threads
    worker_threads_.reserve(config_.worker_threads);
    for (size_t i = 0; i < config_.worker_threads; ++i) {
        worker_threads_.emplace_back(&BinaryServer::worker_loop, this);
    }
    
    // Start accept thread
    accept_thread_ = std::thread(&BinaryServer::accept_loop, this);
    
    // Start metrics monitoring
    start_metrics_monitoring();
    
    spdlog::info("BinaryServer started on {}:{}", config_.host, config_.port);
    return true;
}

void BinaryServer::stop() {
    if (!running_.load()) {
        return;
    }
    
    spdlog::info("Stopping BinaryServer...");
    running_.store(false);
    
    // Stop metrics monitoring
    stop_metrics_monitoring();
    
    // Close server socket to stop accepting new connections
    cleanup_server_socket();
    
    // Stop connection pool cleanup
    connection_pool_->stop_cleanup();
    
    // Wait for threads to finish
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    
    for (auto& worker : worker_threads_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    worker_threads_.clear();
    
    // Close all client connections
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (auto& [fd, conn] : connections_) {
            close_connection(conn);
        }
        connections_.clear();
    }
    
    cleanup_epoll();
    spdlog::info("BinaryServer stopped");
}

bool BinaryServer::setup_server_socket() {
    server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_ < 0) {
        spdlog::error("Failed to create server socket: {}", strerror(errno));
        return false;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        spdlog::warn("Failed to set SO_REUSEADDR: {}", strerror(errno));
    }
    
    // Make socket non-blocking
    int flags = fcntl(server_socket_, F_GETFL, 0);
    if (flags < 0 || fcntl(server_socket_, F_SETFL, flags | O_NONBLOCK) < 0) {
        spdlog::error("Failed to make server socket non-blocking: {}", strerror(errno));
        close(server_socket_);
        server_socket_ = -1;
        return false;
    }
    
    // Bind socket
    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config_.port);
    
    if (config_.host == "0.0.0.0") {
        address.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, config_.host.c_str(), &address.sin_addr) <= 0) {
            spdlog::error("Invalid host address: {}", config_.host);
            close(server_socket_);
            server_socket_ = -1;
            return false;
        }
    }
    
    if (bind(server_socket_, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) < 0) {
        spdlog::error("Failed to bind server socket to {}:{}: {}", 
                     config_.host, config_.port, strerror(errno));
        close(server_socket_);
        server_socket_ = -1;
        return false;
    }
    
    // Start listening
    if (listen(server_socket_, static_cast<int>(config_.pool_config.max_connections)) < 0) {
        spdlog::error("Failed to listen on server socket: {}", strerror(errno));
        close(server_socket_);
        server_socket_ = -1;
        return false;
    }
    
    return true;
}

void BinaryServer::cleanup_server_socket() {
    if (server_socket_ >= 0) {
        close(server_socket_);
        server_socket_ = -1;
    }
}

bool BinaryServer::setup_epoll() {
    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        spdlog::error("Failed to create epoll instance: {}", strerror(errno));
        return false;
    }
    
    // Add server socket to epoll
    if (!add_to_epoll(server_socket_, EPOLLIN)) {
        close(epoll_fd_);
        epoll_fd_ = -1;
        return false;
    }
    
    return true;
}

void BinaryServer::cleanup_epoll() {
    if (epoll_fd_ >= 0) {
        close(epoll_fd_);
        epoll_fd_ = -1;
    }
}

bool BinaryServer::add_to_epoll(int fd, uint32_t events) {
    struct epoll_event event{};
    event.events = events;
    event.data.fd = fd;
    
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &event) < 0) {
        spdlog::error("Failed to add fd {} to epoll: {}", fd, strerror(errno));
        return false;
    }
    
    return true;
}

bool BinaryServer::remove_from_epoll(int fd) {
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr) < 0) {
        spdlog::debug("Failed to remove fd {} from epoll: {}", fd, strerror(errno));
        return false;
    }
    return true;
}

void BinaryServer::accept_loop() {
    spdlog::debug("Accept loop started");
    
    const int max_events = 64;
    struct epoll_event events[max_events];
    
    while (running_.load()) {
        int num_events = epoll_wait(epoll_fd_, events, max_events, 1000); // 1 second timeout
        
        if (num_events < 0) {
            if (errno == EINTR) continue; // Interrupted system call
            spdlog::error("epoll_wait failed: {}", strerror(errno));
            break;
        }
        
        for (int i = 0; i < num_events; ++i) {
            int fd = events[i].data.fd;
            
            if (fd == server_socket_) {
                // New connection
                auto conn = accept_connection();
                if (conn) {
                    stats_.total_connections.fetch_add(1);
                    stats_.active_connections.fetch_add(1);
                    
                    std::lock_guard<std::mutex> lock(connections_mutex_);
                    connections_[conn->managed_conn->socket()] = conn;
                    add_to_epoll(conn->managed_conn->socket(), EPOLLIN | EPOLLHUP | EPOLLERR);
                }
            } else {
                // Existing connection has data
                std::lock_guard<std::mutex> lock(connections_mutex_);
                auto it = connections_.find(fd);
                if (it != connections_.end()) {
                    if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                        // Connection closed or error
                        close_connection(it->second);
                        connections_.erase(it);
                    } else if (events[i].events & EPOLLIN) {
                        // Data available to read
                        handle_client_data(it->second);
                    }
                }
            }
        }
    }
    
    spdlog::debug("Accept loop finished");
}

BinaryServer::SessionConnectionPtr BinaryServer::accept_connection() {
    struct sockaddr_in client_addr{};
    socklen_t addr_len = sizeof(client_addr);
    
    int client_fd = accept(server_socket_, reinterpret_cast<struct sockaddr*>(&client_addr), &addr_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            spdlog::warn("Failed to accept connection: {}", strerror(errno));
        }
        return nullptr;
    }
    
    // Make client socket non-blocking
    int flags = fcntl(client_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        spdlog::warn("Failed to make client socket non-blocking: {}", strerror(errno));
        close(client_fd);
        return nullptr;
    }
    
    // Get client address
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    std::string remote_address = std::string(client_ip) + ":" + std::to_string(ntohs(client_addr.sin_port));
    
    // Check if connection can be accepted by pool
    if (!connection_pool_->can_accept_connection(client_ip)) {
        spdlog::warn("Rejecting connection from {} - pool limits exceeded", remote_address);
        metrics_->record_connection_rejected();
        close(client_fd);
        return nullptr;
    }
    
    // Create session
    std::string session_id = connection_pool_->create_session(client_fd, remote_address);
    if (session_id.empty()) {
        spdlog::warn("Failed to create session for {}", remote_address);
        metrics_->record_connection_failed();
        close(client_fd);
        return nullptr;
    }
    
    auto session = connection_pool_->get_session(session_id);
    if (!session) {
        spdlog::error("Session {} not found after creation", session_id);
        close(client_fd);
        return nullptr;
    }
    
    auto managed_conn = std::make_unique<ManagedConnection>(client_fd, session, connection_pool_);
    auto session_conn = std::make_shared<SessionConnection>(std::move(managed_conn));
    
    // Track successful connection
    metrics_->record_connection_start();
    metrics_->record_session_created();
    
    spdlog::debug("Accepted connection from {} with session {}", remote_address, session_id);
    return session_conn;
}

void BinaryServer::close_connection(SessionConnectionPtr conn) {
    if (conn && conn->managed_conn && conn->managed_conn->is_active()) {
        // Calculate connection duration
        auto session = conn->managed_conn->session();
        auto connection_duration = std::chrono::steady_clock::now() - session->created_at;
        
        // Track connection close
        metrics_->record_connection_end(std::chrono::duration_cast<std::chrono::microseconds>(connection_duration));
        metrics_->record_session_expired(std::chrono::duration_cast<std::chrono::microseconds>(connection_duration));
        
        conn->managed_conn->mark_inactive();
        remove_from_epoll(conn->managed_conn->socket());
        close(conn->managed_conn->socket());
        stats_.active_connections.fetch_sub(1);
        spdlog::debug("Closed connection to {} (session {})", 
                     conn->managed_conn->client_address(), conn->managed_conn->session_id());
    }
}

void BinaryServer::handle_client_data(SessionConnectionPtr conn) {
    if (!conn || !conn->managed_conn || !conn->managed_conn->is_active()) {
        return;
    }
    
    // Check rate limiting
    if (!conn->managed_conn->check_rate_limit()) {
        spdlog::warn("Rate limit exceeded for {}", conn->managed_conn->client_address());
        close_connection(conn);
        return;
    }
    
    // Read available data
    char buffer[4096];
    ssize_t bytes_read = recv(conn->managed_conn->socket(), buffer, sizeof(buffer), MSG_DONTWAIT);
    
    if (bytes_read <= 0) {
        if (bytes_read == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            // Connection closed or error
            close_connection(conn);
        }
        return;
    }
    
    stats_.bytes_received.fetch_add(bytes_read);
    conn->managed_conn->record_request(bytes_read);
    
    // Append to read buffer
    conn->read_buffer.insert(conn->read_buffer.end(), buffer, buffer + bytes_read);
    
    // Process complete messages
    while (conn->managed_conn->is_active() && conn->read_buffer.size() >= HEADER_SIZE) {
        BinaryMessage message;
        if (read_message(conn, message)) {
            process_message(conn, message);
        } else {
            // Invalid message or need more data
            break;
        }
    }
}

bool BinaryServer::read_message(SessionConnectionPtr conn, BinaryMessage& message) {
    if (conn->read_buffer.size() < HEADER_SIZE) {
        return false;
    }
    
    // Parse header to get message size
    MessageHeader header;
    std::memcpy(&header, conn->read_buffer.data(), HEADER_SIZE);
    
    if (header.magic != PROTOCOL_MAGIC || header.version != PROTOCOL_VERSION) {
        spdlog::warn("Invalid message header from {}", conn->managed_conn->client_address());
        close_connection(conn);
        return false;
    }
    
    size_t total_size = HEADER_SIZE + header.data_length;
    if (conn->read_buffer.size() < total_size) {
        return false; // Need more data
    }
    
    // Deserialize complete message
    if (!message.deserialize(conn->read_buffer.data(), total_size)) {
        spdlog::warn("Failed to deserialize message from {}", conn->managed_conn->client_address());
        close_connection(conn);
        return false;
    }
    
    // Remove processed data from buffer
    conn->read_buffer.erase(conn->read_buffer.begin(), conn->read_buffer.begin() + total_size);
    
    return true;
}

bool BinaryServer::write_message(SessionConnectionPtr conn, const BinaryMessage& message) {
    if (!conn || !conn->managed_conn || !conn->managed_conn->is_active()) {
        return false;
    }
    
    auto serialized = message.serialize();
    ssize_t bytes_sent = send(conn->managed_conn->socket(), serialized.data(), serialized.size(), MSG_NOSIGNAL);
    
    if (bytes_sent < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            spdlog::debug("Failed to send message to {}: {}", conn->managed_conn->client_address(), strerror(errno));
            close_connection(conn);
            return false;
        }
        return false; // Would block, should implement proper buffering
    }
    
    stats_.bytes_sent.fetch_add(bytes_sent);
    stats_.total_responses.fetch_add(1);
    conn->managed_conn->record_response(bytes_sent);
    
    // Track metrics
    metrics_->record_bytes_sent(bytes_sent);
    metrics_->record_message_sent();
    
    // Check for compression if enabled
    if (message.has_flag(MessageFlags::COMPRESSED)) {
        // Estimate original size (would need to be tracked properly in real implementation)
        metrics_->record_compression(serialized.size() * 2, serialized.size()); // Rough estimate
    }
    
    return bytes_sent == static_cast<ssize_t>(serialized.size());
}

void BinaryServer::process_message(SessionConnectionPtr conn, const BinaryMessage& request) {
    if (!conn || !conn->managed_conn || !conn->managed_conn->is_active()) {
        return;
    }
    
    auto start_time = std::chrono::steady_clock::now();
    
    stats_.total_requests.fetch_add(1);
    metrics_->record_request_start();
    metrics_->record_bytes_received(request.total_size());
    metrics_->record_message_received();
    
    bool request_successful = true;
    
    try {
        switch (request.type()) {
            case MessageType::PUT_REQUEST:
                metrics_->record_request_by_type("PUT");
                handle_put_request(conn, request);
                break;
            case MessageType::GET_REQUEST:
                metrics_->record_request_by_type("GET");
                handle_get_request(conn, request);
                break;
            case MessageType::DELETE_REQUEST:
                metrics_->record_request_by_type("DELETE");
                handle_delete_request(conn, request);
                break;
            case MessageType::QUERY_REQUEST:
                metrics_->record_request_by_type("QUERY");
                handle_query_request(conn, request);
                break;
            case MessageType::BATCH_REQUEST:
                metrics_->record_request_by_type("BATCH");
                handle_batch_request(conn, request);
                break;
            case MessageType::PING:
                metrics_->record_request_by_type("PING");
                handle_ping_request(conn, request);
                break;
            default:
                request_successful = false;
                metrics_->record_protocol_error();
                send_error_response(conn, request.message_id(), 
                                  StatusCode::UNSUPPORTED_VERSION, "Unsupported message type");
                break;
        }
    } catch (const std::exception& e) {
        request_successful = false;
        spdlog::error("Error processing message from {}: {}", conn->managed_conn->client_address(), e.what());
        send_error_response(conn, request.message_id(), StatusCode::SERVER_ERROR, e.what());
        stats_.errors.fetch_add(1);
        metrics_->record_network_error();
    }
    
    // Record request completion metrics
    auto end_time = std::chrono::steady_clock::now();
    auto response_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    metrics_->record_request_end(response_time, request_successful);
}

void BinaryServer::handle_put_request(SessionConnectionPtr conn, const BinaryMessage& request) {
    auto put_data = MessageParser::parse_put_request(request);
    if (!put_data) {
        send_error_response(conn, request.message_id(), StatusCode::INVALID_REQUEST, 
                          "Invalid PUT request format");
        return;
    }
    
    bool success = storage_->put(put_data->key, put_data->value);
    StatusCode status = success ? StatusCode::SUCCESS : StatusCode::STORAGE_ERROR;
    
    auto response = MessageBuilder::create_put_response(request.message_id(), status);
    write_message(conn, response);
    
    spdlog::debug("PUT {} = {} bytes from {}", put_data->key, put_data->value.size(), conn->managed_conn->client_address());
}

void BinaryServer::handle_get_request(SessionConnectionPtr conn, const BinaryMessage& request) {
    auto get_data = MessageParser::parse_get_request(request);
    if (!get_data) {
        send_error_response(conn, request.message_id(), StatusCode::INVALID_REQUEST,
                          "Invalid GET request format");
        return;
    }
    
    auto value = storage_->get(get_data->key);
    StatusCode status = value ? StatusCode::SUCCESS : StatusCode::KEY_NOT_FOUND;
    
    auto response = MessageBuilder::create_get_response(request.message_id(), status, 
                                                       value ? *value : "");
    write_message(conn, response);
    
    spdlog::debug("GET {} from {} - {}", get_data->key, conn->managed_conn->client_address(), 
                 value ? "found" : "not found");
}

void BinaryServer::handle_delete_request(SessionConnectionPtr conn, const BinaryMessage& request) {
    auto delete_data = MessageParser::parse_delete_request(request);
    if (!delete_data) {
        send_error_response(conn, request.message_id(), StatusCode::INVALID_REQUEST,
                          "Invalid DELETE request format");
        return;
    }
    
    bool success = storage_->delete_key(delete_data->key);
    StatusCode status = success ? StatusCode::SUCCESS : StatusCode::KEY_NOT_FOUND;
    
    auto response = MessageBuilder::create_delete_response(request.message_id(), status);
    write_message(conn, response);
    
    spdlog::debug("DELETE {} from {} - {}", delete_data->key, conn->managed_conn->client_address(),
                 success ? "success" : "not found");
}

void BinaryServer::handle_query_request(SessionConnectionPtr conn, const BinaryMessage& request) {
    auto query_data = MessageParser::parse_query_request(request);
    if (!query_data) {
        send_error_response(conn, request.message_id(), StatusCode::INVALID_REQUEST,
                          "Invalid QUERY request format");
        return;
    }
    
    try {
        auto results = query_engine_->execute_query(query_data->query);
        
        std::vector<std::pair<std::string, std::string>> result_pairs;
        result_pairs.reserve(results.size());
        
        for (const auto& result : results) {
            result_pairs.emplace_back(result.key, result.value);
        }
        
        auto response = MessageBuilder::create_query_response(request.message_id(), 
                                                             StatusCode::SUCCESS, result_pairs);
        write_message(conn, response);
        
        spdlog::debug("QUERY '{}' from {} - {} results", query_data->query, 
                     conn->managed_conn->client_address(), results.size());
        
    } catch (const std::exception& e) {
        send_error_response(conn, request.message_id(), StatusCode::INVALID_REQUEST, e.what());
    }
}

void BinaryServer::handle_batch_request(SessionConnectionPtr conn, const BinaryMessage& request) {
    auto operations = MessageParser::parse_batch_request(request);
    if (operations.empty()) {
        send_error_response(conn, request.message_id(), StatusCode::INVALID_REQUEST,
                          "Empty or invalid batch request");
        return;
    }
    
    std::vector<StatusCode> results;
    results.reserve(operations.size());
    
    for (const auto& operation : operations) {
        StatusCode result = StatusCode::SUCCESS;
        
        try {
            switch (operation.type()) {
                case MessageType::PUT_REQUEST: {
                    auto put_data = MessageParser::parse_put_request(operation);
                    if (put_data && storage_->put(put_data->key, put_data->value)) {
                        result = StatusCode::SUCCESS;
                    } else {
                        result = StatusCode::STORAGE_ERROR;
                    }
                    break;
                }
                case MessageType::GET_REQUEST: {
                    auto get_data = MessageParser::parse_get_request(operation);
                    if (get_data && storage_->get(get_data->key)) {
                        result = StatusCode::SUCCESS;
                    } else {
                        result = StatusCode::KEY_NOT_FOUND;
                    }
                    break;
                }
                case MessageType::DELETE_REQUEST: {
                    auto delete_data = MessageParser::parse_delete_request(operation);
                    if (delete_data && storage_->delete_key(delete_data->key)) {
                        result = StatusCode::SUCCESS;
                    } else {
                        result = StatusCode::KEY_NOT_FOUND;
                    }
                    break;
                }
                default:
                    result = StatusCode::UNSUPPORTED_VERSION;
                    break;
            }
        } catch (const std::exception&) {
            result = StatusCode::SERVER_ERROR;
        }
        
        results.push_back(result);
    }
    
    auto response = MessageBuilder::create_batch_response(request.message_id(), 
                                                         StatusCode::SUCCESS, results);
    write_message(conn, response);
    
    spdlog::debug("BATCH {} operations from {}", operations.size(), conn->managed_conn->client_address());
}

void BinaryServer::handle_ping_request(SessionConnectionPtr conn, const BinaryMessage& request) {
    auto response = MessageBuilder::create_pong(request.message_id());
    write_message(conn, response);
}

void BinaryServer::send_error_response(SessionConnectionPtr conn, uint64_t message_id, 
                                      StatusCode status, const std::string& error) {
    auto response = MessageBuilder::create_error(message_id, status, error);
    write_message(conn, response);
}

void BinaryServer::worker_loop() {
    spdlog::debug("Worker thread started");
    
    while (running_.load()) {
        // This would be where we process queued work items
        // For now, just sleep since we're using epoll for I/O
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    spdlog::debug("Worker thread finished");
}

void BinaryServer::reset_stats() {
    stats_.total_connections.store(0);
    stats_.total_requests.store(0);
    stats_.total_responses.store(0);
    stats_.bytes_sent.store(0);
    stats_.bytes_received.store(0);
    stats_.errors.store(0);
    stats_.timeouts.store(0);
}

void BinaryServer::start_metrics_monitoring() {
    if (!metrics_monitor_) {
        MetricsMonitor::MonitorConfig monitor_config;
        monitor_config.report_interval = std::chrono::seconds(30);
        monitor_config.enable_console_output = true;
        monitor_config.enable_file_output = true;
        monitor_config.log_file_path = "binary_server_metrics.log";
        
        metrics_monitor_ = std::make_unique<MetricsMonitor>(metrics_, monitor_config);
        metrics_monitor_->start();
        spdlog::info("Metrics monitoring started");
    }
}

void BinaryServer::stop_metrics_monitoring() {
    if (metrics_monitor_) {
        metrics_monitor_->stop();
        metrics_monitor_.reset();
        spdlog::info("Metrics monitoring stopped");
    }
}

} // namespace nosql_db::network