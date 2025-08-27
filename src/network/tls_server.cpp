#include "network/tls_server.hpp"
#include "network/binary_protocol.hpp"
#include "network/metrics.hpp"
#include "network/connection_pool.hpp"
#include "storage/storage_engine.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <cstring>
#include <cerrno>

namespace nosql_db {
namespace network {

// TLSConnection Implementation
TLSConnection::TLSConnection(SSL* ssl, int socket_fd)
    : ssl_(ssl), socket_fd_(socket_fd), connected_(true), handshake_complete_(false) {
}

TLSConnection::~TLSConnection() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
    }
    if (socket_fd_ >= 0) {
        close(socket_fd_);
    }
}

bool TLSConnection::perform_handshake() {
    if (handshake_complete_) {
        return true;
    }
    
    int result = SSL_accept(ssl_);
    if (result <= 0) {
        int error = SSL_get_error(ssl_, result);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            return false; // Need to retry
        }
        connected_ = false;
        return false;
    }
    
    handshake_complete_ = true;
    return true;
}

int TLSConnection::read(void* buffer, size_t length) {
    if (!connected_ || !handshake_complete_) {
        return -1;
    }
    
    int bytes_read = SSL_read(ssl_, buffer, static_cast<int>(length));
    if (bytes_read <= 0) {
        int error = SSL_get_error(ssl_, bytes_read);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            connected_ = false;
        }
    }
    
    return bytes_read;
}

int TLSConnection::write(const void* buffer, size_t length) {
    if (!connected_ || !handshake_complete_) {
        return -1;
    }
    
    int bytes_written = SSL_write(ssl_, buffer, static_cast<int>(length));
    if (bytes_written <= 0) {
        int error = SSL_get_error(ssl_, bytes_written);
        if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
            connected_ = false;
        }
    }
    
    return bytes_written;
}

bool TLSConnection::shutdown_connection() {
    if (!ssl_) return false;
    
    int result = SSL_shutdown(ssl_);
    if (result == 0) {
        // First phase of shutdown completed, do second phase
        result = SSL_shutdown(ssl_);
    }
    
    connected_ = false;
    return result >= 0;
}

std::string TLSConnection::get_peer_certificate_subject() const {
    if (!cached_peer_subject_.empty()) {
        return cached_peer_subject_;
    }
    
    X509* cert = SSL_get_peer_certificate(ssl_);
    if (!cert) return "";
    
    char* subject = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
    if (subject) {
        cached_peer_subject_ = subject;
        OPENSSL_free(subject);
    }
    
    X509_free(cert);
    return cached_peer_subject_;
}

std::string TLSConnection::get_peer_certificate_issuer() const {
    if (!cached_peer_issuer_.empty()) {
        return cached_peer_issuer_;
    }
    
    X509* cert = SSL_get_peer_certificate(ssl_);
    if (!cert) return "";
    
    char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
    if (issuer) {
        cached_peer_issuer_ = issuer;
        OPENSSL_free(issuer);
    }
    
    X509_free(cert);
    return cached_peer_issuer_;
}

std::string TLSConnection::get_cipher_name() const {
    const char* cipher = SSL_get_cipher_name(ssl_);
    return cipher ? cipher : "";
}

std::string TLSConnection::get_protocol_version() const {
    const char* version = SSL_get_version(ssl_);
    return version ? version : "";
}

bool TLSConnection::is_client_cert_verified() const {
    return SSL_get_verify_result(ssl_) == X509_V_OK;
}

long TLSConnection::get_verify_result() const {
    return SSL_get_verify_result(ssl_);
}

// TLSServer Implementation
TLSServer::TLSServer(std::shared_ptr<nosql_db::storage::StorageEngine> storage)
    : TLSServer(storage, ServerConfig{}) {
}

TLSServer::TLSServer(std::shared_ptr<nosql_db::storage::StorageEngine> storage, const ServerConfig& config)
    : config_(config), storage_(storage), ssl_context_(nullptr), ssl_initialized_(false),
      server_socket_(-1), running_(false) {
    
    metrics_ = std::make_shared<NetworkMetrics>();
    
    ConnectionPool::PoolConfig pool_config;
    pool_config.max_connections = config_.pool_config.max_connections;
    pool_config.max_connections_per_ip = config_.pool_config.max_connections_per_ip;
    pool_config.session_timeout = config_.pool_config.session_timeout;
    pool_config.enable_rate_limiting = config_.pool_config.enable_rate_limiting;
    pool_config.requests_per_second_limit = config_.pool_config.requests_per_second_limit;
    
    connection_pool_ = std::make_shared<ConnectionPool>(pool_config);
}

TLSServer::~TLSServer() {
    stop();
    cleanup_ssl();
}

bool TLSServer::start() {
    if (running_) {
        return false;
    }
    
    // Initialize SSL/TLS
    if (!initialize_ssl()) {
        std::cerr << "Failed to initialize SSL/TLS" << std::endl;
        return false;
    }
    
    // Create server socket
    server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_ < 0) {
        std::cerr << "Failed to create server socket" << std::endl;
        return false;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set SO_REUSEADDR" << std::endl;
        close(server_socket_);
        return false;
    }
    
    // Bind socket
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    addr.sin_addr.s_addr = config_.host == "0.0.0.0" ? INADDR_ANY : inet_addr(config_.host.c_str());
    
    if (bind(server_socket_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind socket to " << config_.host << ":" << config_.port << std::endl;
        close(server_socket_);
        return false;
    }
    
    // Listen for connections
    if (listen(server_socket_, config_.backlog) < 0) {
        std::cerr << "Failed to listen on socket" << std::endl;
        close(server_socket_);
        return false;
    }
    
    running_ = true;
    
    // Start worker threads
    for (int i = 0; i < config_.worker_threads; ++i) {
        worker_threads_.emplace_back(&TLSServer::worker_thread, this, i);
    }
    
    std::cout << "TLS Server started on " << config_.host << ":" << config_.port << std::endl;
    return true;
}

void TLSServer::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    // Close server socket to stop accepting new connections
    if (server_socket_ >= 0) {
        close(server_socket_);
        server_socket_ = -1;
    }
    
    // Wait for worker threads to finish
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();
    
    std::cout << "TLS Server stopped" << std::endl;
}

bool TLSServer::initialize_ssl() {
    if (ssl_initialized_) {
        return true;
    }
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Create SSL context
    ssl_context_ = create_ssl_context();
    if (!ssl_context_) {
        return false;
    }
    
    // Configure SSL context
    if (!configure_ssl_context(ssl_context_)) {
        SSL_CTX_free(ssl_context_);
        ssl_context_ = nullptr;
        return false;
    }
    
    ssl_initialized_ = true;
    return true;
}

void TLSServer::cleanup_ssl() {
    if (ssl_context_) {
        SSL_CTX_free(ssl_context_);
        ssl_context_ = nullptr;
    }
    
    if (ssl_initialized_) {
        EVP_cleanup();
        ERR_free_strings();
        ssl_initialized_ = false;
    }
}

SSL_CTX* TLSServer::create_ssl_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        log_ssl_error("SSL_CTX_new");
        return nullptr;
    }
    
    return ctx;
}

bool TLSServer::configure_ssl_context(SSL_CTX* ctx) {
    const auto& tls_config = config_.tls_config;
    
    // Set TLS version range
    SSL_CTX_set_min_proto_version(ctx, tls_config.min_tls_version);
    SSL_CTX_set_max_proto_version(ctx, tls_config.max_tls_version);
    
    // Load certificates
    if (!load_certificates(ctx)) {
        return false;
    }
    
    // Setup cipher suites
    if (!setup_cipher_suites(ctx)) {
        return false;
    }
    
    // Configure client certificate verification
    int verify_mode = SSL_VERIFY_NONE;
    if (tls_config.require_client_cert) {
        verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    } else if (tls_config.verify_client_cert) {
        verify_mode = SSL_VERIFY_PEER;
    }
    
    SSL_CTX_set_verify(ctx, verify_mode, verify_callback);
    SSL_CTX_set_verify_depth(ctx, tls_config.verify_depth);
    
    // Load CA certificates for client verification
    if (!tls_config.ca_file.empty()) {
        if (SSL_CTX_load_verify_locations(ctx, tls_config.ca_file.c_str(), nullptr) != 1) {
            log_ssl_error("SSL_CTX_load_verify_locations");
            return false;
        }
    }
    
    // Configure session settings
    if (tls_config.enable_session_reuse) {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_set_timeout(ctx, static_cast<long>(tls_config.session_timeout.count()));
    } else {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    }
    
    // Security options
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    
    if (tls_config.disable_compression) {
        options |= SSL_OP_NO_COMPRESSION;
    }
    
    if (tls_config.enable_secure_renegotiation) {
        // Use available renegotiation option based on OpenSSL version
        #ifdef SSL_OP_ALLOW_SAFE_LEGACY_RENEGOTIATION
            options |= SSL_OP_ALLOW_SAFE_LEGACY_RENEGOTIATION;
        #elif defined(SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)
            // Fallback to unsafe option if safe one not available
            options |= SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
        #endif
    }
    
    if (tls_config.disable_legacy_renegotiation) {
        options |= SSL_OP_NO_RENEGOTIATION;
    }
    
    if (config_.enable_perfect_forward_secrecy) {
        options |= SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE;
    }
    
    SSL_CTX_set_options(ctx, options);
    
    return true;
}

bool TLSServer::load_certificates(SSL_CTX* ctx) {
    const auto& tls_config = config_.tls_config;
    
    // Load certificate
    if (SSL_CTX_use_certificate_file(ctx, tls_config.cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        log_ssl_error("SSL_CTX_use_certificate_file");
        return false;
    }
    
    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, tls_config.key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        log_ssl_error("SSL_CTX_use_PrivateKey_file");
        return false;
    }
    
    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Private key does not match certificate" << std::endl;
        return false;
    }
    
    return true;
}

bool TLSServer::setup_cipher_suites(SSL_CTX* ctx) {
    const auto& tls_config = config_.tls_config;
    
    // Set TLS 1.2 and earlier cipher list
    if (!tls_config.cipher_list.empty()) {
        if (SSL_CTX_set_cipher_list(ctx, tls_config.cipher_list.c_str()) != 1) {
            log_ssl_error("SSL_CTX_set_cipher_list");
            return false;
        }
    }
    
    // Set TLS 1.3 cipher suites
    if (!tls_config.cipher_suites.empty()) {
        if (SSL_CTX_set_ciphersuites(ctx, tls_config.cipher_suites.c_str()) != 1) {
            log_ssl_error("SSL_CTX_set_ciphersuites");
            return false;
        }
    }
    
    return true;
}

void TLSServer::worker_thread(int worker_id) {
    std::cout << "TLS Worker thread " << worker_id << " started" << std::endl;
    
    while (running_) {
        // Accept new connection
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket_, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (running_) {
                std::cerr << "Accept failed: " << strerror(errno) << std::endl;
            }
            continue;
        }
        
        // Get client address
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        std::string client_address = std::string(client_ip) + ":" + std::to_string(ntohs(client_addr.sin_port));
        
        // Check if we can accept this connection
        std::string ip = std::string(client_ip);
        if (!connection_pool_->can_accept_connection(ip)) {
            std::cerr << "Connection rejected from " << client_address << " (rate limit or connection limit reached)" << std::endl;
            close(client_socket);
            metrics_->record_network_error();
            continue;
        }
        
        // Create TLS connection
        auto tls_connection = accept_tls_connection(client_socket);
        if (!tls_connection) {
            close(client_socket);
            metrics_->record_network_error();
            continue;
        }
        
        // Record metrics
        metrics_->record_connection_start();
        
        // Handle the connection
        handle_connection(std::move(tls_connection));
    }
    
    std::cout << "TLS Worker thread " << worker_id << " stopped" << std::endl;
}

std::unique_ptr<TLSConnection> TLSServer::accept_tls_connection(int client_socket) {
    SSL* ssl = SSL_new(ssl_context_);
    if (!ssl) {
        log_ssl_error("SSL_new");
        return nullptr;
    }
    
    if (SSL_set_fd(ssl, client_socket) != 1) {
        log_ssl_error("SSL_set_fd");
        SSL_free(ssl);
        return nullptr;
    }
    
    auto connection = std::make_unique<TLSConnection>(ssl, client_socket);
    
    // Set handshake timeout
    struct timeval timeout;
    timeout.tv_sec = static_cast<long>(config_.ssl_handshake_timeout.count());
    timeout.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Perform SSL handshake
    auto start_time = std::chrono::steady_clock::now();
    while (!connection->is_handshake_complete()) {
        if (!connection->perform_handshake()) {
            auto elapsed = std::chrono::steady_clock::now() - start_time;
            if (elapsed > config_.ssl_handshake_timeout) {
                std::cerr << "SSL handshake timeout" << std::endl;
                metrics_->record_timeout_error();
                return nullptr;
            }
            
            // Check if connection failed
            if (!connection->is_connected()) {
                std::cerr << "SSL handshake failed" << std::endl;
                metrics_->record_protocol_error();
                return nullptr;
            }
            
            // Brief sleep before retry
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    // Clear timeouts for normal operation
    timeout.tv_sec = static_cast<long>(config_.request_timeout.count());
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    return connection;
}

bool TLSServer::handle_connection(std::unique_ptr<TLSConnection> connection) {
    auto start_time = std::chrono::steady_clock::now();
    
    try {
        // Log connection details
        std::cout << "TLS connection established: "
                  << "Protocol=" << connection->get_protocol_version()
                  << ", Cipher=" << connection->get_cipher_name() << std::endl;
        
        if (!connection->get_peer_certificate_subject().empty()) {
            std::cout << "Client certificate: " << connection->get_peer_certificate_subject() << std::endl;
        }
        
        // Process binary protocol messages
        while (connection->is_connected() && running_) {
            if (!process_binary_message(*connection)) {
                break;
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Exception handling TLS connection: " << e.what() << std::endl;
        metrics_->record_protocol_error();
    }
    
    // Record connection metrics
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - start_time);
    metrics_->record_connection_end(duration);
    
    return true;
}

bool TLSServer::process_binary_message(TLSConnection& connection) {
    // First receive the header
    MessageHeader header;
    int bytes_read = connection.read(&header, sizeof(header));
    if (bytes_read != sizeof(header)) {
        return false;
    }
    
    // Validate header
    if (header.magic != PROTOCOL_MAGIC) {
        metrics_->record_protocol_error();
        return false;
    }
    
    // Check data length limits
    if (header.data_length > MAX_MESSAGE_SIZE) {
        metrics_->record_protocol_error();
        return false;
    }
    
    // Calculate total message size and receive complete message
    size_t total_size = HEADER_SIZE + header.data_length;
    std::vector<uint8_t> message_buffer(total_size);
    
    // Copy header to buffer
    std::memcpy(message_buffer.data(), &header, sizeof(header));
    
    // Read data payload if present
    if (header.data_length > 0) {
        bytes_read = connection.read(message_buffer.data() + HEADER_SIZE, header.data_length);
        if (bytes_read != static_cast<int>(header.data_length)) {
            return false;
        }
    }
    
    metrics_->record_bytes_received(total_size);
    metrics_->record_message_received();
    metrics_->record_request_start();
    
    auto request_start = std::chrono::steady_clock::now();
    
    // Deserialize the complete message
    BinaryMessage request;
    if (!request.deserialize(message_buffer)) {
        metrics_->record_protocol_error();
        return false;
    }
    
    // Process request - for now just echo back a success response
    BinaryMessage response;
    
    // Create appropriate response based on request type
    switch (request.type()) {
        case MessageType::PUT_REQUEST:
            response = MessageBuilder::create_put_response(request.message_id(), StatusCode::SUCCESS);
            break;
        case MessageType::GET_REQUEST:
            response = MessageBuilder::create_get_response(request.message_id(), StatusCode::KEY_NOT_FOUND);
            break;
        case MessageType::DELETE_REQUEST:
            response = MessageBuilder::create_delete_response(request.message_id(), StatusCode::SUCCESS);
            break;
        case MessageType::QUERY_REQUEST:
            response = MessageBuilder::create_query_response(request.message_id(), StatusCode::SUCCESS);
            break;
        case MessageType::PING:
            response = MessageBuilder::create_pong(request.message_id());
            break;
        default:
            response = MessageBuilder::create_error(request.message_id(), StatusCode::UNSUPPORTED_VERSION);
            break;
    }
    
    // Send response
    std::vector<uint8_t> response_data = response.serialize();
    int bytes_sent = connection.write(response_data.data(), response_data.size());
    bool success = (bytes_sent == static_cast<int>(response_data.size()));
    
    if (success) {
        metrics_->record_bytes_sent(response_data.size());
        metrics_->record_message_sent();
    }
    
    // Record request completion
    auto request_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - request_start);
    metrics_->record_request_end(request_time, success);
    
    // Record request type for metrics
    std::string op_type;
    switch (request.type()) {
        case MessageType::PUT_REQUEST:
            op_type = "PUT"; break;
        case MessageType::GET_REQUEST:
            op_type = "GET"; break;
        case MessageType::DELETE_REQUEST:
            op_type = "DELETE"; break;
        case MessageType::QUERY_REQUEST:
            op_type = "QUERY"; break;
        case MessageType::BATCH_REQUEST:
            op_type = "BATCH"; break;
        case MessageType::PING:
            op_type = "PING"; break;
        default:
            op_type = "UNKNOWN"; break;
    }
    metrics_->record_request_by_type(op_type);
    
    return success;
}

bool TLSServer::reload_certificates() {
    std::lock_guard<std::mutex> lock(ssl_mutex_);
    
    if (!ssl_context_) {
        return false;
    }
    
    // Try to load new certificates
    if (!load_certificates(ssl_context_)) {
        std::cerr << "Failed to reload certificates" << std::endl;
        return false;
    }
    
    std::cout << "Certificates reloaded successfully" << std::endl;
    return true;
}

bool TLSServer::is_certificate_valid() const {
    return tls_utils::validate_certificate_file(config_.tls_config.cert_file) &&
           tls_utils::validate_private_key_file(config_.tls_config.key_file) &&
           tls_utils::validate_certificate_key_pair(config_.tls_config.cert_file, config_.tls_config.key_file);
}

std::chrono::system_clock::time_point TLSServer::get_certificate_expiry() const {
    return extract_cert_expiry(config_.tls_config.cert_file);
}

std::chrono::system_clock::time_point TLSServer::extract_cert_expiry(const std::string& cert_file) const {
    return tls_utils::get_certificate_expiry(cert_file);
}

void TLSServer::set_client_cert_verify_callback(ClientCertVerifyCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    client_cert_callback_ = callback;
}

void TLSServer::set_cipher_validate_callback(CipherValidateCallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    cipher_callback_ = callback;
}

void TLSServer::set_sni_callback(SNICallback callback) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    sni_callback_ = callback;
    
    if (ssl_context_) {
        SSL_CTX_set_tlsext_servername_callback(ssl_context_, sni_callback);
        SSL_CTX_set_tlsext_servername_arg(ssl_context_, this);
    }
}

int TLSServer::verify_callback(int preverify_ok, X509_STORE_CTX* ctx) {
    // Custom verification logic can be added here
    return preverify_ok;
}

int TLSServer::sni_callback(SSL* ssl, int* ad, void* arg) {
    TLSServer* server = static_cast<TLSServer*>(arg);
    std::lock_guard<std::mutex> lock(server->callback_mutex_);
    
    if (server->sni_callback_) {
        const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (servername) {
            SSL_CTX* new_ctx = server->sni_callback_(servername);
            if (new_ctx) {
                SSL_set_SSL_CTX(ssl, new_ctx);
                return SSL_TLSEXT_ERR_OK;
            }
        }
    }
    
    return SSL_TLSEXT_ERR_NOACK;
}

void TLSServer::log_ssl_error(const std::string& operation) const {
    unsigned long error = ERR_get_error();
    char error_buffer[256];
    ERR_error_string_n(error, error_buffer, sizeof(error_buffer));
    std::cerr << "SSL Error in " << operation << ": " << error_buffer << std::endl;
}

std::string TLSServer::get_ssl_error_string(int error_code) const {
    switch (error_code) {
        case SSL_ERROR_NONE: return "SSL_ERROR_NONE";
        case SSL_ERROR_SSL: return "SSL_ERROR_SSL";
        case SSL_ERROR_WANT_READ: return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE: return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP: return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL: return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_ZERO_RETURN: return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_CONNECT: return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT: return "SSL_ERROR_WANT_ACCEPT";
        default: return "Unknown SSL error";
    }
}

} // namespace network
} // namespace nosql_db