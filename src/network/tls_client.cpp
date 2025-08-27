#include "network/tls_server.hpp"
#include "network/binary_protocol.hpp"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/x509v3.h>
#include <cstring>
#include <thread>

namespace nosql_db {
namespace network {

// TLSClient Implementation
TLSClient::TLSClient()
    : TLSClient(ClientConfig{}) {
}

TLSClient::TLSClient(const ClientConfig& config)
    : config_(config), ssl_context_(nullptr), ssl_initialized_(false) {
}

TLSClient::~TLSClient() {
    disconnect();
    cleanup_ssl();
}

bool TLSClient::connect() {
    std::lock_guard<std::mutex> connection_lock(connection_mutex_);
    
    if (is_connected()) {
        return true;
    }
    
    // Initialize SSL if not already done
    if (!initialize_ssl()) {
        std::cerr << "Failed to initialize SSL" << std::endl;
        return false;
    }
    
    // Create socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return false;
    }
    
    // Set connection timeout
    struct timeval timeout;
    timeout.tv_sec = static_cast<long>(config_.connection_timeout.count());
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // Resolve hostname
    struct hostent* server = gethostbyname(config_.host.c_str());
    if (!server) {
        std::cerr << "Failed to resolve hostname: " << config_.host << std::endl;
        close(sock);
        return false;
    }
    
    // Connect to server
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config_.port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    
    if (::connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to connect to " << config_.host << ":" << config_.port << std::endl;
        close(sock);
        return false;
    }
    
    // Create SSL connection
    SSL* ssl = SSL_new(ssl_context_);
    if (!ssl) {
        log_ssl_error("SSL_new");
        close(sock);
        return false;
    }
    
    if (SSL_set_fd(ssl, sock) != 1) {
        log_ssl_error("SSL_set_fd");
        SSL_free(ssl);
        close(sock);
        return false;
    }
    
    // Set hostname for SNI and certificate verification
    if (config_.verify_hostname) {
        const std::string& hostname = config_.expected_hostname.empty() ? 
                                     config_.host : config_.expected_hostname;
        SSL_set_tlsext_host_name(ssl, hostname.c_str());
    }
    
    connection_ = std::make_unique<TLSConnection>(ssl, sock);
    
    // Perform SSL handshake with timeout
    timeout.tv_sec = static_cast<long>(config_.ssl_handshake_timeout.count());
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    if (!perform_ssl_handshake()) {
        std::cerr << "SSL handshake failed" << std::endl;
        connection_.reset();
        return false;
    }
    
    // Verify server certificate
    if (config_.verify_server_cert && !verify_server_certificate()) {
        std::cerr << "Server certificate verification failed" << std::endl;
        connection_.reset();
        return false;
    }
    
    // Set normal operation timeouts
    timeout.tv_sec = static_cast<long>(config_.request_timeout.count());
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    std::cout << "TLS connection established to " << config_.host << ":" << config_.port << std::endl;
    std::cout << "Protocol: " << get_protocol_version() 
              << ", Cipher: " << get_cipher_name() << std::endl;
    
    return true;
}

void TLSClient::disconnect() {
    std::lock_guard<std::mutex> connection_lock(connection_mutex_);
    
    if (connection_) {
        connection_->shutdown_connection();
        connection_.reset();
    }
}

bool TLSClient::is_connected() const {
    std::lock_guard<std::mutex> connection_lock(connection_mutex_);
    return connection_ && connection_->is_connected() && connection_->is_handshake_complete();
}

bool TLSClient::reconnect() {
    disconnect();
    return connect();
}

bool TLSClient::initialize_ssl() {
    if (ssl_initialized_) {
        return true;
    }
    
    std::lock_guard<std::mutex> ssl_lock(ssl_mutex_);
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    ssl_context_ = create_ssl_context();
    if (!ssl_context_) {
        return false;
    }
    
    if (!configure_ssl_context(ssl_context_)) {
        SSL_CTX_free(ssl_context_);
        ssl_context_ = nullptr;
        return false;
    }
    
    ssl_initialized_ = true;
    return true;
}

void TLSClient::cleanup_ssl() {
    std::lock_guard<std::mutex> ssl_lock(ssl_mutex_);
    
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

SSL_CTX* TLSClient::create_ssl_context() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        log_ssl_error("SSL_CTX_new");
        return nullptr;
    }
    
    return ctx;
}

bool TLSClient::configure_ssl_context(SSL_CTX* ctx) {
    // Set TLS version range
    SSL_CTX_set_min_proto_version(ctx, config_.min_tls_version);
    SSL_CTX_set_max_proto_version(ctx, config_.max_tls_version);
    
    // Set cipher list
    if (!config_.cipher_list.empty()) {
        if (SSL_CTX_set_cipher_list(ctx, config_.cipher_list.c_str()) != 1) {
            log_ssl_error("SSL_CTX_set_cipher_list");
            return false;
        }
    }
    
    // Load client certificate and key if provided
    if (!config_.cert_file.empty() && !config_.key_file.empty()) {
        if (SSL_CTX_use_certificate_file(ctx, config_.cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            log_ssl_error("SSL_CTX_use_certificate_file");
            return false;
        }
        
        if (SSL_CTX_use_PrivateKey_file(ctx, config_.key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
            log_ssl_error("SSL_CTX_use_PrivateKey_file");
            return false;
        }
        
        if (!SSL_CTX_check_private_key(ctx)) {
            std::cerr << "Client private key does not match certificate" << std::endl;
            return false;
        }
    }
    
    // Configure server certificate verification
    if (config_.verify_server_cert) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_verify_depth(ctx, config_.verify_depth);
        
        // Load CA certificates
        if (!config_.ca_file.empty()) {
            if (SSL_CTX_load_verify_locations(ctx, config_.ca_file.c_str(), nullptr) != 1) {
                log_ssl_error("SSL_CTX_load_verify_locations (file)");
                return false;
            }
        }
        
        if (!config_.ca_path.empty()) {
            if (SSL_CTX_load_verify_locations(ctx, nullptr, config_.ca_path.c_str()) != 1) {
                log_ssl_error("SSL_CTX_load_verify_locations (path)");
                return false;
            }
        }
        
        // Use default CA locations if no custom CA specified
        if (config_.ca_file.empty() && config_.ca_path.empty()) {
            if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
                log_ssl_error("SSL_CTX_set_default_verify_paths");
                return false;
            }
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }
    
    // Configure session reuse
    if (config_.enable_session_reuse) {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
    } else {
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    }
    
    // Security options
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, options);
    
    return true;
}

bool TLSClient::perform_ssl_handshake() {
    if (!connection_) {
        return false;
    }
    
    auto start_time = std::chrono::steady_clock::now();
    
    while (!connection_->is_handshake_complete()) {
        SSL* ssl = connection_->ssl_handle();
        int result = SSL_connect(ssl);
        
        if (result <= 0) {
            int error = SSL_get_error(ssl, result);
            if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                // Check timeout
                auto elapsed = std::chrono::steady_clock::now() - start_time;
                if (elapsed > config_.ssl_handshake_timeout) {
                    std::cerr << "SSL handshake timeout" << std::endl;
                    return false;
                }
                
                // Brief sleep before retry
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            
            log_ssl_error("SSL_connect");
            return false;
        }
        
        // Handshake completed
        break;
    }
    
    return true;
}

bool TLSClient::verify_server_certificate() {
    if (!connection_) {
        return false;
    }
    
    SSL* ssl = connection_->ssl_handle();
    
    // Get server certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        std::cerr << "No server certificate presented" << std::endl;
        return false;
    }
    
    // Check verification result
    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        std::cerr << "Certificate verification failed: " 
                  << X509_verify_cert_error_string(verify_result) << std::endl;
        X509_free(cert);
        return false;
    }
    
    // Verify hostname if requested
    if (config_.verify_hostname) {
        const std::string& hostname = config_.expected_hostname.empty() ? 
                                     config_.host : config_.expected_hostname;
        if (!verify_hostname(cert, hostname)) {
            std::cerr << "Hostname verification failed" << std::endl;
            X509_free(cert);
            return false;
        }
    }
    
    X509_free(cert);
    return true;
}

bool TLSClient::verify_hostname(X509* cert, const std::string& hostname) {
    // Check Subject Alternative Names (SAN)
    STACK_OF(GENERAL_NAME)* san_names = static_cast<STACK_OF(GENERAL_NAME)*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    
    if (san_names) {
        int san_count = sk_GENERAL_NAME_num(san_names);
        for (int i = 0; i < san_count; ++i) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(san_names, i);
            if (name->type == GEN_DNS) {
                const unsigned char* dns_data = ASN1_STRING_get0_data(name->d.dNSName);
                char* dns_name = reinterpret_cast<char*>(const_cast<unsigned char*>(dns_data));
                if (dns_name && hostname == dns_name) {
                    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                    return true;
                }
            }
        }
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    }
    
    // Check Common Name in Subject
    X509_NAME* subject = X509_get_subject_name(cert);
    char common_name[256];
    if (X509_NAME_get_text_by_NID(subject, NID_commonName, common_name, sizeof(common_name)) > 0) {
        return hostname == common_name;
    }
    
    return false;
}

// Protocol operations
bool TLSClient::put(const std::string& key, const std::string& value) {
    if (!is_connected()) {
        return false;
    }
    
    BinaryMessage request = BinaryProtocol::create_put_request(key, value);
    if (!send_message(request)) {
        return false;
    }
    
    BinaryMessage response;
    if (!receive_message(response)) {
        return false;
    }
    
    return response.header.status_code == static_cast<uint16_t>(StatusCode::SUCCESS);
}

std::optional<std::string> TLSClient::get(const std::string& key) {
    if (!is_connected()) {
        return std::nullopt;
    }
    
    BinaryMessage request = BinaryProtocol::create_get_request(key);
    if (!send_message(request)) {
        return std::nullopt;
    }
    
    BinaryMessage response;
    if (!receive_message(response)) {
        return std::nullopt;
    }
    
    if (response.header.status_code == static_cast<uint16_t>(StatusCode::SUCCESS)) {
        return BinaryProtocol::extract_value(response);
    }
    
    return std::nullopt;
}

bool TLSClient::delete_key(const std::string& key) {
    if (!is_connected()) {
        return false;
    }
    
    BinaryMessage request = BinaryProtocol::create_delete_request(key);
    if (!send_message(request)) {
        return false;
    }
    
    BinaryMessage response;
    if (!receive_message(response)) {
        return false;
    }
    
    return response.header.status_code == static_cast<uint16_t>(StatusCode::SUCCESS);
}

bool TLSClient::ping() {
    if (!is_connected()) {
        return false;
    }
    
    BinaryMessage request = BinaryProtocol::create_ping_request();
    if (!send_message(request)) {
        return false;
    }
    
    BinaryMessage response;
    if (!receive_message(response)) {
        return false;
    }
    
    return response.header.status_code == static_cast<uint16_t>(StatusCode::SUCCESS);
}

std::vector<std::pair<std::string, std::string>> TLSClient::query(const std::string& query_str) {
    if (!is_connected()) {
        return {};
    }
    
    BinaryMessage request = BinaryProtocol::create_query_request(query_str);
    if (!send_message(request)) {
        return {};
    }
    
    BinaryMessage response;
    if (!receive_message(response)) {
        return {};
    }
    
    if (response.header.status_code == static_cast<uint16_t>(StatusCode::SUCCESS)) {
        return BinaryProtocol::extract_query_results(response);
    }
    
    return {};
}

std::vector<StatusCode> TLSClient::batch_execute(const std::vector<BatchItem>& operations) {
    if (!is_connected()) {
        return std::vector<StatusCode>(operations.size(), StatusCode::NETWORK_ERROR);
    }
    
    // Convert to binary protocol batch items
    std::vector<BinaryProtocol::BatchItem> binary_items;
    for (const auto& op : operations) {
        BinaryProtocol::BatchItem::Operation binary_op;
        switch (op.op) {
            case BatchOperation::PUT:
                binary_op = BinaryProtocol::BatchItem::Operation::PUT;
                break;
            case BatchOperation::GET:
                binary_op = BinaryProtocol::BatchItem::Operation::GET;
                break;
            case BatchOperation::DELETE:
                binary_op = BinaryProtocol::BatchItem::Operation::DELETE;
                break;
        }
        binary_items.emplace_back(binary_op, op.key, op.value);
    }
    
    BinaryMessage request = BinaryProtocol::create_batch_request(binary_items);
    if (!send_message(request)) {
        return std::vector<StatusCode>(operations.size(), StatusCode::NETWORK_ERROR);
    }
    
    BinaryMessage response;
    if (!receive_message(response)) {
        return std::vector<StatusCode>(operations.size(), StatusCode::NETWORK_ERROR);
    }
    
    return BinaryProtocol::extract_batch_results(response);
}

bool TLSClient::send_message(const BinaryMessage& message) {
    if (!connection_) {
        return false;
    }
    
    // Send header
    int header_sent = connection_->write(&message.header, sizeof(message.header));
    if (header_sent != sizeof(message.header)) {
        return false;
    }
    
    // Send payload if present
    if (!message.payload.empty()) {
        int payload_sent = connection_->write(message.payload.data(), message.payload.size());
        if (payload_sent != static_cast<int>(message.payload.size())) {
            return false;
        }
    }
    
    return true;
}

bool TLSClient::receive_message(BinaryMessage& message) {
    if (!connection_) {
        return false;
    }
    
    // Receive header
    int header_received = connection_->read(&message.header, sizeof(message.header));
    if (header_received != sizeof(message.header)) {
        return false;
    }
    
    // Validate header
    if (message.header.magic != BinaryMessage::MAGIC) {
        return false;
    }
    
    // Receive payload if present
    message.payload.clear();
    if (message.header.payload_size > 0) {
        message.payload.resize(message.header.payload_size);
        int payload_received = connection_->read(message.payload.data(), message.header.payload_size);
        if (payload_received != static_cast<int>(message.header.payload_size)) {
            return false;
        }
    }
    
    return true;
}

// TLS-specific getters
std::string TLSClient::get_server_certificate_subject() const {
    return connection_ ? connection_->get_peer_certificate_subject() : "";
}

std::string TLSClient::get_server_certificate_issuer() const {
    return connection_ ? connection_->get_peer_certificate_issuer() : "";
}

std::string TLSClient::get_cipher_name() const {
    return connection_ ? connection_->get_cipher_name() : "";
}

std::string TLSClient::get_protocol_version() const {
    return connection_ ? connection_->get_protocol_version() : "";
}

bool TLSClient::is_server_cert_verified() const {
    return connection_ ? connection_->is_client_cert_verified() : false;
}

void TLSClient::log_ssl_error(const std::string& operation) const {
    unsigned long error = ERR_get_error();
    char error_buffer[256];
    ERR_error_string_n(error, error_buffer, sizeof(error_buffer));
    std::cerr << "SSL Error in " << operation << ": " << error_buffer << std::endl;
}

std::string TLSClient::get_ssl_error_string(int error_code) const {
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