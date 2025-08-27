#pragma once

#include <string>
#include <memory>
#include <chrono>
#include <functional>
#include <thread>
#include <vector>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include "binary_protocol.hpp"

namespace nosql_db {
namespace network {

// Forward declarations
class StorageEngine;
class NetworkMetrics;
class ConnectionPool;

/**
 * TLS/SSL Configuration for secure connections
 */
struct TLSConfig {
    // Certificate and key paths
    std::string cert_file = "server.crt";
    std::string key_file = "server.key";
    std::string ca_file;  // For client certificate verification (optional)
    
    // TLS version settings
    int min_tls_version = TLS1_2_VERSION;
    int max_tls_version = TLS1_3_VERSION;
    
    // Cipher suite configuration
    std::string cipher_list = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS";
    std::string cipher_suites; // TLS 1.3 cipher suites
    
    // Client certificate verification
    bool require_client_cert = false;
    bool verify_client_cert = false;
    int verify_depth = 9;
    
    // Session settings
    bool enable_session_reuse = true;
    std::chrono::seconds session_timeout{300}; // 5 minutes
    
    // OCSP (Online Certificate Status Protocol)
    bool enable_ocsp_stapling = false;
    
    // Certificate transparency
    bool enable_sct_extension = false;
    
    // Security options
    bool disable_compression = true;  // Prevent CRIME attacks
    bool enable_secure_renegotiation = true;
    bool disable_legacy_renegotiation = true;
};

/**
 * TLS Connection context for individual client connections
 */
class TLSConnection {
public:
    TLSConnection(SSL* ssl, int socket_fd);
    ~TLSConnection();
    
    // Connection management
    bool perform_handshake();
    bool is_connected() const { return connected_; }
    bool is_handshake_complete() const { return handshake_complete_; }
    
    // I/O operations
    int read(void* buffer, size_t length);
    int write(const void* buffer, size_t length);
    bool shutdown_connection();
    
    // Certificate information
    std::string get_peer_certificate_subject() const;
    std::string get_peer_certificate_issuer() const;
    std::string get_cipher_name() const;
    std::string get_protocol_version() const;
    
    // Security information
    bool is_client_cert_verified() const;
    long get_verify_result() const;
    
    // Connection details
    int socket() const { return socket_fd_; }
    SSL* ssl_handle() const { return ssl_; }
    
private:
    SSL* ssl_;
    int socket_fd_;
    bool connected_;
    bool handshake_complete_;
    mutable std::string cached_peer_subject_;
    mutable std::string cached_peer_issuer_;
};

/**
 * TLS/SSL Server implementation
 * Extends the binary server with SSL/TLS encryption
 */
class TLSServer {
public:
    struct ServerConfig {
        // Base server configuration
        std::string host = "0.0.0.0";
        uint16_t port = 9443;  // Standard HTTPS-like port
        int backlog = 128;
        
        // Worker configuration
        int worker_threads = 4;
        int max_connections_per_worker = 1000;
        
        // TLS configuration
        TLSConfig tls_config;
        
        // Connection pool configuration
        struct {
            int max_connections = 10000;
            int max_connections_per_ip = 100;
            std::chrono::seconds session_timeout{300};
            bool enable_rate_limiting = true;
            int requests_per_second_limit = 1000;
        } pool_config;
        
        // Timeouts
        std::chrono::seconds connection_timeout{30};
        std::chrono::seconds request_timeout{60};
        std::chrono::seconds ssl_handshake_timeout{10};
        
        // Security settings
        bool enable_perfect_forward_secrecy = true;
        bool enable_hsts = true;  // HTTP Strict Transport Security
        std::chrono::seconds hsts_max_age{31536000}; // 1 year
        
        // Logging
        bool enable_access_log = true;
        bool enable_security_log = true;
        std::string log_file = "tls_server.log";
    };
    
    explicit TLSServer(std::shared_ptr<StorageEngine> storage);
    explicit TLSServer(std::shared_ptr<StorageEngine> storage, 
                       const ServerConfig& config);
    ~TLSServer();
    
    // Server lifecycle
    bool start();
    void stop();
    bool is_running() const { return running_; }
    
    // Configuration
    const ServerConfig& config() const { return config_; }
    const TLSConfig& tls_config() const { return config_.tls_config; }
    
    // Statistics
    std::shared_ptr<NetworkMetrics> metrics() const { return metrics_; }
    std::shared_ptr<ConnectionPool> connection_pool() const { return connection_pool_; }
    
    // Certificate management
    bool reload_certificates();
    bool is_certificate_valid() const;
    std::chrono::system_clock::time_point get_certificate_expiry() const;
    
    // Security policies
    using ClientCertVerifyCallback = std::function<bool(const std::string& subject, 
                                                       const std::string& issuer,
                                                       long verify_result)>;
    void set_client_cert_verify_callback(ClientCertVerifyCallback callback);
    
    // Custom cipher suite validation
    using CipherValidateCallback = std::function<bool(const std::string& cipher)>;
    void set_cipher_validate_callback(CipherValidateCallback callback);
    
    // SNI (Server Name Indication) support
    using SNICallback = std::function<SSL_CTX*(const std::string& hostname)>;
    void set_sni_callback(SNICallback callback);
    
private:
    // SSL/TLS initialization
    bool initialize_ssl();
    void cleanup_ssl();
    SSL_CTX* create_ssl_context();
    bool configure_ssl_context(SSL_CTX* ctx);
    bool load_certificates(SSL_CTX* ctx);
    bool setup_cipher_suites(SSL_CTX* ctx);
    
    // Certificate utilities
    bool verify_certificate_chain(const std::string& cert_file);
    std::chrono::system_clock::time_point extract_cert_expiry(const std::string& cert_file) const;
    
    // Connection handling
    void worker_thread(int worker_id);
    bool handle_connection(std::unique_ptr<TLSConnection> connection);
    std::unique_ptr<TLSConnection> accept_tls_connection(int client_socket);
    
    // Protocol handling (delegates to binary protocol)
    bool process_binary_message(TLSConnection& connection);
    
    // Security callbacks
    static int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);
    static int sni_callback(SSL* ssl, int* ad, void* arg);
    
    // Error handling
    void log_ssl_error(const std::string& operation) const;
    std::string get_ssl_error_string(int error_code) const;
    
    // Server state
    ServerConfig config_;
    std::shared_ptr<StorageEngine> storage_;
    std::shared_ptr<NetworkMetrics> metrics_;
    std::shared_ptr<ConnectionPool> connection_pool_;
    
    // SSL/TLS state
    SSL_CTX* ssl_context_;
    bool ssl_initialized_;
    
    // Network state
    int server_socket_;
    bool running_;
    std::vector<std::thread> worker_threads_;
    
    // Security callbacks
    ClientCertVerifyCallback client_cert_callback_;
    CipherValidateCallback cipher_callback_;
    SNICallback sni_callback_;
    
    // Synchronization
    mutable std::mutex ssl_mutex_;
    mutable std::mutex callback_mutex_;
    std::condition_variable shutdown_cv_;
};

/**
 * TLS-enabled Binary Client
 * Client counterpart that connects to TLSServer
 */
class TLSClient {
public:
    struct ClientConfig {
        // Connection settings
        std::string host = "localhost";
        uint16_t port = 9443;
        std::chrono::seconds connection_timeout{30};
        std::chrono::seconds request_timeout{60};
        std::chrono::seconds ssl_handshake_timeout{10};
        
        // TLS client configuration
        std::string cert_file;     // Client certificate (if required)
        std::string key_file;      // Client private key
        std::string ca_file;       // CA certificate for server verification
        std::string ca_path;       // CA certificate directory
        
        // Verification settings
        bool verify_server_cert = true;
        bool verify_hostname = true;
        std::string expected_hostname; // Override for hostname verification
        int verify_depth = 9;
        
        // TLS version settings  
        int min_tls_version = TLS1_2_VERSION;
        int max_tls_version = TLS1_3_VERSION;
        
        // Cipher preferences
        std::string cipher_list = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS";
        
        // Session reuse
        bool enable_session_reuse = true;
        
        // Retry settings
        int max_retries = 3;
        std::chrono::milliseconds retry_delay{1000};
        
        // Connection pooling (for multiple concurrent connections)
        bool enable_keepalive = true;
        int max_idle_connections = 5;
        std::chrono::seconds idle_timeout{60};
    };
    
    TLSClient();
    explicit TLSClient(const ClientConfig& config);
    ~TLSClient();
    
    // Connection management
    bool connect();
    void disconnect();
    bool is_connected() const;
    bool reconnect();
    
    // Binary protocol operations (same as BinaryClient but over TLS)
    bool put(const std::string& key, const std::string& value);
    std::optional<std::string> get(const std::string& key);
    bool delete_key(const std::string& key);
    bool ping();
    
    // Query operations
    std::vector<std::pair<std::string, std::string>> query(const std::string& query_str);
    
    // Batch operations
    enum class BatchOperation { PUT, GET, DELETE };
    struct BatchItem {
        BatchOperation op;
        std::string key;
        std::string value;
    };
    std::vector<StatusCode> batch_execute(const std::vector<BatchItem>& operations);
    
    // TLS-specific operations
    std::string get_server_certificate_subject() const;
    std::string get_server_certificate_issuer() const;
    std::string get_cipher_name() const;
    std::string get_protocol_version() const;
    bool is_server_cert_verified() const;
    
    // Configuration
    const ClientConfig& config() const { return config_; }
    
private:
    // SSL initialization
    bool initialize_ssl();
    void cleanup_ssl();
    SSL_CTX* create_ssl_context();
    bool configure_ssl_context(SSL_CTX* ctx);
    
    // Connection utilities
    bool perform_ssl_handshake();
    bool verify_server_certificate();
    bool verify_hostname(X509* cert, const std::string& hostname);
    
    // Protocol operations
    bool send_message(const BinaryMessage& message);
    bool receive_message(BinaryMessage& message);
    
    // Error handling
    void log_ssl_error(const std::string& operation) const;
    std::string get_ssl_error_string(int error_code) const;
    
    // Configuration and state
    ClientConfig config_;
    
    // SSL state
    SSL_CTX* ssl_context_;
    std::unique_ptr<TLSConnection> connection_;
    bool ssl_initialized_;
    
    // Synchronization
    mutable std::mutex ssl_mutex_;
    mutable std::mutex connection_mutex_;
};

// Utility functions for TLS/SSL management
namespace tls_utils {

/**
 * Generate self-signed certificate for testing
 */
struct CertificateInfo {
    std::string common_name = "localhost";
    std::string organization = "NoSQL DB";
    std::string country = "US";
    int validity_days = 365;
    int key_size = 2048;
};

bool generate_self_signed_certificate(const std::string& cert_file,
                                     const std::string& key_file);
bool generate_self_signed_certificate(const std::string& cert_file,
                                     const std::string& key_file,
                                     const CertificateInfo& info);

/**
 * Validate certificate file
 */
bool validate_certificate_file(const std::string& cert_file);
bool validate_private_key_file(const std::string& key_file);
bool validate_certificate_key_pair(const std::string& cert_file, 
                                  const std::string& key_file);

/**
 * Certificate information extraction
 */
std::chrono::system_clock::time_point get_certificate_expiry(const std::string& cert_file);
std::string get_certificate_subject(const std::string& cert_file);
std::string get_certificate_issuer(const std::string& cert_file);
std::vector<std::string> get_certificate_san_list(const std::string& cert_file);

/**
 * SSL/TLS version utilities
 */
std::string tls_version_to_string(int version);
int string_to_tls_version(const std::string& version);
std::vector<std::string> get_supported_ciphers(SSL_CTX* ctx);

} // namespace tls_utils

} // namespace network
} // namespace nosql_db