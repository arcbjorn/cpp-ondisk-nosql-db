#pragma once

#include <string>
#include <chrono>
#include <vector>
#include <memory>
#include <fstream>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <queue>
#include <thread>
#include <condition_variable>
#include <functional>

namespace nosql_db::security {

/**
 * Audit event types for comprehensive logging
 */
enum class AuditEventType : uint16_t {
    // Authentication events
    AUTH_LOGIN_SUCCESS = 1000,
    AUTH_LOGIN_FAILURE = 1001,
    AUTH_LOGOUT = 1002,
    AUTH_TOKEN_ISSUED = 1003,
    AUTH_TOKEN_EXPIRED = 1004,
    AUTH_TOKEN_REVOKED = 1005,
    AUTH_PASSWORD_CHANGED = 1006,
    AUTH_ACCOUNT_LOCKED = 1007,
    
    // Authorization events
    AUTHZ_ACCESS_GRANTED = 2000,
    AUTHZ_ACCESS_DENIED = 2001,
    AUTHZ_PERMISSION_CHANGED = 2002,
    AUTHZ_ROLE_ASSIGNED = 2003,
    AUTHZ_ROLE_REMOVED = 2004,
    
    // Data access events
    DATA_READ = 3000,
    DATA_WRITE = 3001,
    DATA_DELETE = 3002,
    DATA_QUERY = 3003,
    DATA_BATCH_OPERATION = 3004,
    DATA_STREAM_START = 3005,
    DATA_STREAM_END = 3006,
    
    // Administrative events
    ADMIN_USER_CREATED = 4000,
    ADMIN_USER_DELETED = 4001,
    ADMIN_USER_MODIFIED = 4002,
    ADMIN_CONFIG_CHANGED = 4003,
    ADMIN_BACKUP_CREATED = 4004,
    ADMIN_RESTORE_PERFORMED = 4005,
    ADMIN_SYSTEM_SHUTDOWN = 4006,
    ADMIN_SYSTEM_STARTUP = 4007,
    
    // Security events
    SECURITY_TLS_CONNECTION = 5000,
    SECURITY_CERTIFICATE_EXPIRED = 5001,
    SECURITY_INTRUSION_DETECTED = 5002,
    SECURITY_RATE_LIMIT_EXCEEDED = 5003,
    SECURITY_SUSPICIOUS_ACTIVITY = 5004,
    SECURITY_ENCRYPTION_KEY_ROTATED = 5005,
    
    // Error events
    ERROR_SYSTEM = 6000,
    ERROR_STORAGE = 6001,
    ERROR_NETWORK = 6002,
    ERROR_PROTOCOL = 6003,
    ERROR_CONFIGURATION = 6004,
    
    // Custom events (for application-specific logging)
    CUSTOM_EVENT = 9000
};

/**
 * Audit event severity levels
 */
enum class AuditSeverity : uint8_t {
    INFO = 0,
    WARNING = 1,
    ERROR = 2,
    CRITICAL = 3
};

/**
 * Individual audit event record
 */
struct AuditEvent {
    uint64_t event_id;                          // Unique event identifier
    AuditEventType event_type;                  // Type of event
    AuditSeverity severity;                     // Event severity
    std::chrono::system_clock::time_point timestamp; // When the event occurred
    
    // Context information
    std::string user_id;                        // User who performed the action
    std::string session_id;                     // Session identifier
    std::string client_address;                 // Client IP address
    std::string user_agent;                     // Client application/library
    
    // Event details
    std::string resource;                       // Resource accessed (key, table, etc.)
    std::string operation;                      // Specific operation performed
    std::string result;                         // Success/failure/error code
    
    // Additional context (JSON-formatted)
    std::string metadata;                       // Flexible additional data
    
    // Performance metrics
    std::chrono::microseconds duration{0};     // Operation duration
    size_t bytes_processed{0};                  // Data volume involved
    
    AuditEvent() : event_id(0), event_type(AuditEventType::CUSTOM_EVENT), 
                   severity(AuditSeverity::INFO), timestamp(std::chrono::system_clock::now()) {}
};

/**
 * Audit log configuration
 */
struct AuditConfig {
    // Output destinations
    bool enable_file_logging = true;
    bool enable_console_logging = false;
    bool enable_syslog_logging = false;
    bool enable_remote_logging = false;
    
    // File settings
    std::string log_file = "audit.log";
    std::string log_directory = "./logs";
    size_t max_file_size_mb = 100;              // Max size before rotation
    int max_log_files = 10;                     // Number of rotated files to keep
    bool compress_rotated_files = true;
    
    // Buffering and performance
    bool enable_async_logging = true;
    size_t buffer_size = 10000;                 // Events to buffer before flush
    std::chrono::milliseconds flush_interval{5000}; // Auto-flush interval
    int worker_threads = 2;                     // Background logging threads
    
    // Filtering
    AuditSeverity min_severity = AuditSeverity::INFO;
    std::vector<AuditEventType> excluded_events; // Events to ignore
    std::vector<AuditEventType> critical_events; // Always log these
    
    // Security settings
    bool enable_log_encryption = false;
    std::string encryption_key;
    bool enable_log_signing = false;
    bool enable_tamper_detection = true;
    
    // Remote logging (syslog/centralized)
    std::string syslog_server;
    int syslog_port = 514;
    std::string syslog_facility = "local0";
    
    // Retention policy
    std::chrono::hours retention_period{24 * 30 * 12}; // 1 year default
    bool enable_auto_cleanup = true;
    
    // Privacy settings
    bool anonymize_ip_addresses = false;
    bool redact_sensitive_data = true;
    std::vector<std::string> sensitive_fields = {"password", "token", "key"};
};

/**
 * Main audit logging system
 */
class AuditLogger {
public:
    explicit AuditLogger(const AuditConfig& config = {});
    ~AuditLogger();
    
    // Lifecycle management
    bool start();
    void stop();
    bool is_running() const { return running_; }
    
    // Event logging interface
    void log_event(const AuditEvent& event);
    void log_event(AuditEventType type, AuditSeverity severity, 
                   const std::string& user_id, const std::string& operation,
                   const std::string& resource = "", const std::string& result = "SUCCESS");
    
    // Convenience methods for common events
    void log_authentication(const std::string& user_id, const std::string& client_address, 
                           bool success, const std::string& details = "");
    void log_authorization(const std::string& user_id, const std::string& resource, 
                          const std::string& operation, bool granted, const std::string& reason = "");
    void log_data_access(const std::string& user_id, const std::string& operation,
                        const std::string& resource, bool success, 
                        size_t bytes_processed = 0, std::chrono::microseconds duration = {});
    void log_admin_action(const std::string& user_id, const std::string& action,
                         const std::string& target, bool success, const std::string& details = "");
    void log_security_event(const std::string& event_description, AuditSeverity severity,
                           const std::string& client_address = "", const std::string& details = "");
    void log_error(const std::string& error_type, const std::string& error_message,
                   const std::string& context = "", AuditSeverity severity = AuditSeverity::ERROR);
    
    // Query and analysis
    std::vector<AuditEvent> query_events(
        const std::chrono::system_clock::time_point& start_time,
        const std::chrono::system_clock::time_point& end_time,
        const std::vector<AuditEventType>& event_types = {},
        const std::string& user_id = "",
        AuditSeverity min_severity = AuditSeverity::INFO) const;
    
    // Statistics and monitoring
    struct AuditStats {
        std::atomic<uint64_t> total_events{0};
        std::atomic<uint64_t> events_written{0};
        std::atomic<uint64_t> events_dropped{0};
        std::atomic<uint64_t> buffer_overruns{0};
        std::atomic<uint64_t> write_errors{0};
        std::chrono::system_clock::time_point last_event_time;
        std::atomic<size_t> current_buffer_size{0};
        std::atomic<size_t> current_file_size{0};
    };
    
    const AuditStats& stats() const { return stats_; }
    void reset_stats();
    
    // Configuration management
    const AuditConfig& config() const { return config_; }
    bool update_config(const AuditConfig& new_config);
    
    // File management
    void rotate_log_files();
    void cleanup_old_logs();
    std::vector<std::string> get_log_files() const;
    
    // Security features
    bool verify_log_integrity() const;
    std::string generate_log_hash(const std::string& log_file) const;
    
private:
    // Core functionality
    void worker_thread();
    void flush_buffer();
    bool write_event(const AuditEvent& event);
    bool should_log_event(const AuditEvent& event) const;
    
    // File operations
    bool open_log_file();
    void close_log_file();
    bool rotate_if_needed();
    std::string format_event(const AuditEvent& event) const;
    std::string generate_filename() const;
    
    // Security functions
    std::string encrypt_log_entry(const std::string& entry) const;
    std::string decrypt_log_entry(const std::string& encrypted_entry) const;
    std::string sign_log_entry(const std::string& entry) const;
    bool verify_log_signature(const std::string& entry, const std::string& signature) const;
    
    // Utility functions
    uint64_t generate_event_id();
    std::string sanitize_data(const std::string& data) const;
    std::string anonymize_ip(const std::string& ip_address) const;
    
    // Configuration and state
    AuditConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdown_requested_{false};
    
    // Threading and synchronization
    std::vector<std::thread> worker_threads_;
    std::mutex buffer_mutex_;
    std::condition_variable buffer_cv_;
    std::condition_variable shutdown_cv_;
    
    // Event buffering
    std::queue<AuditEvent> event_buffer_;
    std::queue<AuditEvent> priority_buffer_; // For critical events
    
    // File handling
    std::unique_ptr<std::ofstream> log_file_;
    std::mutex file_mutex_;
    std::string current_log_filename_;
    
    // Statistics
    mutable AuditStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Event ID generation
    std::atomic<uint64_t> event_id_counter_{1};
    
    // Security state
    mutable std::mutex security_mutex_;
    std::string log_integrity_hash_;
};

/**
 * Audit event builder for complex events
 */
class AuditEventBuilder {
public:
    AuditEventBuilder(AuditEventType type, AuditSeverity severity = AuditSeverity::INFO);
    
    // Context setters
    AuditEventBuilder& user(const std::string& user_id);
    AuditEventBuilder& session(const std::string& session_id);
    AuditEventBuilder& client(const std::string& client_address);
    AuditEventBuilder& user_agent(const std::string& agent);
    
    // Event details
    AuditEventBuilder& resource(const std::string& resource);
    AuditEventBuilder& operation(const std::string& operation);
    AuditEventBuilder& result(const std::string& result);
    AuditEventBuilder& metadata(const std::string& metadata);
    
    // Performance metrics
    AuditEventBuilder& duration(std::chrono::microseconds duration);
    AuditEventBuilder& bytes_processed(size_t bytes);
    
    // Build the event
    AuditEvent build() const;
    
    // Convenience method to log directly
    void log_to(AuditLogger& logger) const;
    
private:
    AuditEvent event_;
};

/**
 * Global audit logger instance management
 */
class AuditManager {
public:
    static AuditLogger& instance();
    static bool initialize(const AuditConfig& config);
    static void shutdown();
    static bool is_initialized();
    
    // Convenience logging functions
    static void log_auth(const std::string& user_id, const std::string& client_address, bool success);
    static void log_access(const std::string& user_id, const std::string& operation, 
                          const std::string& resource, bool success);
    static void log_admin(const std::string& user_id, const std::string& action, 
                         const std::string& target, bool success);
    static void log_security(const std::string& event, AuditSeverity severity = AuditSeverity::WARNING);
    static void log_error(const std::string& error, const std::string& context = "");
    
private:
    static std::unique_ptr<AuditLogger> instance_;
    static std::mutex instance_mutex_;
    static std::atomic<bool> initialized_;
    
    AuditManager() = delete;
    ~AuditManager() = delete;
};

// Macros for convenient audit logging
#define AUDIT_AUTH(user, addr, success) \
    nosql_db::security::AuditManager::log_auth(user, addr, success)

#define AUDIT_ACCESS(user, op, resource, success) \
    nosql_db::security::AuditManager::log_access(user, op, resource, success)

#define AUDIT_ADMIN(user, action, target, success) \
    nosql_db::security::AuditManager::log_admin(user, action, target, success)

#define AUDIT_SECURITY(event, severity) \
    nosql_db::security::AuditManager::log_security(event, severity)

#define AUDIT_ERROR(error, context) \
    nosql_db::security::AuditManager::log_error(error, context)

} // namespace nosql_db::security