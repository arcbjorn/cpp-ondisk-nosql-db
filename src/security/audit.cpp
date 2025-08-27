#include "security/audit.hpp"
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <fstream>
#include <ctime>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <regex>

namespace nosql_db::security {

namespace {
    // Utility function to format timestamps
    std::string format_timestamp(const std::chrono::system_clock::time_point& tp) {
        auto time_t = std::chrono::system_clock::to_time_t(tp);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()) % 1000;
        
        std::ostringstream oss;
        oss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
        oss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
        return oss.str();
    }
    
    // Utility function to get event type name
    std::string event_type_to_string(AuditEventType type) {
        switch (type) {
            case AuditEventType::AUTH_LOGIN_SUCCESS: return "AUTH_LOGIN_SUCCESS";
            case AuditEventType::AUTH_LOGIN_FAILURE: return "AUTH_LOGIN_FAILURE";
            case AuditEventType::AUTH_LOGOUT: return "AUTH_LOGOUT";
            case AuditEventType::AUTH_TOKEN_ISSUED: return "AUTH_TOKEN_ISSUED";
            case AuditEventType::AUTH_TOKEN_EXPIRED: return "AUTH_TOKEN_EXPIRED";
            case AuditEventType::AUTH_TOKEN_REVOKED: return "AUTH_TOKEN_REVOKED";
            case AuditEventType::AUTH_PASSWORD_CHANGED: return "AUTH_PASSWORD_CHANGED";
            case AuditEventType::AUTH_ACCOUNT_LOCKED: return "AUTH_ACCOUNT_LOCKED";
            case AuditEventType::AUTHZ_ACCESS_GRANTED: return "AUTHZ_ACCESS_GRANTED";
            case AuditEventType::AUTHZ_ACCESS_DENIED: return "AUTHZ_ACCESS_DENIED";
            case AuditEventType::AUTHZ_PERMISSION_CHANGED: return "AUTHZ_PERMISSION_CHANGED";
            case AuditEventType::AUTHZ_ROLE_ASSIGNED: return "AUTHZ_ROLE_ASSIGNED";
            case AuditEventType::AUTHZ_ROLE_REMOVED: return "AUTHZ_ROLE_REMOVED";
            case AuditEventType::DATA_READ: return "DATA_READ";
            case AuditEventType::DATA_WRITE: return "DATA_WRITE";
            case AuditEventType::DATA_DELETE: return "DATA_DELETE";
            case AuditEventType::DATA_QUERY: return "DATA_QUERY";
            case AuditEventType::DATA_BATCH_OPERATION: return "DATA_BATCH_OPERATION";
            case AuditEventType::DATA_STREAM_START: return "DATA_STREAM_START";
            case AuditEventType::DATA_STREAM_END: return "DATA_STREAM_END";
            case AuditEventType::ADMIN_USER_CREATED: return "ADMIN_USER_CREATED";
            case AuditEventType::ADMIN_USER_DELETED: return "ADMIN_USER_DELETED";
            case AuditEventType::ADMIN_USER_MODIFIED: return "ADMIN_USER_MODIFIED";
            case AuditEventType::ADMIN_CONFIG_CHANGED: return "ADMIN_CONFIG_CHANGED";
            case AuditEventType::ADMIN_BACKUP_CREATED: return "ADMIN_BACKUP_CREATED";
            case AuditEventType::ADMIN_RESTORE_PERFORMED: return "ADMIN_RESTORE_PERFORMED";
            case AuditEventType::ADMIN_SYSTEM_SHUTDOWN: return "ADMIN_SYSTEM_SHUTDOWN";
            case AuditEventType::ADMIN_SYSTEM_STARTUP: return "ADMIN_SYSTEM_STARTUP";
            case AuditEventType::SECURITY_TLS_CONNECTION: return "SECURITY_TLS_CONNECTION";
            case AuditEventType::SECURITY_CERTIFICATE_EXPIRED: return "SECURITY_CERTIFICATE_EXPIRED";
            case AuditEventType::SECURITY_INTRUSION_DETECTED: return "SECURITY_INTRUSION_DETECTED";
            case AuditEventType::SECURITY_RATE_LIMIT_EXCEEDED: return "SECURITY_RATE_LIMIT_EXCEEDED";
            case AuditEventType::SECURITY_SUSPICIOUS_ACTIVITY: return "SECURITY_SUSPICIOUS_ACTIVITY";
            case AuditEventType::SECURITY_ENCRYPTION_KEY_ROTATED: return "SECURITY_ENCRYPTION_KEY_ROTATED";
            case AuditEventType::ERROR_SYSTEM: return "ERROR_SYSTEM";
            case AuditEventType::ERROR_STORAGE: return "ERROR_STORAGE";
            case AuditEventType::ERROR_NETWORK: return "ERROR_NETWORK";
            case AuditEventType::ERROR_PROTOCOL: return "ERROR_PROTOCOL";
            case AuditEventType::ERROR_CONFIGURATION: return "ERROR_CONFIGURATION";
            case AuditEventType::CUSTOM_EVENT: return "CUSTOM_EVENT";
            default: return "UNKNOWN_EVENT";
        }
    }
    
    std::string severity_to_string(AuditSeverity severity) {
        switch (severity) {
            case AuditSeverity::INFO: return "INFO";
            case AuditSeverity::WARNING: return "WARNING";
            case AuditSeverity::ERROR: return "ERROR";
            case AuditSeverity::CRITICAL: return "CRITICAL";
            default: return "UNKNOWN";
        }
    }
}

// AuditLogger Implementation
AuditLogger::AuditLogger(const AuditConfig& config) : config_(config) {
    // Create log directory if it doesn't exist
    if (config_.enable_file_logging) {
        std::error_code ec;
        std::filesystem::create_directories(config_.log_directory, ec);
        if (ec) {
            spdlog::error("Failed to create audit log directory {}: {}", config_.log_directory, ec.message());
        }
    }
}

AuditLogger::~AuditLogger() {
    stop();
}

bool AuditLogger::start() {
    if (running_.load()) {
        return true;
    }
    
    spdlog::info("Starting audit logger with {} worker threads", config_.worker_threads);
    
    // Open log file if file logging is enabled
    if (config_.enable_file_logging && !open_log_file()) {
        spdlog::error("Failed to open audit log file");
        return false;
    }
    
    running_.store(true);
    shutdown_requested_.store(false);
    
    // Start worker threads
    for (int i = 0; i < config_.worker_threads; ++i) {
        worker_threads_.emplace_back(&AuditLogger::worker_thread, this);
    }
    
    spdlog::info("Audit logger started successfully");
    return true;
}

void AuditLogger::stop() {
    if (!running_.load()) {
        return;
    }
    
    spdlog::info("Stopping audit logger...");
    
    shutdown_requested_.store(true);
    buffer_cv_.notify_all();
    
    // Wait for worker threads to finish
    for (auto& thread : worker_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    worker_threads_.clear();
    
    // Flush any remaining events
    flush_buffer();
    
    // Close log file
    close_log_file();
    
    running_.store(false);
    
    spdlog::info("Audit logger stopped. Final stats - Events: {}, Written: {}, Dropped: {}",
                stats_.total_events.load(), stats_.events_written.load(), stats_.events_dropped.load());
}

void AuditLogger::log_event(const AuditEvent& event) {
    if (!running_.load()) {
        stats_.events_dropped.fetch_add(1);
        return;
    }
    
    // Check if event should be logged
    if (!should_log_event(event)) {
        return;
    }
    
    stats_.total_events.fetch_add(1);
    stats_.last_event_time = event.timestamp;
    
    if (config_.enable_async_logging) {
        // Add to buffer for async processing
        std::unique_lock<std::mutex> lock(buffer_mutex_);
        
        // Check buffer size limits
        if (event_buffer_.size() >= config_.buffer_size) {
            // Drop oldest non-critical events if buffer is full
            if (event.severity != AuditSeverity::CRITICAL) {
                stats_.buffer_overruns.fetch_add(1);
                stats_.events_dropped.fetch_add(1);
                return;
            } else {
                // For critical events, force immediate processing
                lock.unlock();
                write_event(event);
                return;
            }
        }
        
        // Add to appropriate buffer
        if (event.severity == AuditSeverity::CRITICAL) {
            priority_buffer_.push(event);
        } else {
            event_buffer_.push(event);
        }
        
        stats_.current_buffer_size.store(event_buffer_.size() + priority_buffer_.size());
        buffer_cv_.notify_one();
    } else {
        // Synchronous logging
        write_event(event);
    }
}

void AuditLogger::log_event(AuditEventType type, AuditSeverity severity, 
                           const std::string& user_id, const std::string& operation,
                           const std::string& resource, const std::string& result) {
    AuditEvent event;
    event.event_id = generate_event_id();
    event.event_type = type;
    event.severity = severity;
    event.user_id = user_id;
    event.operation = operation;
    event.resource = resource;
    event.result = result;
    event.timestamp = std::chrono::system_clock::now();
    
    log_event(event);
}

void AuditLogger::log_authentication(const std::string& user_id, const std::string& client_address, 
                                     bool success, const std::string& details) {
    AuditEvent event;
    event.event_id = generate_event_id();
    event.event_type = success ? AuditEventType::AUTH_LOGIN_SUCCESS : AuditEventType::AUTH_LOGIN_FAILURE;
    event.severity = success ? AuditSeverity::INFO : AuditSeverity::WARNING;
    event.user_id = user_id;
    event.client_address = client_address;
    event.operation = "LOGIN";
    event.result = success ? "SUCCESS" : "FAILURE";
    event.metadata = details;
    event.timestamp = std::chrono::system_clock::now();
    
    log_event(event);
}

void AuditLogger::log_authorization(const std::string& user_id, const std::string& resource, 
                                   const std::string& operation, bool granted, const std::string& reason) {
    AuditEvent event;
    event.event_id = generate_event_id();
    event.event_type = granted ? AuditEventType::AUTHZ_ACCESS_GRANTED : AuditEventType::AUTHZ_ACCESS_DENIED;
    event.severity = granted ? AuditSeverity::INFO : AuditSeverity::WARNING;
    event.user_id = user_id;
    event.resource = resource;
    event.operation = operation;
    event.result = granted ? "GRANTED" : "DENIED";
    event.metadata = reason;
    event.timestamp = std::chrono::system_clock::now();
    
    log_event(event);
}

void AuditLogger::log_data_access(const std::string& user_id, const std::string& operation,
                                 const std::string& resource, bool success, 
                                 size_t bytes_processed, std::chrono::microseconds duration) {
    AuditEventType event_type = AuditEventType::DATA_READ;
    if (operation == "PUT" || operation == "WRITE") {
        event_type = AuditEventType::DATA_WRITE;
    } else if (operation == "DELETE") {
        event_type = AuditEventType::DATA_DELETE;
    } else if (operation == "QUERY") {
        event_type = AuditEventType::DATA_QUERY;
    } else if (operation == "BATCH") {
        event_type = AuditEventType::DATA_BATCH_OPERATION;
    }
    
    AuditEvent event;
    event.event_id = generate_event_id();
    event.event_type = event_type;
    event.severity = success ? AuditSeverity::INFO : AuditSeverity::WARNING;
    event.user_id = user_id;
    event.resource = resource;
    event.operation = operation;
    event.result = success ? "SUCCESS" : "FAILURE";
    event.bytes_processed = bytes_processed;
    event.duration = duration;
    event.timestamp = std::chrono::system_clock::now();
    
    log_event(event);
}

void AuditLogger::log_admin_action(const std::string& user_id, const std::string& action,
                                  const std::string& target, bool success, const std::string& details) {
    AuditEventType event_type = AuditEventType::ADMIN_CONFIG_CHANGED;
    if (action.find("USER") != std::string::npos) {
        if (action.find("CREATE") != std::string::npos) {
            event_type = AuditEventType::ADMIN_USER_CREATED;
        } else if (action.find("DELETE") != std::string::npos) {
            event_type = AuditEventType::ADMIN_USER_DELETED;
        } else {
            event_type = AuditEventType::ADMIN_USER_MODIFIED;
        }
    } else if (action.find("BACKUP") != std::string::npos) {
        event_type = AuditEventType::ADMIN_BACKUP_CREATED;
    } else if (action.find("RESTORE") != std::string::npos) {
        event_type = AuditEventType::ADMIN_RESTORE_PERFORMED;
    }
    
    AuditEvent event;
    event.event_id = generate_event_id();
    event.event_type = event_type;
    event.severity = success ? AuditSeverity::INFO : AuditSeverity::ERROR;
    event.user_id = user_id;
    event.resource = target;
    event.operation = action;
    event.result = success ? "SUCCESS" : "FAILURE";
    event.metadata = details;
    event.timestamp = std::chrono::system_clock::now();
    
    log_event(event);
}

void AuditLogger::log_security_event(const std::string& event_description, AuditSeverity severity,
                                     const std::string& client_address, const std::string& details) {
    AuditEvent event;
    event.event_id = generate_event_id();
    event.event_type = AuditEventType::SECURITY_SUSPICIOUS_ACTIVITY;
    event.severity = severity;
    event.client_address = client_address;
    event.operation = event_description;
    event.metadata = details;
    event.timestamp = std::chrono::system_clock::now();
    
    log_event(event);
}

void AuditLogger::log_error(const std::string& error_type, const std::string& error_message,
                           const std::string& context, AuditSeverity severity) {
    AuditEventType event_type = AuditEventType::ERROR_SYSTEM;
    if (error_type.find("STORAGE") != std::string::npos) {
        event_type = AuditEventType::ERROR_STORAGE;
    } else if (error_type.find("NETWORK") != std::string::npos) {
        event_type = AuditEventType::ERROR_NETWORK;
    } else if (error_type.find("PROTOCOL") != std::string::npos) {
        event_type = AuditEventType::ERROR_PROTOCOL;
    } else if (error_type.find("CONFIG") != std::string::npos) {
        event_type = AuditEventType::ERROR_CONFIGURATION;
    }
    
    AuditEvent event;
    event.event_id = generate_event_id();
    event.event_type = event_type;
    event.severity = severity;
    event.operation = error_type;
    event.result = "ERROR";
    event.resource = context;
    event.metadata = error_message;
    event.timestamp = std::chrono::system_clock::now();
    
    log_event(event);
}

bool AuditLogger::should_log_event(const AuditEvent& event) const {
    // Check severity filter
    if (event.severity < config_.min_severity) {
        return false;
    }
    
    // Check excluded events (unless critical)
    if (event.severity != AuditSeverity::CRITICAL) {
        auto it = std::find(config_.excluded_events.begin(), config_.excluded_events.end(), event.event_type);
        if (it != config_.excluded_events.end()) {
            return false;
        }
    }
    
    // Always log critical events
    auto critical_it = std::find(config_.critical_events.begin(), config_.critical_events.end(), event.event_type);
    if (critical_it != config_.critical_events.end()) {
        return true;
    }
    
    return true;
}

void AuditLogger::worker_thread() {
    while (running_.load() || !event_buffer_.empty() || !priority_buffer_.empty()) {
        std::unique_lock<std::mutex> lock(buffer_mutex_);
        
        // Wait for events or shutdown
        buffer_cv_.wait_for(lock, config_.flush_interval, [this] {
            return !event_buffer_.empty() || !priority_buffer_.empty() || shutdown_requested_.load();
        });
        
        // Process priority events first
        std::queue<AuditEvent> priority_events;
        priority_events.swap(priority_buffer_);
        
        // Process regular events
        std::queue<AuditEvent> events;
        events.swap(event_buffer_);
        
        stats_.current_buffer_size.store(0);
        lock.unlock();
        
        // Write priority events
        while (!priority_events.empty()) {
            write_event(priority_events.front());
            priority_events.pop();
        }
        
        // Write regular events
        while (!events.empty()) {
            write_event(events.front());
            events.pop();
        }
        
        // Check if log rotation is needed
        if (config_.enable_file_logging) {
            rotate_if_needed();
        }
    }
}

void AuditLogger::flush_buffer() {
    std::unique_lock<std::mutex> lock(buffer_mutex_);
    
    // Write all remaining events
    while (!priority_buffer_.empty()) {
        write_event(priority_buffer_.front());
        priority_buffer_.pop();
    }
    
    while (!event_buffer_.empty()) {
        write_event(event_buffer_.front());
        event_buffer_.pop();
    }
    
    stats_.current_buffer_size.store(0);
}

bool AuditLogger::write_event(const AuditEvent& event) {
    std::string formatted_event = format_event(event);
    
    bool success = true;
    
    // Write to file
    if (config_.enable_file_logging && log_file_) {
        std::lock_guard<std::mutex> file_lock(file_mutex_);
        try {
            *log_file_ << formatted_event << std::endl;
            log_file_->flush();
            
            // Update file size tracking
            stats_.current_file_size.fetch_add(formatted_event.length() + 1);
        } catch (const std::exception& e) {
            spdlog::error("Failed to write audit event to file: {}", e.what());
            stats_.write_errors.fetch_add(1);
            success = false;
        }
    }
    
    // Write to console if enabled
    if (config_.enable_console_logging) {
        std::cout << formatted_event << std::endl;
    }
    
    // Write to syslog if enabled
    if (config_.enable_syslog_logging) {
        // Syslog integration would go here
        spdlog::info("AUDIT: {}", formatted_event);
    }
    
    if (success) {
        stats_.events_written.fetch_add(1);
    } else {
        stats_.events_dropped.fetch_add(1);
    }
    
    return success;
}

std::string AuditLogger::format_event(const AuditEvent& event) const {
    nlohmann::json json_event;
    
    // Core event fields
    json_event["event_id"] = event.event_id;
    json_event["timestamp"] = format_timestamp(event.timestamp);
    json_event["event_type"] = event_type_to_string(event.event_type);
    json_event["severity"] = severity_to_string(event.severity);
    
    // Context fields
    if (!event.user_id.empty()) {
        json_event["user_id"] = sanitize_data(event.user_id);
    }
    if (!event.session_id.empty()) {
        json_event["session_id"] = event.session_id;
    }
    if (!event.client_address.empty()) {
        json_event["client_address"] = config_.anonymize_ip_addresses ? 
                                      anonymize_ip(event.client_address) : event.client_address;
    }
    if (!event.user_agent.empty()) {
        json_event["user_agent"] = sanitize_data(event.user_agent);
    }
    
    // Event details
    if (!event.resource.empty()) {
        json_event["resource"] = sanitize_data(event.resource);
    }
    if (!event.operation.empty()) {
        json_event["operation"] = event.operation;
    }
    if (!event.result.empty()) {
        json_event["result"] = event.result;
    }
    if (!event.metadata.empty()) {
        json_event["metadata"] = sanitize_data(event.metadata);
    }
    
    // Performance metrics
    if (event.duration.count() > 0) {
        json_event["duration_us"] = event.duration.count();
    }
    if (event.bytes_processed > 0) {
        json_event["bytes_processed"] = event.bytes_processed;
    }
    
    return json_event.dump();
}

bool AuditLogger::open_log_file() {
    if (!config_.enable_file_logging) {
        return true;
    }
    
    current_log_filename_ = generate_filename();
    log_file_ = std::make_unique<std::ofstream>(current_log_filename_, std::ios::app);
    
    if (!log_file_->is_open()) {
        spdlog::error("Failed to open audit log file: {}", current_log_filename_);
        return false;
    }
    
    // Get current file size
    log_file_->seekp(0, std::ios::end);
    stats_.current_file_size.store(log_file_->tellp());
    
    spdlog::info("Opened audit log file: {}", current_log_filename_);
    return true;
}

void AuditLogger::close_log_file() {
    if (log_file_) {
        log_file_->close();
        log_file_.reset();
    }
}

std::string AuditLogger::generate_filename() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    oss << config_.log_directory << "/" << config_.log_file;
    
    return oss.str();
}

bool AuditLogger::rotate_if_needed() {
    if (!config_.enable_file_logging || !log_file_) {
        return true;
    }
    
    size_t current_size = stats_.current_file_size.load();
    size_t max_size_bytes = config_.max_file_size_mb * 1024 * 1024;
    
    if (current_size >= max_size_bytes) {
        rotate_log_files();
        return true;
    }
    
    return false;
}

void AuditLogger::rotate_log_files() {
    if (!config_.enable_file_logging) {
        return;
    }
    
    std::lock_guard<std::mutex> file_lock(file_mutex_);
    
    // Close current log file
    if (log_file_) {
        log_file_->close();
    }
    
    // Rotate existing files
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream rotated_name;
    rotated_name << config_.log_directory << "/" << config_.log_file 
                 << "." << std::put_time(std::gmtime(&time_t), "%Y%m%d_%H%M%S");
    
    // Move current log file to rotated name
    std::error_code ec;
    std::filesystem::rename(current_log_filename_, rotated_name.str(), ec);
    if (ec) {
        spdlog::error("Failed to rotate log file: {}", ec.message());
    } else {
        spdlog::info("Rotated audit log file to: {}", rotated_name.str());
    }
    
    // Open new log file
    open_log_file();
    
    // Clean up old log files if needed
    if (config_.enable_auto_cleanup) {
        cleanup_old_logs();
    }
}

void AuditLogger::cleanup_old_logs() {
    try {
        std::vector<std::filesystem::path> log_files;
        
        // Find all rotated log files
        for (const auto& entry : std::filesystem::directory_iterator(config_.log_directory)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                if (filename.starts_with(config_.log_file + ".")) {
                    log_files.push_back(entry.path());
                }
            }
        }
        
        // Sort by modification time (newest first)
        std::sort(log_files.begin(), log_files.end(), [](const auto& a, const auto& b) {
            return std::filesystem::last_write_time(a) > std::filesystem::last_write_time(b);
        });
        
        // Remove files beyond max_log_files limit
        if (static_cast<int>(log_files.size()) > config_.max_log_files) {
            for (size_t i = config_.max_log_files; i < log_files.size(); ++i) {
                std::filesystem::remove(log_files[i]);
                spdlog::info("Removed old audit log file: {}", log_files[i].string());
            }
        }
        
        // Remove files older than retention period
        auto cutoff_time = std::chrono::system_clock::now() - config_.retention_period;
        for (const auto& file : log_files) {
            auto file_time = std::filesystem::last_write_time(file);
            auto file_time_sys = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                file_time - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
            
            if (file_time_sys < cutoff_time) {
                std::filesystem::remove(file);
                spdlog::info("Removed expired audit log file: {}", file.string());
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("Error during log cleanup: {}", e.what());
    }
}

std::string AuditLogger::sanitize_data(const std::string& data) const {
    if (!config_.redact_sensitive_data) {
        return data;
    }
    
    std::string sanitized = data;
    
    // Redact sensitive fields
    for (const auto& sensitive_field : config_.sensitive_fields) {
        std::regex pattern(sensitive_field + R"(\s*[=:]\s*[^,\s}]+)", std::regex_constants::icase);
        sanitized = std::regex_replace(sanitized, pattern, sensitive_field + "=***REDACTED***");
    }
    
    return sanitized;
}

std::string AuditLogger::anonymize_ip(const std::string& ip_address) const {
    if (ip_address.empty()) {
        return "";
    }
    
    // Simple IPv4 anonymization (zero out last octet)
    auto last_dot = ip_address.find_last_of('.');
    if (last_dot != std::string::npos) {
        return ip_address.substr(0, last_dot) + ".xxx";
    }
    
    return "xxx.xxx.xxx.xxx";
}

uint64_t AuditLogger::generate_event_id() {
    return event_id_counter_.fetch_add(1);
}

void AuditLogger::reset_stats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.total_events.store(0);
    stats_.events_written.store(0);
    stats_.events_dropped.store(0);
    stats_.buffer_overruns.store(0);
    stats_.write_errors.store(0);
    stats_.current_buffer_size.store(0);
    stats_.current_file_size.store(0);
}

// AuditEventBuilder Implementation
AuditEventBuilder::AuditEventBuilder(AuditEventType type, AuditSeverity severity) {
    event_.event_type = type;
    event_.severity = severity;
    event_.timestamp = std::chrono::system_clock::now();
}

AuditEventBuilder& AuditEventBuilder::user(const std::string& user_id) {
    event_.user_id = user_id;
    return *this;
}

AuditEventBuilder& AuditEventBuilder::session(const std::string& session_id) {
    event_.session_id = session_id;
    return *this;
}

AuditEventBuilder& AuditEventBuilder::client(const std::string& client_address) {
    event_.client_address = client_address;
    return *this;
}

AuditEventBuilder& AuditEventBuilder::user_agent(const std::string& agent) {
    event_.user_agent = agent;
    return *this;
}

AuditEventBuilder& AuditEventBuilder::resource(const std::string& resource) {
    event_.resource = resource;
    return *this;
}

AuditEventBuilder& AuditEventBuilder::operation(const std::string& operation) {
    event_.operation = operation;
    return *this;
}

AuditEventBuilder& AuditEventBuilder::result(const std::string& result) {
    event_.result = result;
    return *this;
}

AuditEventBuilder& AuditEventBuilder::metadata(const std::string& metadata) {
    event_.metadata = metadata;
    return *this;
}

AuditEventBuilder& AuditEventBuilder::duration(std::chrono::microseconds duration) {
    event_.duration = duration;
    return *this;
}

AuditEventBuilder& AuditEventBuilder::bytes_processed(size_t bytes) {
    event_.bytes_processed = bytes;
    return *this;
}

AuditEvent AuditEventBuilder::build() const {
    return event_;
}

void AuditEventBuilder::log_to(AuditLogger& logger) const {
    logger.log_event(event_);
}

// AuditManager Implementation
std::unique_ptr<AuditLogger> AuditManager::instance_;
std::mutex AuditManager::instance_mutex_;
std::atomic<bool> AuditManager::initialized_{false};

AuditLogger& AuditManager::instance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        instance_ = std::make_unique<AuditLogger>();
        instance_->start();
        initialized_.store(true);
    }
    return *instance_;
}

bool AuditManager::initialize(const AuditConfig& config) {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_) {
        instance_->stop();
    }
    
    instance_ = std::make_unique<AuditLogger>(config);
    bool success = instance_->start();
    initialized_.store(success);
    return success;
}

void AuditManager::shutdown() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_) {
        instance_->stop();
        instance_.reset();
        initialized_.store(false);
    }
}

bool AuditManager::is_initialized() {
    return initialized_.load();
}

void AuditManager::log_auth(const std::string& user_id, const std::string& client_address, bool success) {
    if (is_initialized()) {
        instance().log_authentication(user_id, client_address, success);
    }
}

void AuditManager::log_access(const std::string& user_id, const std::string& operation, 
                             const std::string& resource, bool success) {
    if (is_initialized()) {
        instance().log_data_access(user_id, operation, resource, success);
    }
}

void AuditManager::log_admin(const std::string& user_id, const std::string& action, 
                            const std::string& target, bool success) {
    if (is_initialized()) {
        instance().log_admin_action(user_id, action, target, success);
    }
}

void AuditManager::log_security(const std::string& event, AuditSeverity severity) {
    if (is_initialized()) {
        instance().log_security_event(event, severity);
    }
}

void AuditManager::log_error(const std::string& error, const std::string& context) {
    if (is_initialized()) {
        instance().log_error("SYSTEM", error, context);
    }
}

} // namespace nosql_db::security