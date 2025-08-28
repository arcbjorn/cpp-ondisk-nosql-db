#pragma once

#include <string>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <atomic>
#include <shared_mutex>
#include <optional>
#include <functional>

namespace ishikura::security {

/**
 * API key permissions for fine-grained access control
 */
enum class ApiPermission : uint16_t {
    // No permissions
    NONE = 0x0000,
    
    // Data operations
    READ = 0x0001,
    WRITE = 0x0002,
    DELETE = 0x0004,
    QUERY = 0x0008,
    
    // Administrative operations
    ADMIN_USER_MANAGEMENT = 0x0010,
    ADMIN_CONFIG = 0x0020,
    ADMIN_BACKUP = 0x0040,
    ADMIN_MONITORING = 0x0080,
    
    // System operations
    SYSTEM_INFO = 0x0100,
    SYSTEM_STATS = 0x0200,
    SYSTEM_HEALTH = 0x0400,
    
    // Batch operations
    BATCH_OPERATIONS = 0x0800,
    
    // Advanced operations
    STREAMING = 0x1000,
    TRANSACTIONS = 0x2000,
    
    // Meta permissions
    ALL_DATA = READ | WRITE | DELETE | QUERY,
    ALL_ADMIN = ADMIN_USER_MANAGEMENT | ADMIN_CONFIG | ADMIN_BACKUP | ADMIN_MONITORING,
    ALL_SYSTEM = SYSTEM_INFO | SYSTEM_STATS | SYSTEM_HEALTH,
    ALL_PERMISSIONS = 0xFFFF
};

// Bitwise operators for permissions
inline ApiPermission operator|(ApiPermission a, ApiPermission b) {
    return static_cast<ApiPermission>(static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
}

inline ApiPermission operator&(ApiPermission a, ApiPermission b) {
    return static_cast<ApiPermission>(static_cast<uint16_t>(a) & static_cast<uint16_t>(b));
}

inline ApiPermission operator~(ApiPermission a) {
    return static_cast<ApiPermission>(~static_cast<uint16_t>(a));
}

/**
 * API key status for lifecycle management
 */
enum class ApiKeyStatus : uint8_t {
    ACTIVE = 0,
    SUSPENDED = 1,
    EXPIRED = 2,
    REVOKED = 3,
    PENDING_ACTIVATION = 4
};

/**
 * Rate limiting configuration for API keys
 */
struct RateLimit {
    uint32_t requests_per_minute = 1000;
    uint32_t requests_per_hour = 60000;
    uint32_t requests_per_day = 1000000;
    uint32_t burst_limit = 100;           // Max requests in burst window
    std::chrono::seconds burst_window{60}; // Burst window duration
    
    // Data transfer limits
    uint64_t bytes_per_minute = 100 * 1024 * 1024;  // 100MB/min
    uint64_t bytes_per_hour = 1024 * 1024 * 1024;   // 1GB/hour
    uint64_t bytes_per_day = 10LL * 1024 * 1024 * 1024; // 10GB/day
    
    bool is_default() const {
        return requests_per_minute == 1000 && requests_per_hour == 60000;
    }
};

/**
 * API key metadata and configuration
 */
struct ApiKey {
    // Identity
    std::string key_id;                               // Unique identifier
    std::string key_hash;                             // Hashed API key for storage
    std::string name;                                 // Human-readable name
    std::string description;                          // Key description/purpose
    
    // Ownership and management
    std::string owner_id;                             // User/service that owns this key
    std::string created_by;                           // Who created this key
    std::chrono::system_clock::time_point created_at; // Creation timestamp
    std::chrono::system_clock::time_point last_used;  // Last usage timestamp
    
    // Status and lifecycle
    ApiKeyStatus status = ApiKeyStatus::ACTIVE;
    std::optional<std::chrono::system_clock::time_point> expires_at; // Optional expiration
    
    // Permissions and access control
    ApiPermission permissions = static_cast<ApiPermission>(0);
    std::vector<std::string> allowed_ips;            // IP whitelist (empty = all allowed)
    std::vector<std::string> allowed_hosts;          // Host whitelist
    std::unordered_set<std::string> resource_patterns; // Resource access patterns
    
    // Rate limiting
    RateLimit rate_limit;
    
    // Usage tracking (mutable for thread safety)
    mutable std::atomic<uint64_t> usage_count{0};            // Total requests made
    mutable std::atomic<uint64_t> bytes_transferred{0};      // Total bytes transferred
    std::chrono::system_clock::time_point last_rate_limit_reset;
    mutable std::atomic<uint32_t> requests_this_minute{0};
    mutable std::atomic<uint32_t> requests_this_hour{0};
    mutable std::atomic<uint32_t> requests_today{0};
    mutable std::atomic<uint64_t> bytes_this_minute{0};
    mutable std::atomic<uint64_t> bytes_this_hour{0};
    mutable std::atomic<uint64_t> bytes_today{0};
    
    // Metadata
    std::unordered_map<std::string, std::string> metadata; // Custom key-value pairs
    
    ApiKey() = default;
    explicit ApiKey(const std::string& id) : key_id(id), created_at(std::chrono::system_clock::now()) {}
    
    // Custom copy constructor to handle atomic members
    ApiKey(const ApiKey& other) 
        : key_id(other.key_id), key_hash(other.key_hash), name(other.name),
          description(other.description), owner_id(other.owner_id), 
          created_by(other.created_by), created_at(other.created_at),
          last_used(other.last_used), status(other.status), 
          expires_at(other.expires_at), permissions(other.permissions),
          allowed_ips(other.allowed_ips), allowed_hosts(other.allowed_hosts),
          resource_patterns(other.resource_patterns), rate_limit(other.rate_limit),
          usage_count(other.usage_count.load()),
          bytes_transferred(other.bytes_transferred.load()),
          last_rate_limit_reset(other.last_rate_limit_reset),
          requests_this_minute(other.requests_this_minute.load()),
          requests_this_hour(other.requests_this_hour.load()),
          requests_today(other.requests_today.load()),
          bytes_this_minute(other.bytes_this_minute.load()),
          bytes_this_hour(other.bytes_this_hour.load()),
          bytes_today(other.bytes_today.load()),
          metadata(other.metadata) {}
    
    // Custom assignment operator to handle atomic members
    ApiKey& operator=(const ApiKey& other) {
        if (this != &other) {
            key_id = other.key_id;
            key_hash = other.key_hash;
            name = other.name;
            description = other.description;
            owner_id = other.owner_id;
            created_by = other.created_by;
            created_at = other.created_at;
            last_used = other.last_used;
            status = other.status;
            expires_at = other.expires_at;
            permissions = other.permissions;
            allowed_ips = other.allowed_ips;
            allowed_hosts = other.allowed_hosts;
            resource_patterns = other.resource_patterns;
            rate_limit = other.rate_limit;
            usage_count.store(other.usage_count.load());
            bytes_transferred.store(other.bytes_transferred.load());
            last_rate_limit_reset = other.last_rate_limit_reset;
            requests_this_minute.store(other.requests_this_minute.load());
            requests_this_hour.store(other.requests_this_hour.load());
            requests_today.store(other.requests_today.load());
            bytes_this_minute.store(other.bytes_this_minute.load());
            bytes_this_hour.store(other.bytes_this_hour.load());
            bytes_today.store(other.bytes_today.load());
            metadata = other.metadata;
        }
        return *this;
    }
    
    // Helper methods
    bool is_active() const { return status == ApiKeyStatus::ACTIVE; }
    bool is_expired() const { 
        return expires_at.has_value() && 
               std::chrono::system_clock::now() > *expires_at;
    }
    bool has_permission(ApiPermission perm) const {
        return (permissions & perm) == perm;
    }
    void add_permission(ApiPermission perm) {
        permissions = permissions | perm;
    }
    void remove_permission(ApiPermission perm) {
        permissions = permissions & ~perm;
    }
};

/**
 * API key validation result
 */
struct ValidationResult {
    bool is_valid = false;
    std::string key_id;
    std::string error_message;
    ApiPermission granted_permissions = static_cast<ApiPermission>(0);
    
    // Rate limiting info
    bool rate_limited = false;
    std::chrono::seconds retry_after{0};
    
    // Context information
    std::string client_ip;
    std::string user_agent;
    
    ValidationResult() = default;
    explicit ValidationResult(bool valid) : is_valid(valid) {}
    
    static ValidationResult success(const std::string& id, ApiPermission perms) {
        ValidationResult result(true);
        result.key_id = id;
        result.granted_permissions = perms;
        return result;
    }
    
    static ValidationResult failure(const std::string& error) {
        ValidationResult result(false);
        result.error_message = error;
        return result;
    }
    
    static ValidationResult rate_limit_exceeded(std::chrono::seconds retry_after) {
        ValidationResult result(false);
        result.rate_limited = true;
        result.retry_after = retry_after;
        result.error_message = "Rate limit exceeded";
        return result;
    }
};

/**
 * API key generation configuration
 */
struct KeyGenerationConfig {
    size_t key_length = 32;                          // Length of generated key
    bool include_prefix = true;                      // Include key type prefix
    std::string prefix = "ndb_";                     // Key prefix
    bool include_checksum = true;                    // Include validation checksum
    
    // Default permissions for new keys
    ApiPermission default_permissions = ApiPermission::READ | ApiPermission::WRITE;
    RateLimit default_rate_limit;
    
    // Expiration settings
    std::optional<std::chrono::hours> default_expiry; // Default key expiry
};

/**
 * Main API key management system
 */
class ApiKeyManager {
public:
    explicit ApiKeyManager(const std::string& storage_path = "api_keys.db");
    ~ApiKeyManager();
    
    // Lifecycle management
    bool initialize();
    void shutdown();
    bool is_initialized() const { return initialized_; }
    
    // Key generation and management
    std::pair<std::string, ApiKey> generate_key(const std::string& name, 
                                               const std::string& owner_id,
                                               const KeyGenerationConfig& config = {});
    
    bool create_key(const ApiKey& key, const std::string& raw_key);
    bool update_key(const std::string& key_id, const ApiKey& updated_key);
    bool delete_key(const std::string& key_id);
    bool revoke_key(const std::string& key_id);
    bool suspend_key(const std::string& key_id);
    bool activate_key(const std::string& key_id);
    
    // Key retrieval and validation
    ValidationResult validate_key(const std::string& raw_key, 
                                 ApiPermission required_permission,
                                 const std::string& client_ip = "",
                                 const std::string& resource = "");
    
    std::optional<ApiKey> get_key_by_id(const std::string& key_id);
    std::vector<ApiKey> get_keys_by_owner(const std::string& owner_id);
    std::vector<ApiKey> list_all_keys(bool include_revoked = false);
    
    // Permission management
    bool grant_permission(const std::string& key_id, ApiPermission permission);
    bool revoke_permission(const std::string& key_id, ApiPermission permission);
    bool set_permissions(const std::string& key_id, ApiPermission permissions);
    
    // Rate limiting
    bool update_rate_limits(const std::string& key_id, const RateLimit& limits);
    bool is_rate_limited(const std::string& key_id, uint32_t request_cost = 1, 
                        uint64_t bytes_cost = 0);
    void record_usage(const std::string& key_id, uint32_t request_cost = 1,
                     uint64_t bytes_cost = 0);
    
    // IP and host restrictions
    bool add_allowed_ip(const std::string& key_id, const std::string& ip_pattern);
    bool remove_allowed_ip(const std::string& key_id, const std::string& ip_pattern);
    bool add_allowed_host(const std::string& key_id, const std::string& host_pattern);
    bool remove_allowed_host(const std::string& key_id, const std::string& host_pattern);
    
    // Resource patterns
    bool add_resource_pattern(const std::string& key_id, const std::string& pattern);
    bool remove_resource_pattern(const std::string& key_id, const std::string& pattern);
    bool check_resource_access(const std::string& key_id, const std::string& resource);
    
    // Statistics and monitoring
    struct KeyStats {
        uint64_t total_keys = 0;
        uint64_t active_keys = 0;
        uint64_t suspended_keys = 0;
        uint64_t expired_keys = 0;
        uint64_t revoked_keys = 0;
        uint64_t total_requests = 0;
        uint64_t total_bytes_transferred = 0;
        uint64_t rate_limited_requests = 0;
        std::chrono::system_clock::time_point last_updated;
    };
    
    KeyStats get_statistics() const;
    std::unordered_map<std::string, uint64_t> get_usage_by_owner() const;
    std::vector<std::pair<std::string, uint64_t>> get_top_keys_by_usage(size_t limit = 10) const;
    
    // Maintenance operations
    void cleanup_expired_keys();
    void reset_rate_limits();
    size_t purge_revoked_keys(std::chrono::hours older_than = std::chrono::hours{24 * 30});
    
    // Backup and restore
    bool export_keys(const std::string& export_path, bool include_revoked = false);
    bool import_keys(const std::string& import_path, bool overwrite_existing = false);
    
    // Configuration
    void set_key_generation_config(const KeyGenerationConfig& config);
    const KeyGenerationConfig& get_key_generation_config() const { return generation_config_; }
    
    // Event callbacks
    using KeyEventCallback = std::function<void(const std::string& key_id, const std::string& event_type)>;
    void set_event_callback(KeyEventCallback callback) { event_callback_ = callback; }

private:
    // Storage and persistence
    bool load_keys_from_storage();
    bool save_keys_to_storage();
    bool save_key_to_storage(const ApiKey& key);
    bool remove_key_from_storage(const std::string& key_id);
    
    // Key validation helpers
    bool validate_key_format(const std::string& raw_key);
    std::string hash_key(const std::string& raw_key);
    bool verify_key_hash(const std::string& raw_key, const std::string& stored_hash);
    
    // Access control helpers
    bool check_ip_access(const ApiKey& key, const std::string& client_ip);
    bool check_host_access(const ApiKey& key, const std::string& host);
    bool match_pattern(const std::string& value, const std::string& pattern);
    
    // Rate limiting helpers
    void update_rate_limit_counters(ApiKey& key);
    bool check_rate_limit(const ApiKey& key, uint32_t request_cost, uint64_t bytes_cost);
    std::chrono::seconds calculate_retry_after(const ApiKey& key);
    
    // Utility functions
    std::string generate_random_key(size_t length);
    std::string calculate_checksum(const std::string& key);
    bool validate_checksum(const std::string& key_with_checksum);
    void fire_event(const std::string& key_id, const std::string& event_type);
    
    // Storage path and state
    std::string storage_path_;
    std::atomic<bool> initialized_{false};
    mutable std::mutex storage_mutex_;
    
    // Key storage
    std::unordered_map<std::string, ApiKey> keys_by_id_;
    std::unordered_map<std::string, std::string> hash_to_id_map_;
    mutable std::shared_mutex keys_mutex_;
    
    // Configuration
    KeyGenerationConfig generation_config_;
    
    // Statistics
    mutable KeyStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Event handling
    KeyEventCallback event_callback_;
    std::mutex callback_mutex_;
};

/**
 * Global API key manager instance
 */
class ApiKeyManagerInstance {
public:
    static ApiKeyManager& instance();
    static bool initialize(const std::string& storage_path = "api_keys.db");
    static void shutdown();
    static bool is_initialized();

private:
    static std::unique_ptr<ApiKeyManager> instance_;
    static std::mutex instance_mutex_;
    static std::atomic<bool> initialized_;
    
    ApiKeyManagerInstance() = delete;
    ~ApiKeyManagerInstance() = delete;
};

// Utility functions for permission string conversion
std::string permission_to_string(ApiPermission permission);
ApiPermission string_to_permission(const std::string& permission_str);
std::vector<std::string> permission_to_string_list(ApiPermission permissions);
ApiPermission string_list_to_permission(const std::vector<std::string>& permission_list);

// Utility functions for status conversion
std::string status_to_string(ApiKeyStatus status);
ApiKeyStatus string_to_status(const std::string& status_str);

} // namespace ishikura::security