#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <memory>
#include <optional>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <functional>

namespace ishikura::security {

/**
 * User authentication and session management
 */

// Forward declarations
class User;
class AuthToken;
class AuthManager;

// User roles and permissions
enum class Role {
    ADMIN,      // Full system access
    DEVELOPER,  // Read/write data operations
    READONLY,   // Read-only access
    CUSTOM      // Custom role with specific permissions
};

enum class Permission {
    // Data operations
    READ,
    WRITE, 
    DELETE,
    QUERY,
    
    // Administrative operations
    USER_MANAGEMENT,
    ROLE_MANAGEMENT,
    SYSTEM_CONFIG,
    METRICS_ACCESS,
    
    // Advanced operations
    BACKUP_RESTORE,
    STREAMING,
    BATCH_OPERATIONS,
    
    // Security operations
    AUDIT_ACCESS,
    KEY_MANAGEMENT
};

/**
 * Represents a user in the system
 */
class User {
public:
    User(const std::string& username, const std::string& email, Role role);
    User(const std::string& username, const std::string& email, 
         const std::vector<Permission>& custom_permissions);
    
    // Basic user information
    const std::string& username() const { return username_; }
    const std::string& email() const { return email_; }
    Role role() const { return role_; }
    const std::string& user_id() const { return user_id_; }
    
    // Password management
    bool verify_password(const std::string& password) const;
    void set_password(const std::string& password);
    bool requires_password_change() const { return force_password_change_; }
    void force_password_change() { force_password_change_ = true; }
    
    // Permission checking
    bool has_permission(Permission perm) const;
    const std::vector<Permission>& permissions() const { return permissions_; }
    
    // Account status
    bool is_active() const { return active_; }
    bool is_locked() const { return locked_; }
    void set_active(bool active) { active_ = active; }
    void lock_account() { locked_ = true; failed_attempts_ = 0; }
    void unlock_account() { locked_ = false; failed_attempts_ = 0; }
    
    // Failed login tracking
    void record_failed_login();
    void reset_failed_attempts() { failed_attempts_ = 0; }
    uint32_t failed_attempts() const { return failed_attempts_; }
    
    // Metadata
    std::chrono::system_clock::time_point created_at() const { return created_at_; }
    std::chrono::system_clock::time_point last_login() const { return last_login_; }
    void update_last_login() { last_login_ = std::chrono::system_clock::now(); }
    
    // Serialization
    std::string to_json() const;
    static std::optional<User> from_json(const std::string& json);
    
private:
    std::string user_id_;
    std::string username_;
    std::string email_;
    std::string password_hash_;
    Role role_;
    std::vector<Permission> permissions_;
    
    bool active_{true};
    bool locked_{false};
    bool force_password_change_{false};
    uint32_t failed_attempts_{0};
    
    std::chrono::system_clock::time_point created_at_;
    std::chrono::system_clock::time_point last_login_;
    
    void initialize_permissions_for_role();
    std::string generate_user_id() const;
    std::string hash_password(const std::string& password) const;
};

/**
 * Authentication token (JWT-like)
 */
class AuthToken {
public:
    AuthToken() = default;
    AuthToken(const std::string& user_id, const std::vector<Permission>& permissions,
              std::chrono::minutes validity_duration = std::chrono::minutes(60));
    
    // Token validation
    bool is_valid() const;
    bool is_expired() const;
    bool has_permission(Permission perm) const;
    
    // Token information
    const std::string& token_id() const { return token_id_; }
    const std::string& user_id() const { return user_id_; }
    std::chrono::system_clock::time_point expires_at() const { return expires_at_; }
    std::chrono::system_clock::time_point issued_at() const { return issued_at_; }
    
    // Token operations
    void extend_validity(std::chrono::minutes additional_time);
    void revoke() { revoked_ = true; }
    bool is_revoked() const { return revoked_; }
    
    // Serialization
    std::string serialize() const;
    static std::optional<AuthToken> deserialize(const std::string& token_data);
    
private:
    std::string token_id_;
    std::string user_id_;
    std::vector<Permission> permissions_;
    std::chrono::system_clock::time_point issued_at_;
    std::chrono::system_clock::time_point expires_at_;
    bool revoked_{false};
    
    std::string generate_token_id() const;
};

/**
 * Main authentication manager
 */
class AuthManager {
public:
    struct AuthConfig {
        std::chrono::minutes token_validity_duration{60};
        uint32_t max_failed_attempts{5};
        std::chrono::minutes lockout_duration{15};
        bool require_strong_passwords{true};
        bool enable_2fa{false};
        std::string jwt_secret_key = "default_secret_change_me";
    };
    
    AuthManager();
    explicit AuthManager(const AuthConfig& config);
    ~AuthManager() = default;
    
    // User management
    bool create_user(const std::string& username, const std::string& email, 
                    const std::string& password, Role role);
    bool create_user(const std::string& username, const std::string& email,
                    const std::string& password, const std::vector<Permission>& permissions);
    
    std::optional<std::shared_ptr<User>> get_user(const std::string& username);
    std::optional<std::shared_ptr<User>> get_user_by_id(const std::string& user_id);
    bool delete_user(const std::string& username);
    std::vector<std::string> list_users() const;
    
    // Authentication
    std::optional<AuthToken> authenticate(const std::string& username, const std::string& password);
    bool verify_token(const std::string& token_data);
    std::optional<AuthToken> get_token_info(const std::string& token_data);
    bool revoke_token(const std::string& token_id);
    void revoke_all_user_tokens(const std::string& user_id);
    
    // Authorization
    bool authorize(const std::string& token_data, Permission required_permission);
    bool authorize(const AuthToken& token, Permission required_permission);
    
    // Account management
    bool change_password(const std::string& username, const std::string& old_password,
                        const std::string& new_password);
    bool reset_password(const std::string& username, const std::string& new_password);
    bool activate_user(const std::string& username);
    bool deactivate_user(const std::string& username);
    
    // Statistics and monitoring
    struct AuthStats {
        std::atomic<uint64_t> total_login_attempts{0};
        std::atomic<uint64_t> successful_logins{0};
        std::atomic<uint64_t> failed_logins{0};
        std::atomic<uint64_t> locked_accounts{0};
        std::atomic<uint64_t> active_tokens{0};
        std::atomic<uint64_t> revoked_tokens{0};
    };
    
    const AuthStats& stats() const { return stats_; }
    void reset_stats();
    
    // Configuration
    const AuthConfig& config() const { return config_; }
    void update_config(const AuthConfig& config);
    
    // Persistence
    bool save_users_to_file(const std::string& filepath) const;
    bool load_users_from_file(const std::string& filepath);
    
private:
    AuthConfig config_;
    std::unordered_map<std::string, std::shared_ptr<User>> users_; // username -> user
    std::unordered_map<std::string, std::shared_ptr<User>> user_ids_; // user_id -> user
    std::unordered_map<std::string, AuthToken> active_tokens_; // token_id -> token
    
    mutable std::shared_mutex users_mutex_;
    mutable std::mutex tokens_mutex_;
    
    AuthStats stats_;
    
    // Helper methods
    bool is_strong_password(const std::string& password) const;
    void cleanup_expired_tokens();
    std::string generate_jwt(const AuthToken& token) const;
    std::optional<AuthToken> parse_jwt(const std::string& jwt_token) const;
};

/**
 * Authorization middleware for request processing
 */
class AuthMiddleware {
public:
    using AuthHandler = std::function<bool(const std::string&, Permission)>;
    
    explicit AuthMiddleware(std::shared_ptr<AuthManager> auth_manager);
    
    // Middleware interface
    bool process_request(const std::string& token_header, Permission required_permission);
    
    // Custom authorization handlers
    void set_custom_handler(AuthHandler handler) { custom_handler_ = handler; }
    
    // Request context
    struct RequestContext {
        std::string user_id;
        std::string username;
        std::vector<Permission> permissions;
        bool authenticated{false};
    };
    
    std::optional<RequestContext> get_request_context(const std::string& token_header);
    
private:
    std::shared_ptr<AuthManager> auth_manager_;
    AuthHandler custom_handler_;
    
    std::string extract_token_from_header(const std::string& auth_header);
};

// Utility functions for permission management
std::vector<Permission> get_default_permissions(Role role);
std::string permission_to_string(Permission perm);
std::optional<Permission> string_to_permission(const std::string& perm_str);
std::string role_to_string(Role role);
std::optional<Role> string_to_role(const std::string& role_str);

} // namespace ishikura::security