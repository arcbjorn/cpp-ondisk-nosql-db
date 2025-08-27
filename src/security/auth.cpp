#include "security/auth.hpp"
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <shared_mutex>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <regex>

namespace ishikura::security {

// Utility functions
std::string generate_random_string(size_t length) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);
    
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += chars[dis(gen)];
    }
    return result;
}

std::string hash_with_salt(const std::string& input, const std::string& salt) {
    std::string salted = input + salt;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(salted.c_str()), salted.length(), hash);
    
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

// User implementation
User::User(const std::string& username, const std::string& email, Role role)
    : user_id_(generate_user_id()), username_(username), email_(email), role_(role),
      created_at_(std::chrono::system_clock::now()),
      last_login_(std::chrono::system_clock::now()) {
    initialize_permissions_for_role();
}

User::User(const std::string& username, const std::string& email, 
           const std::vector<Permission>& custom_permissions)
    : user_id_(generate_user_id()), username_(username), email_(email), 
      role_(Role::CUSTOM), permissions_(custom_permissions),
      created_at_(std::chrono::system_clock::now()),
      last_login_(std::chrono::system_clock::now()) {
}

bool User::verify_password(const std::string& password) const {
    if (password_hash_.empty()) return false;
    
    // Extract salt from stored hash (format: hash:salt)
    size_t colon_pos = password_hash_.find(':');
    if (colon_pos == std::string::npos) return false;
    
    std::string stored_hash = password_hash_.substr(0, colon_pos);
    std::string salt = password_hash_.substr(colon_pos + 1);
    
    std::string computed_hash = hash_with_salt(password, salt);
    return computed_hash == stored_hash;
}

void User::set_password(const std::string& password) {
    std::string salt = generate_random_string(16);
    std::string hash = hash_with_salt(password, salt);
    password_hash_ = hash + ":" + salt;
    force_password_change_ = false;
}

bool User::has_permission(Permission perm) const {
    return std::find(permissions_.begin(), permissions_.end(), perm) != permissions_.end();
}

void User::record_failed_login() {
    failed_attempts_++;
    spdlog::warn("Failed login attempt for user {} (attempt {})", username_, failed_attempts_);
}

std::string User::to_json() const {
    nlohmann::json j;
    j["user_id"] = user_id_;
    j["username"] = username_;
    j["email"] = email_;
    j["role"] = role_to_string(role_);
    j["active"] = active_;
    j["locked"] = locked_;
    j["force_password_change"] = force_password_change_;
    j["failed_attempts"] = failed_attempts_;
    j["created_at"] = std::chrono::duration_cast<std::chrono::seconds>(
        created_at_.time_since_epoch()).count();
    j["last_login"] = std::chrono::duration_cast<std::chrono::seconds>(
        last_login_.time_since_epoch()).count();
    
    // Convert permissions to strings
    std::vector<std::string> perm_strings;
    for (auto perm : permissions_) {
        perm_strings.push_back(permission_to_string(perm));
    }
    j["permissions"] = perm_strings;
    
    return j.dump();
}

std::optional<User> User::from_json(const std::string& json) {
    try {
        nlohmann::json j = nlohmann::json::parse(json);
        
        std::string username = j["username"];
        std::string email = j["email"];
        auto role = string_to_role(j["role"]);
        
        if (!role) return std::nullopt;
        
        User user(username, email, *role);
        user.user_id_ = j["user_id"];
        user.active_ = j.value("active", true);
        user.locked_ = j.value("locked", false);
        user.force_password_change_ = j.value("force_password_change", false);
        user.failed_attempts_ = j.value("failed_attempts", 0);
        
        // Parse timestamps
        if (j.contains("created_at")) {
            user.created_at_ = std::chrono::system_clock::from_time_t(j["created_at"]);
        }
        if (j.contains("last_login")) {
            user.last_login_ = std::chrono::system_clock::from_time_t(j["last_login"]);
        }
        
        // Parse custom permissions
        if (j.contains("permissions")) {
            std::vector<Permission> permissions;
            for (const auto& perm_str : j["permissions"]) {
                auto perm = string_to_permission(perm_str);
                if (perm) permissions.push_back(*perm);
            }
            user.permissions_ = permissions;
        }
        
        return user;
    } catch (const std::exception& e) {
        spdlog::error("Failed to parse user from JSON: {}", e.what());
        return std::nullopt;
    }
}

void User::initialize_permissions_for_role() {
    permissions_ = get_default_permissions(role_);
}

std::string User::generate_user_id() const {
    return "user_" + generate_random_string(8);
}

std::string User::hash_password(const std::string& password) const {
    std::string salt = generate_random_string(16);
    return hash_with_salt(password, salt) + ":" + salt;
}

// AuthToken implementation
AuthToken::AuthToken(const std::string& user_id, const std::vector<Permission>& permissions,
                     std::chrono::minutes validity_duration)
    : token_id_(generate_token_id()), user_id_(user_id), permissions_(permissions),
      issued_at_(std::chrono::system_clock::now()),
      expires_at_(issued_at_ + validity_duration) {
}

bool AuthToken::is_valid() const {
    return !is_expired() && !is_revoked();
}

bool AuthToken::is_expired() const {
    return std::chrono::system_clock::now() > expires_at_;
}

bool AuthToken::has_permission(Permission perm) const {
    return std::find(permissions_.begin(), permissions_.end(), perm) != permissions_.end();
}

void AuthToken::extend_validity(std::chrono::minutes additional_time) {
    expires_at_ += additional_time;
}

std::string AuthToken::serialize() const {
    nlohmann::json j;
    j["token_id"] = token_id_;
    j["user_id"] = user_id_;
    j["issued_at"] = std::chrono::duration_cast<std::chrono::seconds>(
        issued_at_.time_since_epoch()).count();
    j["expires_at"] = std::chrono::duration_cast<std::chrono::seconds>(
        expires_at_.time_since_epoch()).count();
    j["revoked"] = revoked_;
    
    std::vector<std::string> perm_strings;
    for (auto perm : permissions_) {
        perm_strings.push_back(permission_to_string(perm));
    }
    j["permissions"] = perm_strings;
    
    return j.dump();
}

std::optional<AuthToken> AuthToken::deserialize(const std::string& token_data) {
    try {
        nlohmann::json j = nlohmann::json::parse(token_data);
        
        std::string user_id = j["user_id"];
        
        // Parse permissions
        std::vector<Permission> permissions;
        if (j.contains("permissions")) {
            for (const auto& perm_str : j["permissions"]) {
                auto perm = string_to_permission(perm_str);
                if (perm) permissions.push_back(*perm);
            }
        }
        
        AuthToken token(user_id, permissions);
        token.token_id_ = j["token_id"];
        token.issued_at_ = std::chrono::system_clock::from_time_t(j["issued_at"]);
        token.expires_at_ = std::chrono::system_clock::from_time_t(j["expires_at"]);
        token.revoked_ = j.value("revoked", false);
        
        return token;
    } catch (const std::exception& e) {
        spdlog::error("Failed to deserialize auth token: {}", e.what());
        return std::nullopt;
    }
}

std::string AuthToken::generate_token_id() const {
    return "token_" + generate_random_string(16);
}

// AuthManager implementation
AuthManager::AuthManager()
    : AuthManager(AuthConfig{}) {
}

AuthManager::AuthManager(const AuthConfig& config) : config_(config) {
    spdlog::info("AuthManager initialized with token validity: {} minutes", 
                config_.token_validity_duration.count());
}

bool AuthManager::create_user(const std::string& username, const std::string& email,
                             const std::string& password, Role role) {
    std::unique_lock<std::shared_mutex> lock(users_mutex_);
    
    if (users_.find(username) != users_.end()) {
        spdlog::warn("Attempt to create user '{}' that already exists", username);
        return false;
    }
    
    if (config_.require_strong_passwords && !is_strong_password(password)) {
        spdlog::warn("Password for user '{}' does not meet strength requirements", username);
        return false;
    }
    
    auto user = std::make_shared<User>(username, email, role);
    user->set_password(password);
    
    users_[username] = user;
    user_ids_[user->user_id()] = user;
    
    spdlog::info("Created user '{}' with role '{}'", username, role_to_string(role));
    return true;
}

bool AuthManager::create_user(const std::string& username, const std::string& email,
                             const std::string& password, const std::vector<Permission>& permissions) {
    std::unique_lock<std::shared_mutex> lock(users_mutex_);
    
    if (users_.find(username) != users_.end()) {
        spdlog::warn("Attempt to create user '{}' that already exists", username);
        return false;
    }
    
    if (config_.require_strong_passwords && !is_strong_password(password)) {
        spdlog::warn("Password for user '{}' does not meet strength requirements", username);
        return false;
    }
    
    auto user = std::make_shared<User>(username, email, permissions);
    user->set_password(password);
    
    users_[username] = user;
    user_ids_[user->user_id()] = user;
    
    spdlog::info("Created user '{}' with custom permissions", username);
    return true;
}

std::optional<std::shared_ptr<User>> AuthManager::get_user(const std::string& username) {
    std::shared_lock<std::shared_mutex> lock(users_mutex_);
    auto it = users_.find(username);
    return (it != users_.end()) ? std::make_optional(it->second) : std::nullopt;
}

std::optional<std::shared_ptr<User>> AuthManager::get_user_by_id(const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(users_mutex_);
    auto it = user_ids_.find(user_id);
    return (it != user_ids_.end()) ? std::make_optional(it->second) : std::nullopt;
}

std::optional<AuthToken> AuthManager::authenticate(const std::string& username, const std::string& password) {
    stats_.total_login_attempts.fetch_add(1);
    
    auto user_opt = get_user(username);
    if (!user_opt) {
        stats_.failed_logins.fetch_add(1);
        spdlog::warn("Authentication failed: user '{}' not found", username);
        return std::nullopt;
    }
    
    auto user = *user_opt;
    
    if (!user->is_active()) {
        stats_.failed_logins.fetch_add(1);
        spdlog::warn("Authentication failed: user '{}' is inactive", username);
        return std::nullopt;
    }
    
    if (user->is_locked()) {
        stats_.failed_logins.fetch_add(1);
        spdlog::warn("Authentication failed: user '{}' is locked", username);
        return std::nullopt;
    }
    
    if (!user->verify_password(password)) {
        user->record_failed_login();
        stats_.failed_logins.fetch_add(1);
        
        // Lock account if too many failed attempts
        if (user->failed_attempts() >= config_.max_failed_attempts) {
            user->lock_account();
            stats_.locked_accounts.fetch_add(1);
            spdlog::warn("User '{}' locked due to {} failed attempts", username, user->failed_attempts());
        }
        
        return std::nullopt;
    }
    
    // Successful authentication
    user->reset_failed_attempts();
    user->update_last_login();
    stats_.successful_logins.fetch_add(1);
    
    // Create token
    AuthToken token(user->user_id(), user->permissions(), config_.token_validity_duration);
    
    {
        std::lock_guard<std::mutex> token_lock(tokens_mutex_);
        active_tokens_[token.token_id()] = token;
        stats_.active_tokens.fetch_add(1);
    }
    
    cleanup_expired_tokens();
    
    spdlog::info("User '{}' authenticated successfully", username);
    return token;
}

bool AuthManager::verify_token(const std::string& token_data) {
    auto token_opt = get_token_info(token_data);
    return token_opt && token_opt->is_valid();
}

std::optional<AuthToken> AuthManager::get_token_info(const std::string& token_data) {
    auto token_opt = AuthToken::deserialize(token_data);
    if (!token_opt) return std::nullopt;
    
    std::lock_guard<std::mutex> lock(tokens_mutex_);
    auto it = active_tokens_.find(token_opt->token_id());
    return (it != active_tokens_.end()) ? std::make_optional(it->second) : std::nullopt;
}

bool AuthManager::authorize(const std::string& token_data, Permission required_permission) {
    auto token_opt = get_token_info(token_data);
    return token_opt && authorize(*token_opt, required_permission);
}

bool AuthManager::authorize(const AuthToken& token, Permission required_permission) {
    return token.is_valid() && token.has_permission(required_permission);
}

bool AuthManager::is_strong_password(const std::string& password) const {
    if (password.length() < 8) return false;
    
    bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
    
    for (char c : password) {
        if (std::isupper(c)) has_upper = true;
        else if (std::islower(c)) has_lower = true;
        else if (std::isdigit(c)) has_digit = true;
        else has_special = true;
    }
    
    return has_upper && has_lower && has_digit && has_special;
}

void AuthManager::cleanup_expired_tokens() {
    std::lock_guard<std::mutex> lock(tokens_mutex_);
    
    auto it = active_tokens_.begin();
    while (it != active_tokens_.end()) {
        if (it->second.is_expired()) {
            stats_.active_tokens.fetch_sub(1);
            it = active_tokens_.erase(it);
        } else {
            ++it;
        }
    }
}

// Utility functions
std::vector<Permission> get_default_permissions(Role role) {
    switch (role) {
        case Role::ADMIN:
            return {
                Permission::READ, Permission::WRITE, Permission::DELETE, Permission::QUERY,
                Permission::USER_MANAGEMENT, Permission::ROLE_MANAGEMENT, Permission::SYSTEM_CONFIG,
                Permission::METRICS_ACCESS, Permission::BACKUP_RESTORE, Permission::STREAMING,
                Permission::BATCH_OPERATIONS, Permission::AUDIT_ACCESS, Permission::KEY_MANAGEMENT
            };
        
        case Role::DEVELOPER:
            return {
                Permission::READ, Permission::WRITE, Permission::DELETE, Permission::QUERY,
                Permission::STREAMING, Permission::BATCH_OPERATIONS
            };
        
        case Role::READONLY:
            return {Permission::READ, Permission::QUERY};
        
        case Role::CUSTOM:
            return {}; // No default permissions for custom roles
    }
    return {};
}

std::string permission_to_string(Permission perm) {
    switch (perm) {
        case Permission::READ: return "READ";
        case Permission::WRITE: return "WRITE";
        case Permission::DELETE: return "DELETE";
        case Permission::QUERY: return "QUERY";
        case Permission::USER_MANAGEMENT: return "USER_MANAGEMENT";
        case Permission::ROLE_MANAGEMENT: return "ROLE_MANAGEMENT";
        case Permission::SYSTEM_CONFIG: return "SYSTEM_CONFIG";
        case Permission::METRICS_ACCESS: return "METRICS_ACCESS";
        case Permission::BACKUP_RESTORE: return "BACKUP_RESTORE";
        case Permission::STREAMING: return "STREAMING";
        case Permission::BATCH_OPERATIONS: return "BATCH_OPERATIONS";
        case Permission::AUDIT_ACCESS: return "AUDIT_ACCESS";
        case Permission::KEY_MANAGEMENT: return "KEY_MANAGEMENT";
    }
    return "UNKNOWN";
}

std::optional<Permission> string_to_permission(const std::string& perm_str) {
    if (perm_str == "READ") return Permission::READ;
    if (perm_str == "WRITE") return Permission::WRITE;
    if (perm_str == "DELETE") return Permission::DELETE;
    if (perm_str == "QUERY") return Permission::QUERY;
    if (perm_str == "USER_MANAGEMENT") return Permission::USER_MANAGEMENT;
    if (perm_str == "ROLE_MANAGEMENT") return Permission::ROLE_MANAGEMENT;
    if (perm_str == "SYSTEM_CONFIG") return Permission::SYSTEM_CONFIG;
    if (perm_str == "METRICS_ACCESS") return Permission::METRICS_ACCESS;
    if (perm_str == "BACKUP_RESTORE") return Permission::BACKUP_RESTORE;
    if (perm_str == "STREAMING") return Permission::STREAMING;
    if (perm_str == "BATCH_OPERATIONS") return Permission::BATCH_OPERATIONS;
    if (perm_str == "AUDIT_ACCESS") return Permission::AUDIT_ACCESS;
    if (perm_str == "KEY_MANAGEMENT") return Permission::KEY_MANAGEMENT;
    return std::nullopt;
}

std::string role_to_string(Role role) {
    switch (role) {
        case Role::ADMIN: return "ADMIN";
        case Role::DEVELOPER: return "DEVELOPER";
        case Role::READONLY: return "READONLY";
        case Role::CUSTOM: return "CUSTOM";
    }
    return "UNKNOWN";
}

std::optional<Role> string_to_role(const std::string& role_str) {
    if (role_str == "ADMIN") return Role::ADMIN;
    if (role_str == "DEVELOPER") return Role::DEVELOPER;
    if (role_str == "READONLY") return Role::READONLY;
    if (role_str == "CUSTOM") return Role::CUSTOM;
    return std::nullopt;
}

} // namespace ishikura::security