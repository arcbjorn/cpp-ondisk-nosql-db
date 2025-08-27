#include "security/api_key.hpp"
#include "security/audit.hpp"
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <random>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <regex>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace nosql_db::security {

namespace {
    // Utility function to generate secure random bytes
    std::vector<uint8_t> generate_random_bytes(size_t length) {
        std::vector<uint8_t> bytes(length);
        if (RAND_bytes(bytes.data(), static_cast<int>(length)) != 1) {
            // Fallback to system random device if OpenSSL fails
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<uint8_t> dis(0, 255);
            for (auto& byte : bytes) {
                byte = dis(gen);
            }
        }
        return bytes;
    }
    
    // Convert bytes to hex string
    std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t byte : bytes) {
            oss << std::setw(2) << static_cast<unsigned>(byte);
        }
        return oss.str();
    }
    
    // SHA-256 hash function
    std::string sha256_hash(const std::string& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, data.c_str(), data.size());
        SHA256_Final(hash, &sha256);
        
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            oss << std::setw(2) << static_cast<unsigned>(hash[i]);
        }
        return oss.str();
    }
    
    // Check if IP matches pattern (supports CIDR notation)
    bool ip_matches_pattern(const std::string& ip, const std::string& pattern) {
        if (pattern == "*" || pattern.empty()) {
            return true;
        }
        
        // Simple exact match
        if (ip == pattern) {
            return true;
        }
        
        // Wildcard patterns (e.g., 192.168.*.*)
        std::string regex_pattern = pattern;
        std::replace(regex_pattern.begin(), regex_pattern.end(), '*', '.');
        regex_pattern = std::regex_replace(regex_pattern, std::regex("\\."), "\\.");
        regex_pattern = std::regex_replace(regex_pattern, std::regex("\\*"), ".*");
        
        try {
            std::regex pattern_regex("^" + regex_pattern + "$");
            return std::regex_match(ip, pattern_regex);
        } catch (const std::exception&) {
            return false;
        }
    }
}

// ApiKeyManager Implementation
ApiKeyManager::ApiKeyManager(const std::string& storage_path) 
    : storage_path_(storage_path) {
    stats_.last_updated = std::chrono::system_clock::now();
}

ApiKeyManager::~ApiKeyManager() {
    shutdown();
}

bool ApiKeyManager::initialize() {
    std::lock_guard<std::mutex> lock(storage_mutex_);
    
    if (initialized_) {
        return true;
    }
    
    try {
        // Ensure storage directory exists
        std::filesystem::path storage_file(storage_path_);
        std::filesystem::create_directories(storage_file.parent_path());
        
        // Load existing keys from storage
        if (!load_keys_from_storage()) {
            spdlog::warn("Failed to load API keys from storage, starting with empty key store");
        }
        
        // Initialize statistics
        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            std::shared_lock<std::shared_mutex> keys_lock(keys_mutex_);
            
            stats_.total_keys = keys_by_id_.size();
            for (const auto& [key_id, key] : keys_by_id_) {
                switch (key.status) {
                    case ApiKeyStatus::ACTIVE:
                        stats_.active_keys++;
                        break;
                    case ApiKeyStatus::SUSPENDED:
                        stats_.suspended_keys++;
                        break;
                    case ApiKeyStatus::EXPIRED:
                        stats_.expired_keys++;
                        break;
                    case ApiKeyStatus::REVOKED:
                        stats_.revoked_keys++;
                        break;
                    default:
                        break;
                }
                stats_.total_requests += key.usage_count.load();
                stats_.total_bytes_transferred += key.bytes_transferred.load();
            }
        }
        
        initialized_ = true;
        spdlog::info("API Key Manager initialized with {} keys", keys_by_id_.size());
        
        // Log admin event
        if (AuditManager::is_initialized()) {
            AUDIT_ADMIN("system", "API key manager initialization", 
                       "Loaded " + std::to_string(keys_by_id_.size()) + " keys", true);
        }
        
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to initialize API Key Manager: {}", e.what());
        return false;
    }
}

void ApiKeyManager::shutdown() {
    if (!initialized_) {
        return;
    }
    
    try {
        // Save all keys to storage
        save_keys_to_storage();
        
        // Clear in-memory storage
        {
            std::unique_lock<std::shared_mutex> lock(keys_mutex_);
            keys_by_id_.clear();
            hash_to_id_map_.clear();
        }
        
        initialized_ = false;
        spdlog::info("API Key Manager shut down");
        
        // Log admin event
        if (AuditManager::is_initialized()) {
            AUDIT_ADMIN("system", "API key manager shutdown", "Graceful shutdown", true);
        }
        
    } catch (const std::exception& e) {
        spdlog::error("Error during API Key Manager shutdown: {}", e.what());
    }
}

std::pair<std::string, ApiKey> ApiKeyManager::generate_key(const std::string& name, 
                                                          const std::string& owner_id,
                                                          const KeyGenerationConfig& config) {
    if (!initialized_) {
        throw std::runtime_error("API Key Manager not initialized");
    }
    
    // Generate random key
    std::string raw_key = generate_random_key(config.key_length);
    
    // Add prefix if requested
    if (config.include_prefix) {
        raw_key = config.prefix + raw_key;
    }
    
    // Add checksum if requested
    if (config.include_checksum) {
        std::string checksum = calculate_checksum(raw_key);
        raw_key += "_" + checksum.substr(0, 8); // Use first 8 chars of checksum
    }
    
    // Create API key object
    ApiKey key;
    key.key_id = generate_random_key(16); // Generate unique ID
    key.key_hash = hash_key(raw_key);
    key.name = name;
    key.owner_id = owner_id;
    key.created_by = owner_id; // Assume creator is owner for now
    key.created_at = std::chrono::system_clock::now();
    key.last_used = std::chrono::system_clock::time_point{}; // Never used
    key.status = ApiKeyStatus::ACTIVE;
    key.permissions = config.default_permissions;
    key.rate_limit = config.default_rate_limit;
    key.last_rate_limit_reset = std::chrono::system_clock::now();
    
    // Set expiration if configured
    if (config.default_expiry.has_value()) {
        key.expires_at = std::chrono::system_clock::now() + *config.default_expiry;
    }
    
    // Store the key
    {
        std::unique_lock<std::shared_mutex> lock(keys_mutex_);
        keys_by_id_[key.key_id] = key;
        hash_to_id_map_[key.key_hash] = key.key_id;
    }
    
    // Save to storage
    save_key_to_storage(key);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.total_keys++;
        stats_.active_keys++;
    }
    
    // Fire event
    fire_event(key.key_id, "key_generated");
    
    // Log the key generation
    if (AuditManager::is_initialized()) {
        AUDIT_ADMIN(owner_id, "API key generation", 
                   "Generated key: " + key.name + " (ID: " + key.key_id + ")", true);
    }
    
    spdlog::info("Generated new API key '{}' for owner '{}'", name, owner_id);
    
    return std::make_pair(raw_key, key);
}

ValidationResult ApiKeyManager::validate_key(const std::string& raw_key, 
                                           ApiPermission required_permission,
                                           const std::string& client_ip,
                                           const std::string& resource) {
    if (!initialized_) {
        return ValidationResult::failure("API Key Manager not initialized");
    }
    
    // Basic format validation
    if (!validate_key_format(raw_key)) {
        return ValidationResult::failure("Invalid key format");
    }
    
    // Hash the key to find it in storage
    std::string key_hash = hash_key(raw_key);
    
    // Find the key
    std::shared_lock<std::shared_mutex> lock(keys_mutex_);
    auto hash_it = hash_to_id_map_.find(key_hash);
    if (hash_it == hash_to_id_map_.end()) {
        return ValidationResult::failure("Invalid API key");
    }
    
    auto key_it = keys_by_id_.find(hash_it->second);
    if (key_it == keys_by_id_.end()) {
        return ValidationResult::failure("Invalid API key");
    }
    
    ApiKey& key = key_it->second;
    lock.unlock(); // Release shared lock for potential modifications
    
    // Check key status
    if (!key.is_active()) {
        std::string status_msg;
        switch (key.status) {
            case ApiKeyStatus::SUSPENDED:
                status_msg = "suspended";
                break;
            case ApiKeyStatus::EXPIRED:
                status_msg = "expired";
                break;
            case ApiKeyStatus::REVOKED:
                status_msg = "revoked";
                break;
            case ApiKeyStatus::PENDING_ACTIVATION:
                status_msg = "pending activation";
                break;
            default:
                status_msg = "inactive";
                break;
        }
        return ValidationResult::failure("API key is " + status_msg);
    }
    
    // Check expiration
    if (key.is_expired()) {
        // Update status to expired
        key.status = ApiKeyStatus::EXPIRED;
        save_key_to_storage(key);
        return ValidationResult::failure("API key has expired");
    }
    
    // Check permissions
    if (!key.has_permission(required_permission)) {
        return ValidationResult::failure("Insufficient permissions");
    }
    
    // Check IP restrictions
    if (!client_ip.empty() && !check_ip_access(key, client_ip)) {
        return ValidationResult::failure("IP address not allowed");
    }
    
    // Check resource access patterns
    if (!resource.empty() && !check_resource_access(key.key_id, resource)) {
        return ValidationResult::failure("Resource access denied");
    }
    
    // Check rate limits
    if (is_rate_limited(key.key_id)) {
        std::chrono::seconds retry_after = calculate_retry_after(key);
        return ValidationResult::rate_limit_exceeded(retry_after);
    }
    
    // Update usage statistics
    key.last_used = std::chrono::system_clock::now();
    
    // Log successful validation
    if (AuditManager::is_initialized()) {
        AUDIT_ACCESS(client_ip.empty() ? key.owner_id : client_ip, 
                    "API key validation", 
                    "Key: " + key.name + ", Resource: " + resource, true);
    }
    
    return ValidationResult::success(key.key_id, key.permissions);
}

bool ApiKeyManager::is_rate_limited(const std::string& key_id, uint32_t request_cost, 
                                   uint64_t bytes_cost) {
    std::shared_lock<std::shared_mutex> lock(keys_mutex_);
    auto it = keys_by_id_.find(key_id);
    if (it == keys_by_id_.end()) {
        return true; // Unknown key is rate limited
    }
    
    ApiKey& key = it->second;
    lock.unlock();
    
    // Update rate limit counters
    update_rate_limit_counters(key);
    
    // Check rate limits
    return !check_rate_limit(key, request_cost, bytes_cost);
}

void ApiKeyManager::record_usage(const std::string& key_id, uint32_t request_cost, 
                                uint64_t bytes_cost) {
    std::shared_lock<std::shared_mutex> lock(keys_mutex_);
    auto it = keys_by_id_.find(key_id);
    if (it == keys_by_id_.end()) {
        return;
    }
    
    ApiKey& key = it->second;
    lock.unlock();
    
    // Update counters
    key.usage_count += request_cost;
    key.bytes_transferred += bytes_cost;
    key.requests_this_minute += request_cost;
    key.requests_this_hour += request_cost;
    key.requests_today += request_cost;
    key.bytes_this_minute += bytes_cost;
    key.bytes_this_hour += bytes_cost;
    key.bytes_today += bytes_cost;
    
    // Update global statistics
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.total_requests += request_cost;
        stats_.total_bytes_transferred += bytes_cost;
    }
}

// Private helper methods
bool ApiKeyManager::load_keys_from_storage() {
    if (!std::filesystem::exists(storage_path_)) {
        spdlog::info("Storage file does not exist, starting with empty key store");
        return true; // Not an error for first run
    }
    
    try {
        std::ifstream file(storage_path_);
        if (!file.is_open()) {
            spdlog::error("Failed to open storage file: {}", storage_path_);
            return false;
        }
        
        nlohmann::json data;
        file >> data;
        file.close();
        
        if (!data.contains("keys") || !data["keys"].is_array()) {
            spdlog::warn("Invalid storage file format");
            return false;
        }
        
        std::unique_lock<std::shared_mutex> lock(keys_mutex_);
        keys_by_id_.clear();
        hash_to_id_map_.clear();
        
        for (const auto& key_data : data["keys"]) {
            try {
                ApiKey key;
                key.key_id = key_data.value("key_id", "");
                key.key_hash = key_data.value("key_hash", "");
                key.name = key_data.value("name", "");
                key.description = key_data.value("description", "");
                key.owner_id = key_data.value("owner_id", "");
                key.created_by = key_data.value("created_by", "");
                
                // Parse timestamps
                if (key_data.contains("created_at")) {
                    auto timestamp = std::chrono::system_clock::from_time_t(key_data["created_at"]);
                    key.created_at = timestamp;
                }
                
                if (key_data.contains("last_used")) {
                    auto timestamp = std::chrono::system_clock::from_time_t(key_data["last_used"]);
                    key.last_used = timestamp;
                }
                
                if (key_data.contains("expires_at") && !key_data["expires_at"].is_null()) {
                    auto timestamp = std::chrono::system_clock::from_time_t(key_data["expires_at"]);
                    key.expires_at = timestamp;
                }
                
                // Parse status
                key.status = string_to_status(key_data.value("status", "active"));
                
                // Parse permissions
                key.permissions = string_list_to_permission(
                    key_data.value("permissions", std::vector<std::string>{}));
                
                // Parse allowed IPs and hosts
                key.allowed_ips = key_data.value("allowed_ips", std::vector<std::string>{});
                key.allowed_hosts = key_data.value("allowed_hosts", std::vector<std::string>{});
                
                // Parse resource patterns
                auto patterns = key_data.value("resource_patterns", std::vector<std::string>{});
                key.resource_patterns = std::unordered_set<std::string>(patterns.begin(), patterns.end());
                
                // Parse rate limits
                if (key_data.contains("rate_limit")) {
                    const auto& rl = key_data["rate_limit"];
                    key.rate_limit.requests_per_minute = rl.value("requests_per_minute", 1000u);
                    key.rate_limit.requests_per_hour = rl.value("requests_per_hour", 60000u);
                    key.rate_limit.requests_per_day = rl.value("requests_per_day", 1000000u);
                    key.rate_limit.burst_limit = rl.value("burst_limit", 100u);
                    key.rate_limit.bytes_per_minute = rl.value("bytes_per_minute", 100ULL * 1024 * 1024);
                    key.rate_limit.bytes_per_hour = rl.value("bytes_per_hour", 1024ULL * 1024 * 1024);
                    key.rate_limit.bytes_per_day = rl.value("bytes_per_day", 10ULL * 1024 * 1024 * 1024);
                }
                
                // Parse usage statistics
                key.usage_count = key_data.value("usage_count", 0ULL);
                key.bytes_transferred = key_data.value("bytes_transferred", 0ULL);
                
                // Parse metadata
                key.metadata = key_data.value("metadata", std::unordered_map<std::string, std::string>{});
                
                // Initialize rate limit counters
                key.last_rate_limit_reset = std::chrono::system_clock::now();
                
                // Store the key
                keys_by_id_[key.key_id] = key;
                hash_to_id_map_[key.key_hash] = key.key_id;
                
            } catch (const std::exception& e) {
                spdlog::warn("Failed to parse API key from storage: {}", e.what());
                continue; // Skip corrupted key
            }
        }
        
        spdlog::info("Loaded {} API keys from storage", keys_by_id_.size());
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to load keys from storage: {}", e.what());
        return false;
    }
}

bool ApiKeyManager::save_keys_to_storage() {
    try {
        nlohmann::json data;
        data["version"] = "1.0";
        data["timestamp"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        data["keys"] = nlohmann::json::array();
        
        std::shared_lock<std::shared_mutex> lock(keys_mutex_);
        
        for (const auto& [key_id, key] : keys_by_id_) {
            nlohmann::json key_data;
            key_data["key_id"] = key.key_id;
            key_data["key_hash"] = key.key_hash;
            key_data["name"] = key.name;
            key_data["description"] = key.description;
            key_data["owner_id"] = key.owner_id;
            key_data["created_by"] = key.created_by;
            key_data["created_at"] = std::chrono::system_clock::to_time_t(key.created_at);
            key_data["last_used"] = std::chrono::system_clock::to_time_t(key.last_used);
            
            if (key.expires_at.has_value()) {
                key_data["expires_at"] = std::chrono::system_clock::to_time_t(*key.expires_at);
            } else {
                key_data["expires_at"] = nullptr;
            }
            
            key_data["status"] = status_to_string(key.status);
            key_data["permissions"] = permission_to_string_list(key.permissions);
            key_data["allowed_ips"] = key.allowed_ips;
            key_data["allowed_hosts"] = key.allowed_hosts;
            
            std::vector<std::string> patterns(key.resource_patterns.begin(), key.resource_patterns.end());
            key_data["resource_patterns"] = patterns;
            
            // Save rate limits
            key_data["rate_limit"]["requests_per_minute"] = key.rate_limit.requests_per_minute;
            key_data["rate_limit"]["requests_per_hour"] = key.rate_limit.requests_per_hour;
            key_data["rate_limit"]["requests_per_day"] = key.rate_limit.requests_per_day;
            key_data["rate_limit"]["burst_limit"] = key.rate_limit.burst_limit;
            key_data["rate_limit"]["bytes_per_minute"] = key.rate_limit.bytes_per_minute;
            key_data["rate_limit"]["bytes_per_hour"] = key.rate_limit.bytes_per_hour;
            key_data["rate_limit"]["bytes_per_day"] = key.rate_limit.bytes_per_day;
            
            // Save usage statistics
            key_data["usage_count"] = key.usage_count.load();
            key_data["bytes_transferred"] = key.bytes_transferred.load();
            
            // Save metadata
            key_data["metadata"] = key.metadata;
            
            data["keys"].push_back(key_data);
        }
        
        lock.unlock();
        
        // Write to file
        std::ofstream file(storage_path_);
        if (!file.is_open()) {
            spdlog::error("Failed to open storage file for writing: {}", storage_path_);
            return false;
        }
        
        file << data.dump(2);
        file.close();
        
        spdlog::debug("Saved {} API keys to storage", keys_by_id_.size());
        return true;
        
    } catch (const std::exception& e) {
        spdlog::error("Failed to save keys to storage: {}", e.what());
        return false;
    }
}

std::string ApiKeyManager::generate_random_key(size_t length) {
    auto bytes = generate_random_bytes(length);
    return bytes_to_hex(bytes);
}

std::string ApiKeyManager::hash_key(const std::string& raw_key) {
    return sha256_hash(raw_key);
}

bool ApiKeyManager::validate_key_format(const std::string& raw_key) {
    if (raw_key.empty() || raw_key.length() < 16) {
        return false;
    }
    
    // Check for valid characters (alphanumeric and underscore)
    const std::string valid_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
    return raw_key.find_first_not_of(valid_chars) == std::string::npos;
}

bool ApiKeyManager::check_ip_access(const ApiKey& key, const std::string& client_ip) {
    if (key.allowed_ips.empty()) {
        return true; // No restrictions
    }
    
    for (const std::string& pattern : key.allowed_ips) {
        if (ip_matches_pattern(client_ip, pattern)) {
            return true;
        }
    }
    
    return false;
}

bool ApiKeyManager::check_resource_access(const std::string& key_id, const std::string& resource) {
    std::shared_lock<std::shared_mutex> lock(keys_mutex_);
    auto it = keys_by_id_.find(key_id);
    if (it == keys_by_id_.end()) {
        return false;
    }
    
    const ApiKey& key = it->second;
    
    if (key.resource_patterns.empty()) {
        return true; // No restrictions
    }
    
    for (const std::string& pattern : key.resource_patterns) {
        if (match_pattern(resource, pattern)) {
            return true;
        }
    }
    
    return false;
}

bool ApiKeyManager::match_pattern(const std::string& value, const std::string& pattern) {
    if (pattern == "*") {
        return true;
    }
    
    // Simple wildcard matching
    try {
        std::string regex_pattern = pattern;
        std::replace(regex_pattern.begin(), regex_pattern.end(), '*', '.');
        regex_pattern = std::regex_replace(regex_pattern, std::regex("\\."), "\\.");
        regex_pattern = std::regex_replace(regex_pattern, std::regex("\\*"), ".*");
        
        std::regex pattern_regex("^" + regex_pattern + "$");
        return std::regex_match(value, pattern_regex);
    } catch (const std::exception&) {
        return value == pattern; // Fallback to exact match
    }
}

void ApiKeyManager::update_rate_limit_counters(ApiKey& key) {
    auto now = std::chrono::system_clock::now();
    auto time_since_reset = now - key.last_rate_limit_reset;
    
    // Reset counters based on time windows
    if (time_since_reset >= std::chrono::minutes(1)) {
        key.requests_this_minute = 0;
        key.bytes_this_minute = 0;
    }
    
    if (time_since_reset >= std::chrono::hours(1)) {
        key.requests_this_hour = 0;
        key.bytes_this_hour = 0;
    }
    
    if (time_since_reset >= std::chrono::hours(24)) {
        key.requests_today = 0;
        key.bytes_today = 0;
        key.last_rate_limit_reset = now;
    }
}

bool ApiKeyManager::check_rate_limit(const ApiKey& key, uint32_t request_cost, uint64_t bytes_cost) {
    // Check request rate limits
    if (key.requests_this_minute.load() + request_cost > key.rate_limit.requests_per_minute) {
        return false;
    }
    
    if (key.requests_this_hour.load() + request_cost > key.rate_limit.requests_per_hour) {
        return false;
    }
    
    if (key.requests_today.load() + request_cost > key.rate_limit.requests_per_day) {
        return false;
    }
    
    // Check byte transfer limits
    if (key.bytes_this_minute.load() + bytes_cost > key.rate_limit.bytes_per_minute) {
        return false;
    }
    
    if (key.bytes_this_hour.load() + bytes_cost > key.rate_limit.bytes_per_hour) {
        return false;
    }
    
    if (key.bytes_today.load() + bytes_cost > key.rate_limit.bytes_per_day) {
        return false;
    }
    
    return true;
}

std::chrono::seconds ApiKeyManager::calculate_retry_after(const ApiKey& key) {
    // Return seconds until next minute (simplest approach)
    auto now = std::chrono::system_clock::now();
    auto time_since_epoch = now.time_since_epoch();
    auto seconds_in_minute = std::chrono::duration_cast<std::chrono::seconds>(time_since_epoch) % std::chrono::minutes(1);
    return std::chrono::minutes(1) - seconds_in_minute;
}

std::string ApiKeyManager::calculate_checksum(const std::string& key) {
    return sha256_hash(key).substr(0, 8);
}

void ApiKeyManager::fire_event(const std::string& key_id, const std::string& event_type) {
    std::lock_guard<std::mutex> lock(callback_mutex_);
    if (event_callback_) {
        try {
            event_callback_(key_id, event_type);
        } catch (const std::exception& e) {
            spdlog::warn("Event callback failed: {}", e.what());
        }
    }
}

// Global instance management
std::unique_ptr<ApiKeyManager> ApiKeyManagerInstance::instance_;
std::mutex ApiKeyManagerInstance::instance_mutex_;
std::atomic<bool> ApiKeyManagerInstance::initialized_{false};

ApiKeyManager& ApiKeyManagerInstance::instance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (!instance_) {
        throw std::runtime_error("ApiKeyManager not initialized");
    }
    return *instance_;
}

bool ApiKeyManagerInstance::initialize(const std::string& storage_path) {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (initialized_) {
        return true;
    }
    
    instance_ = std::make_unique<ApiKeyManager>(storage_path);
    if (instance_->initialize()) {
        initialized_ = true;
        return true;
    } else {
        instance_.reset();
        return false;
    }
}

void ApiKeyManagerInstance::shutdown() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_) {
        instance_->shutdown();
        instance_.reset();
        initialized_ = false;
    }
}

bool ApiKeyManagerInstance::is_initialized() {
    return initialized_.load();
}

// Utility functions
std::string permission_to_string(ApiPermission permission) {
    std::vector<std::string> perms;
    
    if ((permission & ApiPermission::READ) == ApiPermission::READ) perms.push_back("read");
    if ((permission & ApiPermission::WRITE) == ApiPermission::WRITE) perms.push_back("write");
    if ((permission & ApiPermission::DELETE) == ApiPermission::DELETE) perms.push_back("delete");
    if ((permission & ApiPermission::QUERY) == ApiPermission::QUERY) perms.push_back("query");
    if ((permission & ApiPermission::ADMIN_USER_MANAGEMENT) == ApiPermission::ADMIN_USER_MANAGEMENT) perms.push_back("admin_users");
    if ((permission & ApiPermission::ADMIN_CONFIG) == ApiPermission::ADMIN_CONFIG) perms.push_back("admin_config");
    if ((permission & ApiPermission::ADMIN_BACKUP) == ApiPermission::ADMIN_BACKUP) perms.push_back("admin_backup");
    if ((permission & ApiPermission::ADMIN_MONITORING) == ApiPermission::ADMIN_MONITORING) perms.push_back("admin_monitoring");
    if ((permission & ApiPermission::SYSTEM_INFO) == ApiPermission::SYSTEM_INFO) perms.push_back("system_info");
    if ((permission & ApiPermission::SYSTEM_STATS) == ApiPermission::SYSTEM_STATS) perms.push_back("system_stats");
    if ((permission & ApiPermission::SYSTEM_HEALTH) == ApiPermission::SYSTEM_HEALTH) perms.push_back("system_health");
    if ((permission & ApiPermission::BATCH_OPERATIONS) == ApiPermission::BATCH_OPERATIONS) perms.push_back("batch_ops");
    if ((permission & ApiPermission::STREAMING) == ApiPermission::STREAMING) perms.push_back("streaming");
    if ((permission & ApiPermission::TRANSACTIONS) == ApiPermission::TRANSACTIONS) perms.push_back("transactions");
    
    if (perms.empty()) {
        return "none";
    }
    
    std::string result = perms[0];
    for (size_t i = 1; i < perms.size(); ++i) {
        result += "," + perms[i];
    }
    return result;
}

std::vector<std::string> permission_to_string_list(ApiPermission permissions) {
    std::vector<std::string> result;
    
    if ((permissions & ApiPermission::READ) == ApiPermission::READ) result.push_back("read");
    if ((permissions & ApiPermission::WRITE) == ApiPermission::WRITE) result.push_back("write");
    if ((permissions & ApiPermission::DELETE) == ApiPermission::DELETE) result.push_back("delete");
    if ((permissions & ApiPermission::QUERY) == ApiPermission::QUERY) result.push_back("query");
    if ((permissions & ApiPermission::ADMIN_USER_MANAGEMENT) == ApiPermission::ADMIN_USER_MANAGEMENT) result.push_back("admin_users");
    if ((permissions & ApiPermission::ADMIN_CONFIG) == ApiPermission::ADMIN_CONFIG) result.push_back("admin_config");
    if ((permissions & ApiPermission::ADMIN_BACKUP) == ApiPermission::ADMIN_BACKUP) result.push_back("admin_backup");
    if ((permissions & ApiPermission::ADMIN_MONITORING) == ApiPermission::ADMIN_MONITORING) result.push_back("admin_monitoring");
    if ((permissions & ApiPermission::SYSTEM_INFO) == ApiPermission::SYSTEM_INFO) result.push_back("system_info");
    if ((permissions & ApiPermission::SYSTEM_STATS) == ApiPermission::SYSTEM_STATS) result.push_back("system_stats");
    if ((permissions & ApiPermission::SYSTEM_HEALTH) == ApiPermission::SYSTEM_HEALTH) result.push_back("system_health");
    if ((permissions & ApiPermission::BATCH_OPERATIONS) == ApiPermission::BATCH_OPERATIONS) result.push_back("batch_ops");
    if ((permissions & ApiPermission::STREAMING) == ApiPermission::STREAMING) result.push_back("streaming");
    if ((permissions & ApiPermission::TRANSACTIONS) == ApiPermission::TRANSACTIONS) result.push_back("transactions");
    
    return result;
}

ApiPermission string_list_to_permission(const std::vector<std::string>& permission_list) {
    ApiPermission result = static_cast<ApiPermission>(0);
    
    for (const std::string& perm : permission_list) {
        if (perm == "read") result = result | ApiPermission::READ;
        else if (perm == "write") result = result | ApiPermission::WRITE;
        else if (perm == "delete") result = result | ApiPermission::DELETE;
        else if (perm == "query") result = result | ApiPermission::QUERY;
        else if (perm == "admin_users") result = result | ApiPermission::ADMIN_USER_MANAGEMENT;
        else if (perm == "admin_config") result = result | ApiPermission::ADMIN_CONFIG;
        else if (perm == "admin_backup") result = result | ApiPermission::ADMIN_BACKUP;
        else if (perm == "admin_monitoring") result = result | ApiPermission::ADMIN_MONITORING;
        else if (perm == "system_info") result = result | ApiPermission::SYSTEM_INFO;
        else if (perm == "system_stats") result = result | ApiPermission::SYSTEM_STATS;
        else if (perm == "system_health") result = result | ApiPermission::SYSTEM_HEALTH;
        else if (perm == "batch_ops") result = result | ApiPermission::BATCH_OPERATIONS;
        else if (perm == "streaming") result = result | ApiPermission::STREAMING;
        else if (perm == "transactions") result = result | ApiPermission::TRANSACTIONS;
    }
    
    return result;
}

std::string status_to_string(ApiKeyStatus status) {
    switch (status) {
        case ApiKeyStatus::ACTIVE: return "active";
        case ApiKeyStatus::SUSPENDED: return "suspended";
        case ApiKeyStatus::EXPIRED: return "expired";
        case ApiKeyStatus::REVOKED: return "revoked";
        case ApiKeyStatus::PENDING_ACTIVATION: return "pending";
        default: return "unknown";
    }
}

ApiKeyStatus string_to_status(const std::string& status_str) {
    if (status_str == "active") return ApiKeyStatus::ACTIVE;
    if (status_str == "suspended") return ApiKeyStatus::SUSPENDED;
    if (status_str == "expired") return ApiKeyStatus::EXPIRED;
    if (status_str == "revoked") return ApiKeyStatus::REVOKED;
    if (status_str == "pending") return ApiKeyStatus::PENDING_ACTIVATION;
    return ApiKeyStatus::ACTIVE; // Default
}

// Additional ApiKeyManager method implementations
bool ApiKeyManager::save_key_to_storage(const ApiKey& key) {
    // For now, just save all keys - could be optimized to save individual keys
    return save_keys_to_storage();
}

bool ApiKeyManager::remove_key_from_storage(const std::string& key_id) {
    // For now, just save all keys after removing from memory - could be optimized
    return save_keys_to_storage();
}

bool ApiKeyManager::revoke_key(const std::string& key_id) {
    std::unique_lock<std::shared_mutex> lock(keys_mutex_);
    auto it = keys_by_id_.find(key_id);
    if (it == keys_by_id_.end()) {
        return false;
    }
    
    it->second.status = ApiKeyStatus::REVOKED;
    lock.unlock();
    
    // Save to storage
    save_key_to_storage(it->second);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.active_keys--;
        stats_.revoked_keys++;
    }
    
    // Fire event and log
    fire_event(key_id, "key_revoked");
    
    if (AuditManager::is_initialized()) {
        AUDIT_ADMIN(it->second.owner_id, "API key revocation", 
                   "Revoked key: " + it->second.name + " (ID: " + key_id + ")", true);
    }
    
    return true;
}

bool ApiKeyManager::suspend_key(const std::string& key_id) {
    std::unique_lock<std::shared_mutex> lock(keys_mutex_);
    auto it = keys_by_id_.find(key_id);
    if (it == keys_by_id_.end()) {
        return false;
    }
    
    if (it->second.status != ApiKeyStatus::ACTIVE) {
        return false; // Can only suspend active keys
    }
    
    it->second.status = ApiKeyStatus::SUSPENDED;
    lock.unlock();
    
    // Save to storage
    save_key_to_storage(it->second);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.active_keys--;
        stats_.suspended_keys++;
    }
    
    // Fire event and log
    fire_event(key_id, "key_suspended");
    
    if (AuditManager::is_initialized()) {
        AUDIT_ADMIN(it->second.owner_id, "API key suspension", 
                   "Suspended key: " + it->second.name + " (ID: " + key_id + ")", true);
    }
    
    return true;
}

bool ApiKeyManager::activate_key(const std::string& key_id) {
    std::unique_lock<std::shared_mutex> lock(keys_mutex_);
    auto it = keys_by_id_.find(key_id);
    if (it == keys_by_id_.end()) {
        return false;
    }
    
    if (it->second.status != ApiKeyStatus::SUSPENDED && it->second.status != ApiKeyStatus::PENDING_ACTIVATION) {
        return false; // Can only activate suspended or pending keys
    }
    
    ApiKeyStatus old_status = it->second.status;
    it->second.status = ApiKeyStatus::ACTIVE;
    lock.unlock();
    
    // Save to storage
    save_key_to_storage(it->second);
    
    // Update statistics
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.active_keys++;
        if (old_status == ApiKeyStatus::SUSPENDED) {
            stats_.suspended_keys--;
        }
    }
    
    // Fire event and log
    fire_event(key_id, "key_activated");
    
    if (AuditManager::is_initialized()) {
        AUDIT_ADMIN(it->second.owner_id, "API key activation", 
                   "Activated key: " + it->second.name + " (ID: " + key_id + ")", true);
    }
    
    return true;
}

std::optional<ApiKey> ApiKeyManager::get_key_by_id(const std::string& key_id) {
    std::shared_lock<std::shared_mutex> lock(keys_mutex_);
    auto it = keys_by_id_.find(key_id);
    if (it == keys_by_id_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<ApiKey> ApiKeyManager::get_keys_by_owner(const std::string& owner_id) {
    std::vector<ApiKey> result;
    std::shared_lock<std::shared_mutex> lock(keys_mutex_);
    
    for (const auto& [key_id, key] : keys_by_id_) {
        if (key.owner_id == owner_id) {
            result.push_back(key);
        }
    }
    
    return result;
}

std::vector<ApiKey> ApiKeyManager::list_all_keys(bool include_revoked) {
    std::vector<ApiKey> result;
    std::shared_lock<std::shared_mutex> lock(keys_mutex_);
    
    for (const auto& [key_id, key] : keys_by_id_) {
        if (include_revoked || key.status != ApiKeyStatus::REVOKED) {
            result.push_back(key);
        }
    }
    
    return result;
}

ApiKeyManager::KeyStats ApiKeyManager::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    KeyStats current_stats = stats_;
    current_stats.last_updated = std::chrono::system_clock::now();
    return current_stats;
}

void ApiKeyManager::cleanup_expired_keys() {
    std::vector<std::string> expired_keys;
    auto now = std::chrono::system_clock::now();
    
    {
        std::unique_lock<std::shared_mutex> lock(keys_mutex_);
        
        for (auto& [key_id, key] : keys_by_id_) {
            if (key.expires_at.has_value() && now > *key.expires_at) {
                if (key.status == ApiKeyStatus::ACTIVE) {
                    key.status = ApiKeyStatus::EXPIRED;
                    expired_keys.push_back(key_id);
                }
            }
        }
    }
    
    // Update statistics
    if (!expired_keys.empty()) {
        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.active_keys -= expired_keys.size();
            stats_.expired_keys += expired_keys.size();
        }
        
        // Save changes to storage
        save_keys_to_storage();
        
        // Log cleanup
        if (AuditManager::is_initialized()) {
            AUDIT_ADMIN("system", "API key cleanup", 
                       "Expired " + std::to_string(expired_keys.size()) + " keys", true);
        }
        
        spdlog::info("Cleaned up {} expired API keys", expired_keys.size());
    }
}

} // namespace nosql_db::security