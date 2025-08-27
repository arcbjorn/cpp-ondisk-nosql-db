#include "security/api_key.hpp"
#include "security/audit.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>

using namespace nosql_db::security;

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options] <command> [args...]\\n"
              << "\\n"
              << "Commands:\\n"
              << "  generate <name> <owner_id>     Generate new API key\\n"
              << "  list [owner_id]                List API keys (optionally by owner)\\n"
              << "  show <key_id>                  Show details of specific key\\n"
              << "  validate <raw_key> <permission> Validate API key and permission\\n"
              << "  revoke <key_id>                Revoke an API key\\n"
              << "  suspend <key_id>               Suspend an API key\\n"
              << "  activate <key_id>              Activate a suspended key\\n"
              << "  stats                          Show usage statistics\\n"
              << "  cleanup                        Remove expired keys\\n"
              << "\\n"
              << "Options:\\n"
              << "  --storage <path>               Storage file path (default: api_keys.db)\\n"
              << "  --permissions <perms>          Comma-separated permissions for generate command\\n"
              << "  --expires <hours>              Key expiration in hours for generate command\\n"
              << "  --help                         Show this help message\\n"
              << "\\n"
              << "Permissions:\\n"
              << "  read, write, delete, query, admin_users, admin_config, admin_backup,\\n"
              << "  admin_monitoring, system_info, system_stats, system_health, batch_ops,\\n"
              << "  streaming, transactions\\n";
}

std::vector<std::string> split_string(const std::string& str, char delimiter) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;
    
    while (std::getline(ss, item, delimiter)) {
        result.push_back(item);
    }
    
    return result;
}

ApiPermission parse_permissions(const std::string& perms_str) {
    if (perms_str.empty()) {
        return ApiPermission::READ | ApiPermission::WRITE;
    }
    
    auto perm_list = split_string(perms_str, ',');
    
    // Trim whitespace from each permission
    for (auto& perm : perm_list) {
        perm.erase(perm.begin(), std::find_if(perm.begin(), perm.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));
        perm.erase(std::find_if(perm.rbegin(), perm.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), perm.end());
    }
    
    return string_list_to_permission(perm_list);
}

std::string format_timestamp(const std::chrono::system_clock::time_point& tp) {
    if (tp == std::chrono::system_clock::time_point{}) {
        return "Never";
    }
    
    auto time_t = std::chrono::system_clock::to_time_t(tp);
    auto tm = *std::localtime(&time_t);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void print_key_info(const ApiKey& key) {
    std::cout << "Key ID: " << key.key_id << std::endl;
    std::cout << "Name: " << key.name << std::endl;
    std::cout << "Owner: " << key.owner_id << std::endl;
    std::cout << "Status: " << status_to_string(key.status) << std::endl;
    std::cout << "Created: " << format_timestamp(key.created_at) << std::endl;
    std::cout << "Last Used: " << format_timestamp(key.last_used) << std::endl;
    
    if (key.expires_at.has_value()) {
        std::cout << "Expires: " << format_timestamp(*key.expires_at) << std::endl;
    } else {
        std::cout << "Expires: Never" << std::endl;
    }
    
    std::cout << "Permissions: " << permission_to_string(key.permissions) << std::endl;
    std::cout << "Usage Count: " << key.usage_count.load() << std::endl;
    std::cout << "Bytes Transferred: " << key.bytes_transferred.load() << std::endl;
    
    if (!key.allowed_ips.empty()) {
        std::cout << "Allowed IPs: ";
        for (size_t i = 0; i < key.allowed_ips.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << key.allowed_ips[i];
        }
        std::cout << std::endl;
    }
    
    std::cout << "Rate Limits:" << std::endl;
    std::cout << "  Requests/min: " << key.rate_limit.requests_per_minute << std::endl;
    std::cout << "  Requests/hour: " << key.rate_limit.requests_per_hour << std::endl;
    std::cout << "  Requests/day: " << key.rate_limit.requests_per_day << std::endl;
    std::cout << "  Bytes/min: " << key.rate_limit.bytes_per_minute << " bytes" << std::endl;
    
    if (!key.description.empty()) {
        std::cout << "Description: " << key.description << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "NoSQL DB API Key Manager" << std::endl;
    std::cout << "========================" << std::endl;
    
    std::string storage_path = "api_keys.db";
    std::string permissions_str;
    std::optional<int> expiry_hours;
    
    // Parse options
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--storage" && i + 1 < argc) {
            storage_path = argv[++i];
        } else if (arg == "--permissions" && i + 1 < argc) {
            permissions_str = argv[++i];
        } else if (arg == "--expires" && i + 1 < argc) {
            expiry_hours = std::stoi(argv[++i]);
        } else if (arg.substr(0, 2) == "--") {
            std::cerr << "Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        } else {
            args.push_back(arg);
        }
    }
    
    if (args.empty()) {
        std::cerr << "No command specified" << std::endl;
        print_usage(argv[0]);
        return 1;
    }
    
    // Initialize audit system
    if (!AuditManager::is_initialized()) {
        AuditConfig audit_config;
        audit_config.log_file = "api_key_manager_audit.log";
        audit_config.enable_file_logging = true;
        audit_config.min_severity = AuditSeverity::INFO;
        AuditManager::initialize(audit_config);
    }
    
    // Initialize API key manager
    if (!ApiKeyManagerInstance::initialize(storage_path)) {
        std::cerr << "Failed to initialize API Key Manager" << std::endl;
        return 1;
    }
    
    auto& manager = ApiKeyManagerInstance::instance();
    std::string command = args[0];
    
    try {
        if (command == "generate") {
            if (args.size() < 3) {
                std::cerr << "Usage: generate <name> <owner_id>" << std::endl;
                return 1;
            }
            
            std::string name = args[1];
            std::string owner_id = args[2];
            
            KeyGenerationConfig config;
            if (!permissions_str.empty()) {
                config.default_permissions = parse_permissions(permissions_str);
            }
            
            if (expiry_hours.has_value()) {
                config.default_expiry = std::chrono::hours(*expiry_hours);
            }
            
            auto [raw_key, key] = manager.generate_key(name, owner_id, config);
            
            std::cout << "Generated API key:" << std::endl;
            std::cout << "Raw Key: " << raw_key << std::endl;
            std::cout << std::endl;
            print_key_info(key);
            
        } else if (command == "list") {
            std::string owner_filter;
            if (args.size() > 1) {
                owner_filter = args[1];
            }
            
            std::vector<ApiKey> keys;
            if (owner_filter.empty()) {
                keys = manager.list_all_keys();
            } else {
                keys = manager.get_keys_by_owner(owner_filter);
            }
            
            if (keys.empty()) {
                std::cout << "No API keys found" << std::endl;
                return 0;
            }
            
            std::cout << "Found " << keys.size() << " API key(s):" << std::endl;
            std::cout << std::endl;
            
            std::cout << std::left << std::setw(20) << "Key ID" 
                      << std::setw(20) << "Name"
                      << std::setw(15) << "Owner"
                      << std::setw(12) << "Status"
                      << std::setw(12) << "Usage"
                      << "Created" << std::endl;
            std::cout << std::string(95, '-') << std::endl;
            
            for (const auto& key : keys) {
                std::cout << std::left << std::setw(20) << key.key_id.substr(0, 18) + ".."
                          << std::setw(20) << key.name.substr(0, 18)
                          << std::setw(15) << key.owner_id.substr(0, 13)
                          << std::setw(12) << status_to_string(key.status)
                          << std::setw(12) << key.usage_count.load()
                          << format_timestamp(key.created_at) << std::endl;
            }
            
        } else if (command == "show") {
            if (args.size() < 2) {
                std::cerr << "Usage: show <key_id>" << std::endl;
                return 1;
            }
            
            std::string key_id = args[1];
            auto key_opt = manager.get_key_by_id(key_id);
            
            if (!key_opt.has_value()) {
                std::cerr << "API key not found: " << key_id << std::endl;
                return 1;
            }
            
            print_key_info(*key_opt);
            
        } else if (command == "validate") {
            if (args.size() < 3) {
                std::cerr << "Usage: validate <raw_key> <permission>" << std::endl;
                return 1;
            }
            
            std::string raw_key = args[1];
            std::string permission_str = args[2];
            
            ApiPermission required_perm = string_list_to_permission({permission_str});
            ValidationResult result = manager.validate_key(raw_key, required_perm);
            
            std::cout << "Validation Result:" << std::endl;
            std::cout << "Valid: " << (result.is_valid ? "Yes" : "No") << std::endl;
            
            if (result.is_valid) {
                std::cout << "Key ID: " << result.key_id << std::endl;
                std::cout << "Granted Permissions: " << permission_to_string(result.granted_permissions) << std::endl;
            } else {
                std::cout << "Error: " << result.error_message << std::endl;
                if (result.rate_limited) {
                    std::cout << "Retry After: " << result.retry_after.count() << " seconds" << std::endl;
                }
            }
            
        } else if (command == "revoke") {
            if (args.size() < 2) {
                std::cerr << "Usage: revoke <key_id>" << std::endl;
                return 1;
            }
            
            std::string key_id = args[1];
            if (manager.revoke_key(key_id)) {
                std::cout << "API key revoked: " << key_id << std::endl;
            } else {
                std::cerr << "Failed to revoke key: " << key_id << std::endl;
                return 1;
            }
            
        } else if (command == "suspend") {
            if (args.size() < 2) {
                std::cerr << "Usage: suspend <key_id>" << std::endl;
                return 1;
            }
            
            std::string key_id = args[1];
            if (manager.suspend_key(key_id)) {
                std::cout << "API key suspended: " << key_id << std::endl;
            } else {
                std::cerr << "Failed to suspend key: " << key_id << std::endl;
                return 1;
            }
            
        } else if (command == "activate") {
            if (args.size() < 2) {
                std::cerr << "Usage: activate <key_id>" << std::endl;
                return 1;
            }
            
            std::string key_id = args[1];
            if (manager.activate_key(key_id)) {
                std::cout << "API key activated: " << key_id << std::endl;
            } else {
                std::cerr << "Failed to activate key: " << key_id << std::endl;
                return 1;
            }
            
        } else if (command == "stats") {
            auto stats = manager.get_statistics();
            
            std::cout << "API Key Statistics:" << std::endl;
            std::cout << "  Total Keys: " << stats.total_keys << std::endl;
            std::cout << "  Active Keys: " << stats.active_keys << std::endl;
            std::cout << "  Suspended Keys: " << stats.suspended_keys << std::endl;
            std::cout << "  Expired Keys: " << stats.expired_keys << std::endl;
            std::cout << "  Revoked Keys: " << stats.revoked_keys << std::endl;
            std::cout << "  Total Requests: " << stats.total_requests << std::endl;
            std::cout << "  Total Bytes: " << stats.total_bytes_transferred << std::endl;
            std::cout << "  Rate Limited Requests: " << stats.rate_limited_requests << std::endl;
            std::cout << "  Last Updated: " << format_timestamp(stats.last_updated) << std::endl;
            
        } else if (command == "cleanup") {
            manager.cleanup_expired_keys();
            std::cout << "Cleanup completed - expired keys removed" << std::endl;
            
        } else {
            std::cerr << "Unknown command: " << command << std::endl;
            print_usage(argv[0]);
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    // Shutdown
    ApiKeyManagerInstance::shutdown();
    AuditManager::shutdown();
    
    return 0;
}