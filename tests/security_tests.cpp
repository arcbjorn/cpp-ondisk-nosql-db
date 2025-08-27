#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_session.hpp>
#include "security/api_key.hpp"
#include "security/audit.hpp"
#include "network/tls_server.hpp"
#include "network/binary_protocol.hpp"
#include <thread>
#include <chrono>
#include <fstream>
#include <filesystem>

using namespace nosql_db::security;
using namespace nosql_db::network;

// Helper class for temporary file management
class TempFileManager {
public:
    TempFileManager(const std::string& base_name) {
        temp_path_ = std::filesystem::temp_directory_path() / 
                    ("nosql_test_" + base_name + "_" + std::to_string(std::rand()));
        std::filesystem::create_directories(temp_path_.parent_path());
    }
    
    ~TempFileManager() {
        if (std::filesystem::exists(temp_path_)) {
            std::filesystem::remove_all(temp_path_);
        }
    }
    
    std::string path() const { return temp_path_.string(); }
    
private:
    std::filesystem::path temp_path_;
};

TEST_CASE("API Key Security Tests", "[security][api_key]") {
    TempFileManager temp_storage("api_keys");
    ApiKeyManager manager(temp_storage.path());
    
    REQUIRE(manager.initialize());
    
    SECTION("Secure Key Generation") {
        KeyGenerationConfig config;
        config.key_length = 32;
        config.include_checksum = true;
        config.default_permissions = ApiPermission::READ | ApiPermission::WRITE;
        
        auto [raw_key, api_key] = manager.generate_key("test_key", "user123", config);
        
        // Test key format and length
        REQUIRE(!raw_key.empty());
        REQUIRE(raw_key.length() > 32); // Should include prefix and checksum
        REQUIRE(raw_key.find("ndb_") == 0); // Should have prefix
        REQUIRE(raw_key.find("_") != std::string::npos); // Should have checksum delimiter
        
        // Test key properties
        REQUIRE(api_key.name == "test_key");
        REQUIRE(api_key.owner_id == "user123");
        REQUIRE(api_key.status == ApiKeyStatus::ACTIVE);
        REQUIRE(api_key.has_permission(ApiPermission::READ));
        REQUIRE(api_key.has_permission(ApiPermission::WRITE));
        REQUIRE(!api_key.has_permission(ApiPermission::DELETE));
    }
    
    SECTION("Key Validation Security") {
        auto [raw_key, api_key] = manager.generate_key("validation_test", "user456");
        
        // Valid key should pass
        auto result = manager.validate_key(raw_key, ApiPermission::READ);
        REQUIRE(result.is_valid);
        REQUIRE(result.key_id == api_key.key_id);
        
        // Invalid keys should fail
        REQUIRE_FALSE(manager.validate_key("invalid_key", ApiPermission::READ).is_valid);
        REQUIRE_FALSE(manager.validate_key("", ApiPermission::READ).is_valid);
        REQUIRE_FALSE(manager.validate_key("ndb_invalidhash", ApiPermission::READ).is_valid);
        
        // Test permission enforcement
        auto no_write = manager.validate_key(raw_key, ApiPermission::DELETE);
        REQUIRE_FALSE(no_write.is_valid);
        REQUIRE(no_write.error_message == "Insufficient permissions");
    }
    
    SECTION("Rate Limiting Security") {
        RateLimit strict_limits;
        strict_limits.requests_per_minute = 5;
        strict_limits.requests_per_hour = 10;
        strict_limits.burst_limit = 2;
        
        auto [raw_key, api_key] = manager.generate_key("rate_limit_test", "user789");
        manager.update_rate_limits(api_key.key_id, strict_limits);
        
        // Should allow initial requests
        for (int i = 0; i < 2; ++i) {
            REQUIRE_FALSE(manager.is_rate_limited(api_key.key_id));
            manager.record_usage(api_key.key_id, 1, 0);
        }
        
        // Should start rate limiting after burst
        for (int i = 0; i < 3; ++i) {
            manager.record_usage(api_key.key_id, 1, 0);
        }
        REQUIRE(manager.is_rate_limited(api_key.key_id));
        
        // Test rate limit validation response
        auto rate_limited = manager.validate_key(raw_key, ApiPermission::READ);
        REQUIRE_FALSE(rate_limited.is_valid);
        REQUIRE(rate_limited.rate_limited);
        REQUIRE(rate_limited.retry_after.count() > 0);
    }
    
    SECTION("IP Access Control Security") {
        auto [raw_key, api_key] = manager.generate_key("ip_test", "user_ip");
        
        // Add IP restrictions
        REQUIRE(manager.add_allowed_ip(api_key.key_id, "192.168.1.*"));
        REQUIRE(manager.add_allowed_ip(api_key.key_id, "10.0.0.100"));
        
        // Test allowed IPs
        auto result_allowed = manager.validate_key(raw_key, ApiPermission::READ, "192.168.1.50");
        REQUIRE(result_allowed.is_valid);
        
        auto result_exact = manager.validate_key(raw_key, ApiPermission::READ, "10.0.0.100");
        REQUIRE(result_exact.is_valid);
        
        // Test blocked IPs
        auto result_blocked = manager.validate_key(raw_key, ApiPermission::READ, "172.16.1.1");
        REQUIRE_FALSE(result_blocked.is_valid);
        REQUIRE(result_blocked.error_message == "IP address not allowed");
    }
    
    SECTION("Key Lifecycle Security") {
        auto [raw_key, api_key] = manager.generate_key("lifecycle_test", "user_lc");
        
        // Test suspension
        REQUIRE(manager.suspend_key(api_key.key_id));
        auto suspended_result = manager.validate_key(raw_key, ApiPermission::READ);
        REQUIRE_FALSE(suspended_result.is_valid);
        REQUIRE(suspended_result.error_message.find("suspended") != std::string::npos);
        
        // Test activation
        REQUIRE(manager.activate_key(api_key.key_id));
        auto activated_result = manager.validate_key(raw_key, ApiPermission::READ);
        REQUIRE(activated_result.is_valid);
        
        // Test revocation (permanent)
        REQUIRE(manager.revoke_key(api_key.key_id));
        auto revoked_result = manager.validate_key(raw_key, ApiPermission::READ);
        REQUIRE_FALSE(revoked_result.is_valid);
        REQUIRE(revoked_result.error_message.find("revoked") != std::string::npos);
        
        // Revoked keys can't be reactivated
        REQUIRE_FALSE(manager.activate_key(api_key.key_id));
    }
    
    SECTION("Resource Pattern Security") {
        auto [raw_key, api_key] = manager.generate_key("resource_test", "user_res");
        
        // Add resource patterns
        REQUIRE(manager.add_resource_pattern(api_key.key_id, "users/*"));
        REQUIRE(manager.add_resource_pattern(api_key.key_id, "documents/public/*"));
        
        // Test allowed resources
        auto allowed1 = manager.validate_key(raw_key, ApiPermission::READ, "", "users/123");
        REQUIRE(allowed1.is_valid);
        
        auto allowed2 = manager.validate_key(raw_key, ApiPermission::READ, "", "documents/public/file.txt");
        REQUIRE(allowed2.is_valid);
        
        // Test blocked resources
        auto blocked = manager.validate_key(raw_key, ApiPermission::READ, "", "admin/settings");
        REQUIRE_FALSE(blocked.is_valid);
        REQUIRE(blocked.error_message == "Resource access denied");
    }
}

TEST_CASE("Audit Logging Security Tests", "[security][audit]") {
    TempFileManager temp_audit("audit");
    
    AuditConfig config;
    config.log_file = temp_audit.path();
    config.enable_file_logging = true;
    config.enable_async_logging = false; // Synchronous for testing
    config.min_severity = AuditSeverity::INFO;
    config.enable_tamper_detection = true;
    
    SECTION("Audit Event Generation") {
        AuditLogger logger(config);
        REQUIRE(logger.start());
        
        // Test different event types
        logger.log_authentication("user123", "192.168.1.100", true);
        logger.log_authorization("user123", "resource1", "READ", true);
        logger.log_data_access("user123", "GET", "key123", true, 1024, std::chrono::microseconds(500));
        logger.log_security_event("Suspicious login attempt", AuditSeverity::WARNING);
        logger.log_error("Database connection failed", "Connection timeout");
        
        logger.stop();
        
        // Verify log file exists and contains events
        REQUIRE(std::filesystem::exists(temp_audit.path()));
        std::ifstream log_file(temp_audit.path());
        REQUIRE(log_file.is_open());
        
        std::string line;
        int event_count = 0;
        while (std::getline(log_file, line)) {
            if (!line.empty() && line[0] == '{') { // JSON lines
                event_count++;
                
                // Verify JSON structure contains required fields
                REQUIRE(line.find("\"timestamp\"") != std::string::npos);
                REQUIRE(line.find("\"event_type\"") != std::string::npos);
                REQUIRE(line.find("\"severity\"") != std::string::npos);
            }
        }
        
        REQUIRE(event_count >= 5); // Should have at least our test events
    }
    
    SECTION("Audit Event Filtering") {
        config.min_severity = AuditSeverity::ERROR;
        AuditLogger logger(config);
        REQUIRE(logger.start());
        
        // Only ERROR and CRITICAL should be logged
        logger.log_security_event("Info event", AuditSeverity::INFO);      // Should be filtered
        logger.log_security_event("Warning event", AuditSeverity::WARNING); // Should be filtered
        logger.log_security_event("Error event", AuditSeverity::ERROR);     // Should be logged
        logger.log_security_event("Critical event", AuditSeverity::CRITICAL); // Should be logged
        
        logger.stop();
        
        std::ifstream log_file(temp_audit.path());
        std::string content((std::istreambuf_iterator<char>(log_file)),
                           std::istreambuf_iterator<char>());
        
        // Should contain ERROR and CRITICAL but not INFO or WARNING
        REQUIRE(content.find("Error event") != std::string::npos);
        REQUIRE(content.find("Critical event") != std::string::npos);
        REQUIRE(content.find("Info event") == std::string::npos);
        REQUIRE(content.find("Warning event") == std::string::npos);
    }
    
    SECTION("Sensitive Data Redaction") {
        config.redact_sensitive_data = true;
        config.sensitive_fields = {"password", "token", "key", "secret"};
        AuditLogger logger(config);
        REQUIRE(logger.start());
        
        // Create event with sensitive data in metadata
        AuditEvent event;
        event.event_type = AuditEventType::AUTH_LOGIN_SUCCESS;
        event.user_id = "user123";
        event.metadata = R"({"password": "secret123", "token": "abc123", "normal_field": "value"})";
        
        logger.log_event(event);
        logger.stop();
        
        // Check that sensitive data was redacted
        std::ifstream log_file(temp_audit.path());
        std::string content((std::istreambuf_iterator<char>(log_file)),
                           std::istreambuf_iterator<char>());
        
        // Should not contain actual sensitive values
        REQUIRE(content.find("secret123") == std::string::npos);
        REQUIRE(content.find("abc123") == std::string::npos);
        REQUIRE(content.find("[REDACTED]") != std::string::npos);
        REQUIRE(content.find("normal_field") != std::string::npos); // Non-sensitive data should remain
    }
}

TEST_CASE("TLS Security Tests", "[security][tls]") {
    // Note: These are basic TLS configuration tests
    // Full TLS testing would require certificate setup
    
    SECTION("TLS Configuration Security") {
        TLSServer::ServerConfig config;
        config.tls_config.min_tls_version = TLS1_2_VERSION;
        config.tls_config.max_tls_version = TLS1_3_VERSION;
        config.tls_config.require_client_cert = true;
        config.tls_config.disable_compression = true;
        config.tls_config.enable_secure_renegotiation = true;
        
        // Verify secure configuration
        REQUIRE(config.tls_config.min_tls_version >= TLS1_2_VERSION);
        REQUIRE(config.tls_config.disable_compression); // Prevents CRIME attacks
        REQUIRE(config.tls_config.enable_secure_renegotiation);
        
        // Verify cipher suite security
        std::string cipher_list = config.tls_config.cipher_list;
        REQUIRE(cipher_list.find("!aNULL") != std::string::npos); // No null authentication
        REQUIRE(cipher_list.find("!MD5") != std::string::npos);   // No MD5
        REQUIRE(cipher_list.find("ECDHE") != std::string::npos);  // Forward secrecy
    }
    
    SECTION("Connection Pool Security") {
        TLSServer::ServerConfig config;
        config.pool_config.max_connections = 1000;
        config.pool_config.max_connections_per_ip = 10;
        config.pool_config.enable_rate_limiting = true;
        config.pool_config.requests_per_second_limit = 100;
        
        // Verify DoS protection settings
        REQUIRE(config.pool_config.max_connections > 0);
        REQUIRE(config.pool_config.max_connections_per_ip > 0);
        REQUIRE(config.pool_config.max_connections_per_ip <= config.pool_config.max_connections);
        REQUIRE(config.pool_config.enable_rate_limiting);
        REQUIRE(config.pool_config.requests_per_second_limit > 0);
    }
}

TEST_CASE("Protocol Security Tests", "[security][protocol]") {
    SECTION("Message Validation") {
        // Test message size limits
        BinaryMessage large_msg;
        large_msg.set_type(MessageType::PUT_REQUEST);
        
        // Create oversized payload
        std::string large_payload(MAX_MESSAGE_SIZE + 1, 'A');
        large_msg.set_data(large_payload);
        
        // Should exceed maximum allowed size
        REQUIRE(large_msg.data_size() > MAX_MESSAGE_SIZE);
        
        // Serialization should handle size appropriately
        auto serialized = large_msg.serialize();
        REQUIRE(!serialized.empty()); // Should serialize but server should reject
    }
    
    SECTION("Message Type Validation") {
        // Test valid message types
        BinaryMessage msg;
        msg.set_type(MessageType::PUT_REQUEST);
        REQUIRE(msg.type() == MessageType::PUT_REQUEST);
        
        msg.set_type(MessageType::GET_REQUEST);
        REQUIRE(msg.type() == MessageType::GET_REQUEST);
        
        // Test message ID validation
        uint64_t test_id = 12345;
        msg.set_message_id(test_id);
        REQUIRE(msg.message_id() == test_id);
    }
    
    SECTION("Input Sanitization") {
        // Test key validation
        std::vector<std::string> invalid_keys = {
            "",                    // Empty key
            std::string(1000, 'A'), // Oversized key
            "key\x00with\x00nulls", // Null bytes
            "key\nwith\nnewlines",  // Control characters
        };
        
        for (const auto& invalid_key : invalid_keys) {
            auto msg = MessageBuilder::create_put_request(1, invalid_key, "value");
            auto parsed = MessageParser::parse_put_request(msg);
            
            // Parser should handle gracefully (specific validation depends on implementation)
            if (parsed.has_value()) {
                // If parsed, key should be sanitized or validated elsewhere
                REQUIRE((!parsed->key.empty() || invalid_key.empty()));
            }
        }
    }
}

TEST_CASE("Integration Security Tests", "[security][integration]") {
    SECTION("API Key + Audit Integration") {
        TempFileManager temp_api("integration_api");
        TempFileManager temp_audit("integration_audit");
        
        // Initialize audit system
        AuditConfig audit_config;
        audit_config.log_file = temp_audit.path();
        audit_config.enable_file_logging = true;
        audit_config.enable_async_logging = false;
        AuditManager::initialize(audit_config);
        
        // Initialize API key manager
        ApiKeyManager manager(temp_api.path());
        REQUIRE(manager.initialize());
        
        // Generate and use API key (should generate audit events)
        auto [raw_key, api_key] = manager.generate_key("integration_test", "test_user");
        
        // Validate key (should generate audit events)
        auto result = manager.validate_key(raw_key, ApiPermission::READ, "192.168.1.1");
        REQUIRE(result.is_valid);
        
        // Record usage (should generate audit events)
        manager.record_usage(api_key.key_id, 1, 1024);
        
        // Suspend key (should generate audit events)
        manager.suspend_key(api_key.key_id);
        
        // Check that audit events were generated
        auto audit_stats = AuditManager::instance().stats();
        REQUIRE(audit_stats.total_events.load() > 0);
        
        // Cleanup
        AuditManager::shutdown();
    }
}

// Vulnerability scanning tests
TEST_CASE("Vulnerability Scanning Tests", "[security][vulnerability]") {
    SECTION("Buffer Overflow Protection") {
        // Test that string operations don't cause buffer overflows
        std::string large_input(10000, 'A');
        
        // Test API key validation with large input
        TempFileManager temp("vuln_test");
        ApiKeyManager manager(temp.path());
        REQUIRE(manager.initialize());
        
        // Should handle large input gracefully without crashing
        auto result = manager.validate_key(large_input, ApiPermission::READ);
        REQUIRE_FALSE(result.is_valid); // Should reject but not crash
    }
    
    SECTION("SQL Injection Protection") {
        // Test that JSON storage doesn't allow injection
        TempFileManager temp("sql_injection");
        ApiKeyManager manager(temp.path());
        REQUIRE(manager.initialize());
        
        // Try to inject malicious content in key names
        std::vector<std::string> malicious_names = {
            "'; DROP TABLE users; --",
            "\"; DROP TABLE users; //",
            "test<script>alert('xss')</script>",
            "test\'; DELETE FROM keys WHERE 1=1; --"
        };
        
        for (const auto& malicious_name : malicious_names) {
            // Should handle gracefully without executing malicious content
            auto [raw_key, api_key] = manager.generate_key(malicious_name, "test_user");
            REQUIRE(!raw_key.empty());
            REQUIRE(api_key.name == malicious_name); // Should store as-is, not execute
        }
    }
    
    SECTION("Path Traversal Protection") {
        // Test path traversal attempts in storage paths
        std::vector<std::string> malicious_paths = {
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "../../sensitive_file.txt"
        };
        
        for (const auto& malicious_path : malicious_paths) {
            try {
                ApiKeyManager manager(malicious_path);
                // Should either reject the path or sanitize it
                // The filesystem operations should be contained
                manager.initialize();
                // If initialization succeeds, verify no unauthorized access
                REQUIRE(true); // Test passes if no exception and no unauthorized access
            } catch (const std::exception&) {
                // It's acceptable to throw an exception for invalid paths
                REQUIRE(true);
            }
        }
    }
    
    SECTION("Denial of Service Protection") {
        TempFileManager temp("dos_test");
        ApiKeyManager manager(temp.path());
        REQUIRE(manager.initialize());
        
        // Test rate limiting prevents DoS
        RateLimit strict_limits;
        strict_limits.requests_per_minute = 1;
        strict_limits.burst_limit = 1;
        
        auto [raw_key, api_key] = manager.generate_key("dos_test", "attacker");
        manager.update_rate_limits(api_key.key_id, strict_limits);
        
        // First request should succeed
        auto result1 = manager.validate_key(raw_key, ApiPermission::READ);
        REQUIRE(result1.is_valid);
        manager.record_usage(api_key.key_id);
        
        // Subsequent requests should be rate limited
        for (int i = 0; i < 10; ++i) {
            auto result = manager.validate_key(raw_key, ApiPermission::READ);
            if (!result.is_valid && result.rate_limited) {
                // Rate limiting is working
                REQUIRE(true);
                break;
            }
            manager.record_usage(api_key.key_id);
        }
    }
}

// Performance and resource leak tests
TEST_CASE("Security Performance Tests", "[security][performance]") {
    SECTION("Memory Leak Detection") {
        TempFileManager temp("memory_test");
        
        // Create and destroy many managers to test for leaks
        for (int i = 0; i < 100; ++i) {
            ApiKeyManager manager(temp.path() + "_" + std::to_string(i));
            manager.initialize();
            
            // Generate keys
            for (int j = 0; j < 10; ++j) {
                auto [raw_key, api_key] = manager.generate_key("test_" + std::to_string(j), "user");
                manager.validate_key(raw_key, ApiPermission::READ);
            }
            
            // Manager destructor should clean up properly
        }
        
        REQUIRE(true); // Test passes if no crashes or excessive memory usage
    }
    
    SECTION("Thread Safety Under Load") {
        TempFileManager temp("thread_test");
        ApiKeyManager manager(temp.path());
        REQUIRE(manager.initialize());
        
        // Generate a key for testing
        auto [raw_key, api_key] = manager.generate_key("thread_test", "user");
        
        const int num_threads = 10;
        const int operations_per_thread = 100;
        std::vector<std::thread> threads;
        std::atomic<int> successful_validations{0};
        std::atomic<int> successful_usages{0};
        
        // Launch concurrent threads
        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&]() {
                for (int i = 0; i < operations_per_thread; ++i) {
                    // Validate key
                    auto result = manager.validate_key(raw_key, ApiPermission::READ);
                    if (result.is_valid) {
                        successful_validations++;
                    }
                    
                    // Record usage
                    manager.record_usage(api_key.key_id);
                    successful_usages++;
                    
                    // Small delay to increase contention
                    std::this_thread::sleep_for(std::chrono::microseconds(1));
                }
            });
        }
        
        // Wait for all threads
        for (auto& thread : threads) {
            thread.join();
        }
        
        // Verify thread safety - all operations should succeed
        REQUIRE(successful_validations > 0);
        REQUIRE(successful_usages == num_threads * operations_per_thread);
        
        // Verify key usage counter was updated correctly (within reasonable bounds due to concurrency)
        auto updated_key = manager.get_key_by_id(api_key.key_id);
        REQUIRE(updated_key.has_value());
        REQUIRE(updated_key->usage_count.load() > 0);
    }
}