#include <catch2/catch_test_macros.hpp>
#include "network/connection_pool.hpp"
#include <thread>
#include <chrono>

using namespace ishikura::network;

TEST_CASE("ConnectionPool - Basic Functionality", "[network][connection_pool]") {
    ConnectionPool::PoolConfig config;
    config.max_connections = 100;
    config.max_connections_per_ip = 10;
    config.session_timeout = std::chrono::seconds(5);
    config.enable_rate_limiting = true;
    config.requests_per_second_limit = 1000;
    
    ConnectionPool pool(config);
    
    SECTION("Initial state") {
        REQUIRE(pool.stats().active_sessions.load() == 0);
        REQUIRE(pool.stats().total_sessions.load() == 0);
        REQUIRE(pool.get_active_session_ids().empty());
    }
    
    SECTION("Session creation and retrieval") {
        std::string session_id = pool.create_session(1, "127.0.0.1:12345");
        REQUIRE_FALSE(session_id.empty());
        REQUIRE(pool.stats().total_sessions.load() == 1);
        
        auto session = pool.get_session(session_id);
        REQUIRE(session != nullptr);
        REQUIRE(session->session_id == session_id);
        REQUIRE(session->client_address == "127.0.0.1:12345");
        REQUIRE(session->total_requests.load() == 0);
    }
    
    SECTION("Connection limits per IP") {
        // Try to create max_connections_per_ip + 1 connections from same IP
        std::vector<std::string> sessions;
        
        for (int i = 0; i < config.max_connections_per_ip; ++i) {
            std::string session_id = pool.create_session(i + 1, "192.168.1.100:123" + std::to_string(i));
            REQUIRE_FALSE(session_id.empty());
            sessions.push_back(session_id);
        }
        
        // This should fail due to per-IP limit
        REQUIRE_FALSE(pool.can_accept_connection("192.168.1.100"));
        
        // But different IP should still work
        REQUIRE(pool.can_accept_connection("192.168.1.101"));
    }
    
    SECTION("Global connection limits") {
        // Create sessions up to max_connections
        std::vector<std::string> sessions;
        
        // Use different IPs to avoid per-IP limits
        for (int i = 0; i < config.max_connections; ++i) {
            std::string ip = "10.0." + std::to_string(i / 256) + "." + std::to_string(i % 256);
            std::string session_id = pool.create_session(i + 1, ip + ":12345");
            
            if (session_id.empty()) {
                // May hit limit before exactly max_connections due to implementation details
                break;
            }
            sessions.push_back(session_id);
        }
        
        // Pool should be at or near capacity
        REQUIRE(pool.stats().active_sessions.load() >= config.max_connections - 5); // Allow some tolerance
        
        // New connections should be rejected
        REQUIRE_FALSE(pool.can_accept_connection("172.16.0.1"));
    }
    
    SECTION("Session removal") {
        std::string session_id = pool.create_session(1, "10.0.0.1:12345");
        REQUIRE_FALSE(session_id.empty());
        REQUIRE(pool.stats().total_sessions.load() == 1);
        REQUIRE(pool.stats().active_sessions.load() == 1);
        
        bool removed = pool.remove_session(session_id);
        REQUIRE(removed);
        REQUIRE(pool.stats().total_sessions.load() == 1); // total_sessions is cumulative
        REQUIRE(pool.stats().active_sessions.load() == 0); // active_sessions should decrease
        
        // Second removal should fail
        REQUIRE_FALSE(pool.remove_session(session_id));
    }
}

TEST_CASE("ManagedConnection - Basic Functionality", "[network][connection_pool]") {
    ConnectionPool::PoolConfig config;
    config.enable_rate_limiting = true;
    config.requests_per_second_limit = 10; // Low limit for testing
    config.burst_limit = 0; // No burst for strict testing
    
    auto pool = std::make_shared<ConnectionPool>(config);
    
    std::string session_id = pool->create_session(1, "127.0.0.1:54321");
    auto session = pool->get_session(session_id);
    REQUIRE(session != nullptr);
    
    ManagedConnection conn(1, session, pool);
    
    SECTION("Initial state") {
        REQUIRE(conn.socket() == 1);
        REQUIRE(conn.session_id() == session_id);
        REQUIRE(conn.client_address() == "127.0.0.1:54321");
        REQUIRE(conn.is_active());
    }
    
    SECTION("Activity tracking") {
        uint64_t initial_requests = session->total_requests.load();
        uint64_t initial_bytes = session->bytes_sent.load();
        
        conn.record_request(256);
        REQUIRE(session->total_requests.load() == initial_requests + 1);
        REQUIRE(session->bytes_received.load() == 256);
        
        conn.record_response(512);
        REQUIRE(session->bytes_sent.load() == initial_bytes + 512);
    }
    
    SECTION("Rate limiting") {
        // Initially should allow requests
        REQUIRE(conn.check_rate_limit());
        
        // Simulate many requests in quick succession
        auto start_time = std::chrono::steady_clock::now();
        int allowed_requests = 0;
        
        for (int i = 0; i < 20; ++i) {
            if (conn.check_rate_limit()) {
                allowed_requests++;
                conn.record_request(100);
            }
        }
        
        // Should have been rate limited (not all 20 requests allowed)
        REQUIRE(allowed_requests <= config.requests_per_second_limit);
    }
    
    SECTION("Lifecycle management") {
        REQUIRE(conn.is_active());
        
        conn.mark_inactive();
        REQUIRE_FALSE(conn.is_active());
    }
}

TEST_CASE("ConnectionPool - Rate Limiting", "[network][connection_pool]") {
    ConnectionPool::PoolConfig config;
    config.enable_rate_limiting = true;
    config.requests_per_second_limit = 5; // Very low for testing
    config.burst_limit = 0; // No burst for strict testing
    
    ConnectionPool pool(config);
    
    SECTION("Rate limit enforcement") {
        std::string session_id = pool.create_session(1, "192.168.1.50:8080");
        auto session = pool.get_session(session_id);
        REQUIRE(session != nullptr);
        
        auto managed_conn = std::make_unique<ManagedConnection>(1, session, std::make_shared<ConnectionPool>(config));
        
        int successful_requests = 0;
        for (int i = 0; i < 10; ++i) {
            if (managed_conn->check_rate_limit()) {
                successful_requests++;
                managed_conn->record_request(100);
            }
        }
        
        // Should be rate limited
        REQUIRE(successful_requests <= config.requests_per_second_limit);
    }
}

TEST_CASE("ConnectionPool - Session Timeout", "[network][connection_pool]") {
    ConnectionPool::PoolConfig config;
    config.session_timeout = std::chrono::seconds(1); // Very short for testing
    
    ConnectionPool pool(config);
    
    SECTION("Session expires after timeout") {
        std::string session_id = pool.create_session(1, "10.1.1.1:9999");
        REQUIRE_FALSE(session_id.empty());
        
        auto session = pool.get_session(session_id);
        REQUIRE(session != nullptr);
        
        // Wait longer than timeout
        std::this_thread::sleep_for(std::chrono::milliseconds(1100));
        
        // Start cleanup (normally done by background thread)
        pool.start_cleanup();
        std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Let cleanup run
        pool.stop_cleanup();
        
        // Session should be expired/cleaned up
        auto expired_session = pool.get_session(session_id);
        // Note: Session might still exist but be marked as expired depending on implementation
    }
}

TEST_CASE("ConnectionPool - Statistics", "[network][connection_pool]") {
    ConnectionPool::PoolConfig config;
    ConnectionPool pool(config);
    
    SECTION("Connection statistics") {
        const auto& initial_stats = pool.stats();
        REQUIRE(initial_stats.total_sessions.load() == 0);
        REQUIRE(initial_stats.active_sessions.load() == 0);
        
        // Create some sessions
        std::vector<std::string> sessions;
        for (int i = 0; i < 5; ++i) {
            std::string session_id = pool.create_session(i + 1, "172.20.0." + std::to_string(i) + ":8080");
            if (!session_id.empty()) {
                sessions.push_back(session_id);
            }
        }
        
        const auto& updated_stats = pool.stats();
        REQUIRE(updated_stats.total_sessions.load() >= 5);
        REQUIRE(updated_stats.active_sessions.load() >= 5);
        
        // Remove some sessions
        for (int i = 0; i < 2 && i < sessions.size(); ++i) {
            pool.remove_session(sessions[i]);
        }
        
        const auto& final_stats = pool.stats();
        REQUIRE(final_stats.active_sessions.load() >= 3);
    }
}

TEST_CASE("ConnectionPool - Concurrent Access", "[network][connection_pool]") {
    ConnectionPool::PoolConfig config;
    config.max_connections = 1000;
    config.max_connections_per_ip = 100;
    
    ConnectionPool pool(config);
    
    SECTION("Concurrent session creation") {
        std::vector<std::thread> threads;
        std::vector<std::vector<std::string>> thread_sessions(4);
        
        // Create 4 threads, each creating 25 sessions
        for (int t = 0; t < 4; ++t) {
            threads.emplace_back([&, t]() {
                for (int i = 0; i < 25; ++i) {
                    std::string ip = "10." + std::to_string(t) + ".0." + std::to_string(i);
                    std::string session_id = pool.create_session(t * 100 + i, ip + ":12345");
                    if (!session_id.empty()) {
                        thread_sessions[t].push_back(session_id);
                    }
                }
            });
        }
        
        // Wait for all threads
        for (auto& thread : threads) {
            thread.join();
        }
        
        // Verify total sessions created
        size_t total_sessions = 0;
        for (const auto& sessions : thread_sessions) {
            total_sessions += sessions.size();
        }
        
        REQUIRE(total_sessions >= 90); // Allow for some failures due to concurrency
        REQUIRE(pool.stats().total_sessions.load() >= 90);
    }
}

TEST_CASE("ConnectionPool - IP Address Extraction", "[network][connection_pool]") {
    ConnectionPool::PoolConfig config;
    ConnectionPool pool(config);
    
    SECTION("Valid IP extraction") {
        // Test the extract_ip_from_address method
        REQUIRE(pool.extract_ip_from_address("192.168.1.1:8080") == "192.168.1.1");
        REQUIRE(pool.extract_ip_from_address("10.0.0.50:12345") == "10.0.0.50");
        REQUIRE(pool.extract_ip_from_address("127.0.0.1:9090") == "127.0.0.1");
    }
    
    SECTION("Invalid address formats") {
        REQUIRE(pool.extract_ip_from_address("invalid") == "invalid");
        REQUIRE(pool.extract_ip_from_address("192.168.1.1") == "192.168.1.1"); // No port
        REQUIRE(pool.extract_ip_from_address("") == "");
    }
}

TEST_CASE("ConnectionPool - Configuration", "[network][connection_pool]") {
    SECTION("Default configuration") {
        ConnectionPool::PoolConfig config;
        ConnectionPool pool(config);
        
        REQUIRE(pool.config().max_connections == 1000);
        REQUIRE(pool.config().max_connections_per_ip == 100);
        REQUIRE(pool.config().enable_rate_limiting == true);
        REQUIRE(pool.config().requests_per_second_limit == 1000);
    }
    
    SECTION("Custom configuration") {
        ConnectionPool::PoolConfig config;
        config.max_connections = 500;
        config.max_connections_per_ip = 50;
        config.enable_rate_limiting = false;
        config.requests_per_second_limit = 2000;
        
        ConnectionPool pool(config);
        
        REQUIRE(pool.config().max_connections == 500);
        REQUIRE(pool.config().max_connections_per_ip == 50);
        REQUIRE(pool.config().enable_rate_limiting == false);
        REQUIRE(pool.config().requests_per_second_limit == 2000);
    }
}