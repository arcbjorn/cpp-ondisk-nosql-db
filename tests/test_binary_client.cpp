#include <catch2/catch_test_macros.hpp>
#include "network/binary_server.hpp"
#include "storage/storage_engine.hpp"
#include <thread>
#include <chrono>
#include <filesystem>

using namespace ishikura::network;
using namespace ishikura::storage;

class TestServer {
public:
    TestServer(uint16_t port = 0) : port_(port == 0 ? find_available_port() : port) {
        // Create temporary storage
        storage_dir_ = std::filesystem::temp_directory_path() / ("test_db_" + std::to_string(port_));
        std::filesystem::create_directories(storage_dir_);
        
        storage_ = std::make_shared<StorageEngine>(storage_dir_, StorageEngine::EngineType::SimpleLog);
        
        BinaryServer::ServerConfig config;
        config.host = "127.0.0.1";
        config.port = port_;
        config.worker_threads = 2;
        config.pool_config.max_connections = 100;
        
        server_ = std::make_unique<BinaryServer>(storage_, config);
    }
    
    ~TestServer() {
        stop();
        // Cleanup temporary directory
        if (std::filesystem::exists(storage_dir_)) {
            std::filesystem::remove_all(storage_dir_);
        }
    }
    
    bool start() {
        if (server_->start()) {
            // Give server time to start
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            return true;
        }
        return false;
    }
    
    void stop() {
        if (server_) {
            server_->stop();
        }
    }
    
    uint16_t port() const { return port_; }
    
private:
    uint16_t find_available_port() {
        // Simple method to find an available port for testing
        // In a real implementation, you might use system calls to find a free port
        static uint16_t test_port = 19090;
        return test_port++;
    }
    
    uint16_t port_;
    std::filesystem::path storage_dir_;
    std::shared_ptr<StorageEngine> storage_;
    std::unique_ptr<BinaryServer> server_;
};

TEST_CASE("BinaryClient - Connection Management", "[network][client]") {
    TestServer server;
    REQUIRE(server.start());
    
    BinaryClient::ClientConfig config;
    config.host = "127.0.0.1";
    config.port = server.port();
    config.connection_timeout = std::chrono::seconds(5);
    
    BinaryClient client(config);
    
    SECTION("Basic connection") {
        REQUIRE(client.connect());
        REQUIRE(client.is_connected());
        
        client.disconnect();
        REQUIRE_FALSE(client.is_connected());
    }
    
    SECTION("Connection to invalid host") {
        BinaryClient::ClientConfig bad_config;
        bad_config.host = "127.0.0.1";
        bad_config.port = 9999; // Hopefully unused port
        bad_config.connection_timeout = std::chrono::seconds(1);
        
        BinaryClient bad_client(bad_config);
        REQUIRE_FALSE(bad_client.connect());
        REQUIRE_FALSE(bad_client.is_connected());
    }
    
    SECTION("Reconnection") {
        REQUIRE(client.connect());
        REQUIRE(client.is_connected());
        
        client.disconnect();
        REQUIRE_FALSE(client.is_connected());
        
        REQUIRE(client.connect());
        REQUIRE(client.is_connected());
    }
}

TEST_CASE("BinaryClient - Basic Operations", "[network][client]") {
    TestServer server;
    REQUIRE(server.start());
    
    BinaryClient::ClientConfig config;
    config.host = "127.0.0.1";
    config.port = server.port();
    
    BinaryClient client(config);
    REQUIRE(client.connect());
    
    SECTION("PUT operation") {
        REQUIRE(client.put("test_key", "test_value"));
        REQUIRE(client.put("key2", "value2"));
    }
    
    SECTION("GET operation") {
        // PUT first
        REQUIRE(client.put("get_test", "get_value"));
        
        auto result = client.get("get_test");
        REQUIRE(result.has_value());
        REQUIRE(*result == "get_value");
        
        // Non-existent key
        auto missing = client.get("nonexistent");
        REQUIRE_FALSE(missing.has_value());
    }
    
    SECTION("DELETE operation") {
        // PUT first
        REQUIRE(client.put("delete_test", "delete_value"));
        
        // Verify it exists
        auto result = client.get("delete_test");
        REQUIRE(result.has_value());
        
        // Delete it
        REQUIRE(client.delete_key("delete_test"));
        
        // Verify it's gone
        auto after_delete = client.get("delete_test");
        REQUIRE_FALSE(after_delete.has_value());
        
        // Delete non-existent key (should still return true in most implementations)
        // This behavior may vary based on implementation
        client.delete_key("nonexistent_key");
    }
    
    SECTION("PING operation") {
        REQUIRE(client.ping());
    }
}

TEST_CASE("BinaryClient - Query Operations", "[network][client]") {
    TestServer server;
    REQUIRE(server.start());
    
    BinaryClient client;
    BinaryClient::ClientConfig config;
    config.host = "127.0.0.1";
    config.port = server.port();
    
    BinaryClient configured_client(config);
    REQUIRE(configured_client.connect());
    
    SECTION("SCAN query") {
        // Setup test data for this section
        REQUIRE(configured_client.put("user:alice", "Alice Smith"));
        REQUIRE(configured_client.put("user:bob", "Bob Jones"));
        REQUIRE(configured_client.put("user:charlie", "Charlie Brown"));
        REQUIRE(configured_client.put("post:1", "Hello World"));
        REQUIRE(configured_client.put("post:2", "Binary Protocol Test"));
        REQUIRE(configured_client.put("config:theme", "dark"));
        
        auto results = configured_client.query("SCAN");
        REQUIRE(results.size() >= 6); // At least the test data we inserted
        
        auto limited_results = configured_client.query("SCAN LIMIT 3");
        REQUIRE(limited_results.size() <= 3);
    }
    
    SECTION("PREFIX query") {
        // Setup test data for this section
        REQUIRE(configured_client.put("user:alice", "Alice Smith"));
        REQUIRE(configured_client.put("user:bob", "Bob Jones"));
        REQUIRE(configured_client.put("user:charlie", "Charlie Brown"));
        REQUIRE(configured_client.put("post:1", "Hello World"));
        REQUIRE(configured_client.put("post:2", "Binary Protocol Test"));
        REQUIRE(configured_client.put("config:theme", "dark"));
        
        auto user_results = configured_client.query("PREFIX user:");
        REQUIRE(user_results.size() == 3);
        
        auto post_results = configured_client.query("PREFIX post:");
        REQUIRE(post_results.size() == 2);
        
        auto config_results = configured_client.query("PREFIX config:");
        REQUIRE(config_results.size() == 1);
    }
    
    SECTION("RANGE query") {
        // Setup test data for this section
        REQUIRE(configured_client.put("user:alice", "Alice Smith"));
        REQUIRE(configured_client.put("user:bob", "Bob Jones"));
        REQUIRE(configured_client.put("user:charlie", "Charlie Brown"));
        REQUIRE(configured_client.put("post:1", "Hello World"));
        REQUIRE(configured_client.put("post:2", "Binary Protocol Test"));
        REQUIRE(configured_client.put("config:theme", "dark"));
        
        auto range_results = configured_client.query("RANGE post:1 post:2");
        REQUIRE(range_results.size() >= 2);
    }
    
    SECTION("COUNT query") {
        // Setup test data for this section
        REQUIRE(configured_client.put("user:alice", "Alice Smith"));
        REQUIRE(configured_client.put("user:bob", "Bob Jones"));
        REQUIRE(configured_client.put("user:charlie", "Charlie Brown"));
        REQUIRE(configured_client.put("post:1", "Hello World"));
        REQUIRE(configured_client.put("post:2", "Binary Protocol Test"));
        REQUIRE(configured_client.put("config:theme", "dark"));
        
        auto count_results = configured_client.query("COUNT");
        REQUIRE(count_results.size() == 1);
        // The count should be in the value of the result
        REQUIRE_FALSE(count_results[0].second.empty());
    }
}

TEST_CASE("BinaryClient - Batch Operations", "[network][client]") {
    TestServer server;
    REQUIRE(server.start());
    
    BinaryClient::ClientConfig config;
    config.host = "127.0.0.1";
    config.port = server.port();
    
    BinaryClient client(config);
    REQUIRE(client.connect());
    
    SECTION("Mixed batch operations") {
        std::vector<BinaryClient::BatchOperation> operations = {
            {BinaryClient::BatchOperation::PUT, "batch:key1", "value1"},
            {BinaryClient::BatchOperation::PUT, "batch:key2", "value2"},
            {BinaryClient::BatchOperation::GET, "batch:key1", ""},
            {BinaryClient::BatchOperation::DELETE, "batch:key1", ""},
            {BinaryClient::BatchOperation::GET, "batch:key1", ""} // Should not find it
        };
        
        auto results = client.batch_execute(operations);
        REQUIRE(results.size() == operations.size());
        
        // First two PUTs should succeed
        REQUIRE(results[0] == StatusCode::SUCCESS);
        REQUIRE(results[1] == StatusCode::SUCCESS);
        
        // GET should succeed (key exists)
        REQUIRE(results[2] == StatusCode::SUCCESS);
        
        // DELETE should succeed
        REQUIRE(results[3] == StatusCode::SUCCESS);
        
        // Second GET should fail (key deleted)
        REQUIRE(results[4] == StatusCode::KEY_NOT_FOUND);
    }
    
    SECTION("Large batch operation") {
        std::vector<BinaryClient::BatchOperation> large_batch;
        
        // Create 100 PUT operations
        for (int i = 0; i < 100; ++i) {
            std::string key = "large_batch:" + std::to_string(i);
            std::string value = "value_" + std::to_string(i);
            large_batch.emplace_back(BinaryClient::BatchOperation::PUT, key, value);
        }
        
        auto results = client.batch_execute(large_batch);
        REQUIRE(results.size() == 100);
        
        // All operations should succeed
        for (const auto& result : results) {
            REQUIRE(result == StatusCode::SUCCESS);
        }
    }
}

TEST_CASE("BinaryClient - Error Handling", "[network][client]") {
    TestServer server;
    REQUIRE(server.start());
    
    BinaryClient::ClientConfig config;
    config.host = "127.0.0.1";
    config.port = server.port();
    config.request_timeout = std::chrono::seconds(2);
    config.max_retries = 1; // Reduced for faster testing
    
    BinaryClient client(config);
    REQUIRE(client.connect());
    
    SECTION("Operations on disconnected client") {
        client.disconnect();
        REQUIRE_FALSE(client.is_connected());
        
        // These should all fail gracefully
        REQUIRE_FALSE(client.put("test", "value"));
        REQUIRE_FALSE(client.get("test").has_value());
        REQUIRE_FALSE(client.delete_key("test"));
        REQUIRE(client.query("SCAN").empty());
        REQUIRE_FALSE(client.ping());
    }
    
    SECTION("Operations after server shutdown") {
        REQUIRE(client.is_connected());
        
        // Stop the server
        server.stop();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Operations should fail
        REQUIRE_FALSE(client.put("test", "value"));
        REQUIRE_FALSE(client.ping());
    }
}

TEST_CASE("BinaryClient - Configuration", "[network][client]") {
    SECTION("Default configuration") {
        BinaryClient client;
        
        const auto& config = client.config();
        REQUIRE(config.host == "localhost");
        REQUIRE(config.port == 9090);
        REQUIRE(config.enable_keepalive == true);
        REQUIRE(config.max_retries == 3);
    }
    
    SECTION("Custom configuration") {
        BinaryClient::ClientConfig custom_config;
        custom_config.host = "192.168.1.100";
        custom_config.port = 8080;
        custom_config.connection_timeout = std::chrono::seconds(30);
        custom_config.request_timeout = std::chrono::seconds(60);
        custom_config.enable_keepalive = false;
        custom_config.max_retries = 5;
        
        BinaryClient client(custom_config);
        
        const auto& config = client.config();
        REQUIRE(config.host == "192.168.1.100");
        REQUIRE(config.port == 8080);
        REQUIRE(config.connection_timeout == std::chrono::seconds(30));
        REQUIRE(config.request_timeout == std::chrono::seconds(60));
        REQUIRE(config.enable_keepalive == false);
        REQUIRE(config.max_retries == 5);
    }
}

TEST_CASE("BinaryClient - Concurrent Access", "[network][client]") {
    TestServer server;
    REQUIRE(server.start());
    
    SECTION("Multiple clients") {
        const int num_clients = 5;
        std::vector<std::unique_ptr<BinaryClient>> clients;
        std::vector<std::thread> threads;
        
        // Create clients
        for (int i = 0; i < num_clients; ++i) {
            BinaryClient::ClientConfig config;
            config.host = "127.0.0.1";
            config.port = server.port();
            
            auto client = std::make_unique<BinaryClient>(config);
            REQUIRE(client->connect());
            clients.push_back(std::move(client));
        }
        
        // Each client performs operations
        for (int i = 0; i < num_clients; ++i) {
            threads.emplace_back([&clients, i]() {
                auto& client = clients[i];
                
                // Each client puts unique data
                for (int j = 0; j < 10; ++j) {
                    std::string key = "client" + std::to_string(i) + "_key" + std::to_string(j);
                    std::string value = "client" + std::to_string(i) + "_value" + std::to_string(j);
                    
                    REQUIRE(client->put(key, value));
                }
                
                // Verify data
                for (int j = 0; j < 10; ++j) {
                    std::string key = "client" + std::to_string(i) + "_key" + std::to_string(j);
                    std::string expected_value = "client" + std::to_string(i) + "_value" + std::to_string(j);
                    
                    auto result = client->get(key);
                    REQUIRE(result.has_value());
                    REQUIRE(*result == expected_value);
                }
                
                // Test other operations
                REQUIRE(client->ping());
            });
        }
        
        // Wait for all threads
        for (auto& thread : threads) {
            thread.join();
        }
        
        // Verify all data is accessible from any client
        auto& test_client = clients[0];
        for (int i = 0; i < num_clients; ++i) {
            for (int j = 0; j < 10; ++j) {
                std::string key = "client" + std::to_string(i) + "_key" + std::to_string(j);
                auto result = test_client->get(key);
                REQUIRE(result.has_value());
            }
        }
    }
}