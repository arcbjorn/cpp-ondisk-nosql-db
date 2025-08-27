#include <catch2/catch_test_macros.hpp>
#include "api/kv_controller.hpp"
#include "storage/storage_engine.hpp"
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <thread>
#include <filesystem>
#include <chrono>

using json = nlohmann::json;
using namespace ishikura;

namespace {
    class TestHttpServer {
    public:
        TestHttpServer() : port_(0) {
            // Create temporary storage directory
            temp_dir_ = std::filesystem::temp_directory_path() / "test_api_storage";
            std::filesystem::remove_all(temp_dir_);
            
            storage_ = std::make_shared<storage::StorageEngine>(temp_dir_, storage::StorageEngine::EngineType::LSMTree);
            controller_ = std::make_unique<api::KvController>(storage_);
            
            // Find available port
            server_.set_pre_routing_handler([](const httplib::Request&, httplib::Response&) {
                return httplib::Server::HandlerResponse::Unhandled;
            });
            
            controller_->register_routes(server_);
        }
        
        ~TestHttpServer() {
            stop();
            std::filesystem::remove_all(temp_dir_);
        }
        
        bool start() {
            // Start server in background thread
            server_thread_ = std::thread([this]() {
                server_.listen("127.0.0.1", 0); // Use any available port
            });
            
            // Wait for server to start and get the actual port
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            // Try to connect to determine the actual port
            for (int test_port = 8080; test_port < 8200; ++test_port) {
                httplib::Client test_client("127.0.0.1", test_port);
                test_client.set_connection_timeout(1, 0);
                
                auto res = test_client.Get("/api/v1/health");
                if (res && res->status == 200) {
                    port_ = test_port;
                    break;
                }
            }
            
            if (port_ == 0) {
                // Fallback: start on specific port
                stop();
                port_ = 18080;
                server_thread_ = std::thread([this]() {
                    server_.listen("127.0.0.1", port_);
                });
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            
            return port_ > 0;
        }
        
        void stop() {
            server_.stop();
            if (server_thread_.joinable()) {
                server_thread_.join();
            }
        }
        
        int port() const { return port_; }
        
        httplib::Client create_client() {
            return httplib::Client("127.0.0.1", port_);
        }
        
        
    private:
        httplib::Server server_;
        std::thread server_thread_;
        std::filesystem::path temp_dir_;
        std::shared_ptr<storage::StorageEngine> storage_;
        std::unique_ptr<api::KvController> controller_;
        int port_;
    };
}

TEST_CASE("HTTP API Integration Tests", "[api]") {
    TestHttpServer test_server;
    REQUIRE(test_server.start());
    
    auto client = test_server.create_client();
    client.set_connection_timeout(5, 0);
    client.set_read_timeout(5, 0);
    
    SECTION("Health check endpoint") {
        auto res = client.Get("/api/v1/health");
        
        REQUIRE(res);
        REQUIRE(res->status == 200);
        REQUIRE(res->get_header_value("Content-Type") == "application/json");
        
        auto response_json = json::parse(res->body);
        REQUIRE(response_json["status"] == "healthy");
        REQUIRE(response_json["service"] == "nosql-db");
        REQUIRE(response_json.contains("version"));
    }
    
    SECTION("PUT and GET key-value operations") {
        // Test JSON data
        json test_data = {
            {"name", "Alice"},
            {"age", 30},
            {"active", true}
        };
        
        // PUT operation
        auto put_res = client.Put("/api/v1/kv/user:alice", 
                                 test_data.dump(), 
                                 "application/json");
        
        REQUIRE(put_res);
        REQUIRE(put_res->status == 201);
        
        auto put_response = json::parse(put_res->body);
        REQUIRE(put_response["key"] == "user:alice");
        REQUIRE(put_response["status"] == "stored");
        REQUIRE(put_response.contains("size"));
        
        // GET operation
        auto get_res = client.Get("/api/v1/kv/user:alice");
        
        REQUIRE(get_res);
        REQUIRE(get_res->status == 200);
        REQUIRE(get_res->get_header_value("Content-Type") == "application/json");
        
        auto retrieved_data = json::parse(get_res->body);
        REQUIRE(retrieved_data == test_data);
    }
    
    SECTION("GET non-existent key") {
        auto res = client.Get("/api/v1/kv/nonexistent");
        
        REQUIRE(res);
        REQUIRE(res->status == 404);
        
        auto error_response = json::parse(res->body);
        REQUIRE(error_response["error"] == "Key not found");
        REQUIRE(error_response["status"] == 404);
    }
    
    SECTION("PUT with plain text value") {
        std::string text_value = "This is a plain text value";
        
        auto put_res = client.Put("/api/v1/kv/text:example", 
                                 text_value, 
                                 "text/plain");
        
        REQUIRE(put_res);
        REQUIRE(put_res->status == 201);
        
        auto get_res = client.Get("/api/v1/kv/text:example");
        
        REQUIRE(get_res);
        REQUIRE(get_res->status == 200);
        REQUIRE(get_res->get_header_value("Content-Type") == "text/plain");
        REQUIRE(get_res->body == text_value);
    }
    
    SECTION("Key validation") {
        // Empty key
        auto res1 = client.Put("/api/v1/kv/", "{}", "application/json");
        REQUIRE(res1);
        REQUIRE(res1->status == 404); // Will be handled by routing as not matching pattern
        
        // Very long key
        std::string long_key(300, 'x');
        auto res2 = client.Put("/api/v1/kv/" + long_key, "{}", "application/json");
        REQUIRE(res2);
        REQUIRE(res2->status == 400);
        
        auto error_response = json::parse(res2->body);
        REQUIRE(error_response["error"] == "Invalid key format");
    }
    
    SECTION("Empty body validation") {
        auto res = client.Put("/api/v1/kv/empty:test", "", "application/json");
        
        REQUIRE(res);
        REQUIRE(res->status == 400);
        
        auto error_response = json::parse(res->body);
        REQUIRE(error_response["error"] == "Request body cannot be empty");
    }
    
    SECTION("Invalid JSON validation") {
        auto res = client.Put("/api/v1/kv/invalid:json", 
                             "invalid json {", 
                             "application/json");
        
        REQUIRE(res);
        REQUIRE(res->status == 400);
        
        auto error_response = json::parse(res->body);
        REQUIRE(error_response["error"].get<std::string>().find("Invalid JSON format") == 0);
    }
    
    SECTION("DELETE operation") {
        // First store a value
        json test_data = {{"value", "to-be-deleted"}};
        auto put_res = client.Put("/api/v1/kv/delete:test", 
                                 test_data.dump(), 
                                 "application/json");
        REQUIRE(put_res);
        REQUIRE(put_res->status == 201);
        
        // Verify it exists
        auto get_res1 = client.Get("/api/v1/kv/delete:test");
        REQUIRE(get_res1);
        REQUIRE(get_res1->status == 200);
        
        // Delete it
        auto delete_res = client.Delete("/api/v1/kv/delete:test");
        REQUIRE(delete_res);
        REQUIRE(delete_res->status == 204);
        
        // Verify it's deleted (should return 404 since key no longer exists)
        auto get_res2 = client.Get("/api/v1/kv/delete:test");
        REQUIRE(get_res2);
        REQUIRE(get_res2->status == 404);
    }
    
    SECTION("List keys endpoint") {
        // Store multiple keys
        std::vector<std::string> test_keys = {"list:key1", "list:key2", "list:key3"};
        
        for (size_t i = 0; i < test_keys.size(); ++i) {
            json data = {{"index", i}, {"key", test_keys[i]}};
            auto res = client.Put("/api/v1/kv/" + test_keys[i], 
                                 data.dump(), 
                                 "application/json");
            REQUIRE(res);
            REQUIRE(res->status == 201);
        }
        
        // List all keys
        auto list_res = client.Get("/api/v1/kv");
        REQUIRE(list_res);
        REQUIRE(list_res->status == 200);
        
        auto response = json::parse(list_res->body);
        REQUIRE(response.contains("keys"));
        REQUIRE(response.contains("total"));
        REQUIRE(response.contains("offset"));
        REQUIRE(response.contains("limit"));
        REQUIRE(response.contains("count"));
        
        REQUIRE(response["offset"] == 0);
        REQUIRE(response["limit"] == 100);
        REQUIRE(response["total"].get<int>() >= 3);
        REQUIRE(response["count"].get<int>() >= 3);
        
        // Test pagination
        auto paginated_res = client.Get("/api/v1/kv?offset=1&limit=1");
        REQUIRE(paginated_res);
        REQUIRE(paginated_res->status == 200);
        
        auto paginated_response = json::parse(paginated_res->body);
        REQUIRE(paginated_response["offset"] == 1);
        REQUIRE(paginated_response["limit"] == 1);
        REQUIRE(paginated_response["count"] == 1);
    }
    
    SECTION("Key updates (latest value wins)") {
        std::string key = "update:test";
        
        // Store initial value
        json initial = {{"version", 1}, {"data", "initial"}};
        auto res1 = client.Put("/api/v1/kv/" + key, initial.dump(), "application/json");
        REQUIRE(res1->status == 201);
        
        // Update with new value
        json updated = {{"version", 2}, {"data", "updated"}};
        auto res2 = client.Put("/api/v1/kv/" + key, updated.dump(), "application/json");
        REQUIRE(res2->status == 201);
        
        // Retrieve and verify latest value
        auto get_res = client.Get("/api/v1/kv/" + key);
        REQUIRE(get_res->status == 200);
        
        auto retrieved = json::parse(get_res->body);
        REQUIRE(retrieved == updated);
    }
    
    SECTION("CORS headers") {
        auto res = client.Get("/api/v1/health");
        REQUIRE(res);
        
        REQUIRE(res->get_header_value("Access-Control-Allow-Origin") == "*");
        REQUIRE(!res->get_header_value("Access-Control-Allow-Methods").empty());
        REQUIRE(!res->get_header_value("Access-Control-Allow-Headers").empty());
    }
}