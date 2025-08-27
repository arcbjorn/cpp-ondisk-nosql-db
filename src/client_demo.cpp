#include "network/binary_server.hpp"
#include <spdlog/spdlog.h>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    // Set up logging
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%f] [%l] %v");
    
    // Parse command line arguments
    std::string host = "localhost";
    uint16_t port = 9090;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--debug") {
            spdlog::set_level(spdlog::level::debug);
        } else if (arg == "--help") {
            std::cout << "NoSQL Database Binary Client Demo\n\n"
                      << "Usage: " << argv[0] << " [options]\n\n"
                      << "Options:\n"
                      << "  --host <host>     Server host (default: localhost)\n"
                      << "  --port <port>     Server port (default: 9090)\n"
                      << "  --debug           Enable debug logging\n"
                      << "  --help            Show this help message\n\n"
                      << "Demo Operations:\n"
                      << "  - PUT operations with test data\n"
                      << "  - GET operations to retrieve data\n"
                      << "  - Query operations (PREFIX, RANGE, SCAN)\n"
                      << "  - Batch operations for performance\n"
                      << "  - DELETE operations\n"
                      << "  - Connection health checks (PING)\n";
            return 0;
        }
    }
    
    try {
        // Configure client
        nosql_db::network::BinaryClient::ClientConfig config;
        config.host = host;
        config.port = port;
        config.connection_timeout = std::chrono::seconds(10);
        config.request_timeout = std::chrono::seconds(30);
        config.enable_keepalive = true;
        config.max_retries = 3;
        
        // Create and connect client
        nosql_db::network::BinaryClient client(config);
        
        if (!client.connect()) {
            spdlog::error("Failed to connect to server at {}:{}", host, port);
            return 1;
        }
        
        spdlog::info("Connected to NoSQL Database Binary Server at {}:{}", host, port);
        
        // Test basic operations
        std::cout << "=== Binary Client Demo ===" << std::endl;
        
        // Test PING
        std::cout << "\n1. Testing connection health..." << std::endl;
        if (client.ping()) {
            std::cout << "✓ Server is responsive (PING successful)" << std::endl;
        } else {
            std::cout << "✗ Server ping failed" << std::endl;
            return 1;
        }
        
        // Test PUT operations
        std::cout << "\n2. Testing PUT operations..." << std::endl;
        std::vector<std::pair<std::string, std::string>> test_data = {
            {"user:alice", "Alice Smith"},
            {"user:bob", "Bob Jones"},
            {"user:charlie", "Charlie Brown"},
            {"post:1", "Hello World"},
            {"post:2", "Binary Protocol Demo"},
            {"config:theme", "dark"},
            {"config:language", "en"}
        };
        
        for (const auto& [key, value] : test_data) {
            if (client.put(key, value)) {
                std::cout << "✓ PUT " << key << " = " << value << std::endl;
            } else {
                std::cout << "✗ PUT " << key << " failed" << std::endl;
            }
        }
        
        // Test GET operations
        std::cout << "\n3. Testing GET operations..." << std::endl;
        for (const auto& [key, expected_value] : test_data) {
            auto value = client.get(key);
            if (value && *value == expected_value) {
                std::cout << "✓ GET " << key << " = " << *value << std::endl;
            } else {
                std::cout << "✗ GET " << key << " failed or incorrect value" << std::endl;
            }
        }
        
        // Test query operations
        std::cout << "\n4. Testing QUERY operations..." << std::endl;
        
        std::vector<std::string> queries = {
            "PREFIX user:",
            "PREFIX config:",
            "RANGE post:1 post:2",
            "SCAN LIMIT 5",
            "COUNT"
        };
        
        for (const auto& query_str : queries) {
            auto results = client.query(query_str);
            std::cout << "Query: " << query_str << " -> " << results.size() << " results" << std::endl;
            
            for (size_t i = 0; i < std::min(results.size(), size_t(3)); ++i) {
                std::cout << "  " << results[i].first << " = " << results[i].second << std::endl;
            }
            if (results.size() > 3) {
                std::cout << "  ... (" << (results.size() - 3) << " more)" << std::endl;
            }
        }
        
        // Test batch operations
        std::cout << "\n5. Testing BATCH operations..." << std::endl;
        std::vector<nosql_db::network::BinaryClient::BatchOperation> batch_ops = {
            {nosql_db::network::BinaryClient::BatchOperation::PUT, "batch:1", "first"},
            {nosql_db::network::BinaryClient::BatchOperation::PUT, "batch:2", "second"},
            {nosql_db::network::BinaryClient::BatchOperation::GET, "user:alice", ""},
            {nosql_db::network::BinaryClient::BatchOperation::DELETE, "temp:delete", ""}
        };
        
        auto batch_results = client.batch_execute(batch_ops);
        std::cout << "Batch operations: " << batch_ops.size() << " -> " << batch_results.size() << " results" << std::endl;
        
        for (size_t i = 0; i < batch_results.size(); ++i) {
            std::cout << "  Operation " << (i+1) << ": " 
                      << (batch_results[i] == nosql_db::network::StatusCode::SUCCESS ? "✓" : "✗") 
                      << std::endl;
        }
        
        // Test DELETE operations
        std::cout << "\n6. Testing DELETE operations..." << std::endl;
        std::vector<std::string> delete_keys = {"batch:1", "batch:2", "user:charlie"};
        
        for (const auto& key : delete_keys) {
            if (client.delete_key(key)) {
                std::cout << "✓ DELETE " << key << std::endl;
            } else {
                std::cout << "✗ DELETE " << key << " failed" << std::endl;
            }
        }
        
        // Final verification
        std::cout << "\n7. Final verification..." << std::endl;
        auto final_results = client.query("SCAN");
        std::cout << "Remaining keys: " << final_results.size() << std::endl;
        
        std::cout << "\n=== Demo completed successfully ===" << std::endl;
        
        client.disconnect();
        return 0;
        
    } catch (const std::exception& e) {
        spdlog::error("Client error: {}", e.what());
        return 1;
    }
}