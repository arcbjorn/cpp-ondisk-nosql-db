#include <catch2/catch_test_macros.hpp>
#include "query/query_engine.hpp"
#include "storage/storage_engine.hpp"
#include <filesystem>

using namespace nosql_db::query;
using namespace nosql_db::storage;

TEST_CASE("QueryEngine basic operations", "[query][basic]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_query_basic";
    std::filesystem::remove_all(test_dir);
    
    SECTION("Initialization and setup") {
        auto storage = std::make_shared<StorageEngine>(test_dir, StorageEngine::EngineType::LSMTree);
        QueryEngine query_engine(storage);
        
        REQUIRE(query_engine.count_keys() == 0);
        
        // Add some test data
        storage->put("user:alice", "Alice Smith");
        storage->put("user:bob", "Bob Jones");
        storage->put("post:1", "Hello World");
        storage->put("post:2", "Query Engine");
        
        REQUIRE(query_engine.count_keys() == 4);
    }
    
    SECTION("Single key GET operations") {
        auto storage = std::make_shared<StorageEngine>(test_dir, StorageEngine::EngineType::LSMTree);
        QueryEngine query_engine(storage);
        
        // Add test data
        storage->put("key1", "value1");
        storage->put("key2", "value2");
        
        // Test successful GET
        auto result = query_engine.get("key1");
        REQUIRE(result.has_value());
        REQUIRE(result->key == "key1");
        REQUIRE(result->value == "value1");
        
        // Test missing key
        auto missing = query_engine.get("nonexistent");
        REQUIRE(!missing.has_value());
    }
    
    std::filesystem::remove_all(test_dir);
}

TEST_CASE("QueryEngine range queries", "[query][range]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_query_range";
    std::filesystem::remove_all(test_dir);
    
    auto storage = std::make_shared<StorageEngine>(test_dir, StorageEngine::EngineType::LSMTree);
    QueryEngine query_engine(storage);
    
    // Add ordered test data
    storage->put("key_a", "value_a");
    storage->put("key_b", "value_b");
    storage->put("key_c", "value_c");
    storage->put("key_d", "value_d");
    storage->put("key_e", "value_e");
    
    SECTION("Range query with inclusive bounds") {
        auto results = query_engine.range_query("key_b", "key_d");
        
        REQUIRE(results.size() == 3);
        REQUIRE(results[0].key == "key_b");
        REQUIRE(results[1].key == "key_c");
        REQUIRE(results[2].key == "key_d");
    }
    
    SECTION("Range query with no matches") {
        auto results = query_engine.range_query("key_x", "key_z");
        REQUIRE(results.empty());
    }
    
    SECTION("Range query with single key") {
        auto results = query_engine.range_query("key_c", "key_c");
        REQUIRE(results.size() == 1);
        REQUIRE(results[0].key == "key_c");
    }
    
    std::filesystem::remove_all(test_dir);
}

TEST_CASE("QueryEngine prefix queries", "[query][prefix]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_query_prefix";
    std::filesystem::remove_all(test_dir);
    
    auto storage = std::make_shared<StorageEngine>(test_dir, StorageEngine::EngineType::LSMTree);
    QueryEngine query_engine(storage);
    
    // Add hierarchical test data
    storage->put("user:alice:name", "Alice Smith");
    storage->put("user:alice:email", "alice@example.com");
    storage->put("user:bob:name", "Bob Jones");
    storage->put("user:bob:email", "bob@example.com");
    storage->put("post:1:title", "Hello World");
    storage->put("post:1:content", "First post");
    storage->put("settings:theme", "dark");
    
    SECTION("Prefix query for user namespace") {
        auto results = query_engine.prefix_query("user:");
        
        REQUIRE(results.size() == 4);
        // Results should be sorted by key
        REQUIRE(results[0].key == "user:alice:email");
        REQUIRE(results[1].key == "user:alice:name");
        REQUIRE(results[2].key == "user:bob:email");
        REQUIRE(results[3].key == "user:bob:name");
    }
    
    SECTION("Prefix query for specific user") {
        auto results = query_engine.prefix_query("user:alice:");
        
        REQUIRE(results.size() == 2);
        REQUIRE(results[0].key == "user:alice:email");
        REQUIRE(results[1].key == "user:alice:name");
    }
    
    SECTION("Prefix query with no matches") {
        auto results = query_engine.prefix_query("admin:");
        REQUIRE(results.empty());
    }
    
    std::filesystem::remove_all(test_dir);
}

TEST_CASE("QueryEngine pattern queries", "[query][pattern]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_query_pattern";
    std::filesystem::remove_all(test_dir);
    
    auto storage = std::make_shared<StorageEngine>(test_dir, StorageEngine::EngineType::LSMTree);
    QueryEngine query_engine(storage);
    
    // Add test data with patterns
    storage->put("file1.txt", "text file 1");
    storage->put("file2.txt", "text file 2");
    storage->put("image1.jpg", "image file 1");
    storage->put("image2.png", "image file 2");
    storage->put("document.pdf", "pdf document");
    storage->put("readme", "readme file");
    
    SECTION("Wildcard pattern matching") {
        auto results = query_engine.pattern_query("*.txt");
        
        REQUIRE(results.size() == 2);
        REQUIRE(results[0].key == "file1.txt");
        REQUIRE(results[1].key == "file2.txt");
    }
    
    SECTION("Single character wildcard") {
        auto results = query_engine.pattern_query("file?.txt");
        
        REQUIRE(results.size() == 2);
        REQUIRE(results[0].key == "file1.txt");
        REQUIRE(results[1].key == "file2.txt");
    }
    
    SECTION("Complex pattern") {
        auto results = query_engine.pattern_query("image*.*");
        
        REQUIRE(results.size() == 2);
        REQUIRE(results[0].key == "image1.jpg");
        REQUIRE(results[1].key == "image2.png");
    }
    
    std::filesystem::remove_all(test_dir);
}

TEST_CASE("QueryEngine string-based queries", "[query][string]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_query_string";
    std::filesystem::remove_all(test_dir);
    
    auto storage = std::make_shared<StorageEngine>(test_dir, StorageEngine::EngineType::LSMTree);
    QueryEngine query_engine(storage);
    
    // Add test data
    storage->put("key1", "value1");
    storage->put("key2", "value2");
    storage->put("user:alice", "Alice Smith");
    storage->put("user:bob", "Bob Jones");
    
    SECTION("Simple GET query") {
        auto results = query_engine.execute_query("GET key1");
        
        REQUIRE(results.size() == 1);
        REQUIRE(results[0].key == "key1");
        REQUIRE(results[0].value == "value1");
    }
    
    SECTION("RANGE query") {
        auto results = query_engine.execute_query("RANGE key1 key2");
        
        REQUIRE(results.size() == 2);
        REQUIRE(results[0].key == "key1");
        REQUIRE(results[1].key == "key2");
    }
    
    SECTION("PREFIX query") {
        auto results = query_engine.execute_query("PREFIX user:");
        
        REQUIRE(results.size() == 2);
        REQUIRE(results[0].key == "user:alice");
        REQUIRE(results[1].key == "user:bob");
    }
    
    SECTION("PATTERN query") {
        auto results = query_engine.execute_query("PATTERN user:*");
        
        REQUIRE(results.size() == 2);
        REQUIRE(results[0].key == "user:alice");
        REQUIRE(results[1].key == "user:bob");
    }
    
    SECTION("SCAN query") {
        auto results = query_engine.execute_query("SCAN");
        
        REQUIRE(results.size() == 4);
    }
    
    SECTION("COUNT query") {
        auto results = query_engine.execute_query("COUNT");
        
        REQUIRE(results.size() == 1);
        REQUIRE(results[0].key == "__COUNT__");
        REQUIRE(results[0].value == "4");
    }
    
    std::filesystem::remove_all(test_dir);
}

TEST_CASE("QueryEngine pagination and limits", "[query][pagination]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_query_pagination";
    std::filesystem::remove_all(test_dir);
    
    auto storage = std::make_shared<StorageEngine>(test_dir, StorageEngine::EngineType::LSMTree);
    QueryEngine query_engine(storage);
    
    // Add test data
    for (int i = 1; i <= 10; ++i) {
        storage->put("key" + std::to_string(i), "value" + std::to_string(i));
    }
    
    SECTION("LIMIT clause") {
        auto results = query_engine.execute_query("SCAN LIMIT 3");
        REQUIRE(results.size() == 3);
    }
    
    SECTION("OFFSET clause") {
        auto results = query_engine.execute_query("SCAN OFFSET 5");
        REQUIRE(results.size() == 5); // 10 total - 5 offset = 5 results
    }
    
    SECTION("LIMIT and OFFSET combined") {
        auto results = query_engine.execute_query("SCAN LIMIT 2 OFFSET 3");
        REQUIRE(results.size() == 2);
    }
    
    std::filesystem::remove_all(test_dir);
}

TEST_CASE("QueryEngine optimization and statistics", "[query][optimization]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_query_optimization";
    std::filesystem::remove_all(test_dir);
    
    auto storage = std::make_shared<StorageEngine>(test_dir, StorageEngine::EngineType::LSMTree);
    QueryEngine query_engine(storage);
    
    // Add test data
    storage->put("key1", "value1");
    storage->put("key2", "value2");
    
    SECTION("Query plan generation") {
        auto parsed_query = query_engine.parse_query("GET key1");
        auto plan = query_engine.create_execution_plan(parsed_query);
        
        REQUIRE(plan.operation == QueryOp::GET);
        REQUIRE(plan.use_index == true);
        REQUIRE(plan.requires_full_scan == false);
        REQUIRE(plan.estimated_cost == 1);
    }
    
    SECTION("Statistics tracking") {
        auto initial_stats = query_engine.get_query_statistics();
        
        // Execute some queries
        query_engine.execute_query("GET key1");
        query_engine.execute_query("SCAN");
        
        auto updated_stats = query_engine.get_query_statistics();
        // Should have more executed queries and full scans
        REQUIRE(updated_stats.size() == 3); // queries_executed, cache_hits, full_scans
    }
    
    SECTION("Configuration options") {
        query_engine.set_max_results(5);
        query_engine.set_enable_query_cache(false);
        
        // Add more data to test limits
        for (int i = 3; i <= 10; ++i) {
            storage->put("key" + std::to_string(i), "value" + std::to_string(i));
        }
        
        auto results = query_engine.execute_query("SCAN");
        REQUIRE(results.size() <= 5); // Should be limited
    }
    
    std::filesystem::remove_all(test_dir);
}

TEST_CASE("QueryEngine error handling", "[query][errors]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_query_errors";
    std::filesystem::remove_all(test_dir);
    
    auto storage = std::make_shared<StorageEngine>(test_dir, StorageEngine::EngineType::LSMTree);
    QueryEngine query_engine(storage);
    
    SECTION("Invalid query operations") {
        REQUIRE_THROWS_AS(query_engine.execute_query("INVALID key1"), std::invalid_argument);
        REQUIRE_THROWS_AS(query_engine.execute_query(""), std::invalid_argument);
    }
    
    SECTION("Missing required parameters") {
        REQUIRE_THROWS_AS(query_engine.execute_query("GET"), std::invalid_argument);
        REQUIRE_THROWS_AS(query_engine.execute_query("RANGE key1"), std::invalid_argument);
        REQUIRE_THROWS_AS(query_engine.execute_query("PREFIX"), std::invalid_argument);
    }
    
    std::filesystem::remove_all(test_dir);
}

TEST_CASE("QueryEngine with LSM-Tree integration", "[query][lsm]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_query_lsm";
    std::filesystem::remove_all(test_dir);
    
    auto storage = std::make_shared<StorageEngine>(test_dir, StorageEngine::EngineType::LSMTree);
    QueryEngine query_engine(storage);
    
    SECTION("Query after segment rotation") {
        // Add enough data to trigger segment rotation
        std::string large_value(1000, 'x'); // 1KB value
        for (int i = 1; i <= 20; ++i) {
            storage->put("large_key_" + std::to_string(i), large_value);
        }
        
        // Queries should still work correctly
        auto results = query_engine.prefix_query("large_key_");
        REQUIRE(results.size() == 20);
        
        auto get_result = query_engine.get("large_key_10");
        REQUIRE(get_result.has_value());
        REQUIRE(get_result->value == large_value);
    }
    
    SECTION("Query with deleted keys") {
        storage->put("temp_key1", "temp_value1");
        storage->put("temp_key2", "temp_value2");
        
        // Verify keys exist
        REQUIRE(query_engine.get("temp_key1").has_value());
        
        // Delete a key
        storage->delete_key("temp_key1");
        
        // Query should not return deleted key
        REQUIRE(!query_engine.get("temp_key1").has_value());
        REQUIRE(query_engine.get("temp_key2").has_value());
        
        // Prefix query should not include deleted keys
        auto results = query_engine.prefix_query("temp_key");
        REQUIRE(results.size() == 1);
        REQUIRE(results[0].key == "temp_key2");
    }
    
    std::filesystem::remove_all(test_dir);
}