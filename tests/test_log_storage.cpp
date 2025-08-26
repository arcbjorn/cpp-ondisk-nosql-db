#include <catch2/catch_test_macros.hpp>
#include "storage/log_storage.hpp"
#include <filesystem>
#include <thread>

using namespace nosql_db::storage;

TEST_CASE("LogStorage basic operations", "[storage]") {
    const auto test_file = std::filesystem::temp_directory_path() / "test_log.log";
    std::filesystem::remove(test_file);
    
    SECTION("Constructor and destructor") {
        LogStorage storage(test_file);
        REQUIRE(storage.is_open());
        REQUIRE(std::filesystem::exists(test_file));
    }
    
    SECTION("Append and get operations") {
        LogStorage storage(test_file);
        
        REQUIRE(storage.append("key1", "value1"));
        REQUIRE(storage.append("key2", "value2"));
        
        auto result1 = storage.get("key1");
        REQUIRE(result1.has_value());
        REQUIRE(result1.value() == "value1");
        
        auto result2 = storage.get("key2");
        REQUIRE(result2.has_value());
        REQUIRE(result2.value() == "value2");
        
        auto result3 = storage.get("nonexistent");
        REQUIRE(!result3.has_value());
    }
    
    SECTION("Key update - latest value wins") {
        LogStorage storage(test_file);
        
        REQUIRE(storage.append("key1", "old_value"));
        REQUIRE(storage.append("key1", "new_value"));
        
        auto result = storage.get("key1");
        REQUIRE(result.has_value());
        REQUIRE(result.value() == "new_value");
    }
    
    SECTION("Get all records") {
        LogStorage storage(test_file);
        
        REQUIRE(storage.append("key1", "value1"));
        REQUIRE(storage.append("key2", "value2"));
        REQUIRE(storage.append("key1", "updated_value1"));
        
        auto records = storage.get_all();
        REQUIRE(records.size() == 3);
        
        REQUIRE(records[0].key == "key1");
        REQUIRE(records[0].value == "value1");
        
        REQUIRE(records[1].key == "key2");
        REQUIRE(records[1].value == "value2");
        
        REQUIRE(records[2].key == "key1");
        REQUIRE(records[2].value == "updated_value1");
    }
    
    SECTION("Empty key handling") {
        LogStorage storage(test_file);
        REQUIRE(!storage.append("", "value"));
    }
    
    SECTION("Large values") {
        LogStorage storage(test_file);
        std::string large_value(10000, 'x');
        
        REQUIRE(storage.append("large_key", large_value));
        
        auto result = storage.get("large_key");
        REQUIRE(result.has_value());
        REQUIRE(result.value() == large_value);
    }
    
    SECTION("Persistence across instances") {
        {
            LogStorage storage(test_file);
            REQUIRE(storage.append("persist_key", "persist_value"));
            storage.sync();
        }
        
        {
            LogStorage storage(test_file);
            auto result = storage.get("persist_key");
            REQUIRE(result.has_value());
            REQUIRE(result.value() == "persist_value");
        }
    }
    
    SECTION("Timestamp ordering") {
        LogStorage storage(test_file);
        
        REQUIRE(storage.append("key1", "value1"));
        std::this_thread::sleep_for(std::chrono::microseconds(1));
        REQUIRE(storage.append("key2", "value2"));
        
        auto records = storage.get_all();
        REQUIRE(records.size() == 2);
        REQUIRE(records[0].timestamp < records[1].timestamp);
    }
    
    SECTION("Index-based fast lookup") {
        LogStorage storage(test_file);
        
        // Add many records to test index performance
        for (int i = 0; i < 1000; ++i) {
            std::string key = "key_" + std::to_string(i);
            std::string value = "value_" + std::to_string(i);
            REQUIRE(storage.append(key, value));
        }
        
        // Test random lookups
        auto result = storage.get("key_500");
        REQUIRE(result.has_value());
        REQUIRE(result.value() == "value_500");
        
        auto missing = storage.get("nonexistent");
        REQUIRE(!missing.has_value());
    }
    
    std::filesystem::remove(test_file);
}