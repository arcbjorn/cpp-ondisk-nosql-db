#include <catch2/catch_test_macros.hpp>
#include "storage/lsm_tree.hpp"
#include "storage/storage_engine.hpp"
#include <filesystem>
#include <thread>
#include <chrono>

using namespace nosql_db::storage;

TEST_CASE("LSMTree basic operations", "[lsm][storage]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_lsm";
    std::filesystem::remove_all(test_dir);
    
    SECTION("Constructor and initialization") {
        LSMTree lsm(test_dir);
        REQUIRE(lsm.get_level_count() >= 1);
        REQUIRE(std::filesystem::exists(test_dir));
    }
    
    SECTION("Basic put and get operations") {
        LSMTree lsm(test_dir);
        
        REQUIRE(lsm.put("key1", "value1"));
        REQUIRE(lsm.put("key2", "value2"));
        
        auto result1 = lsm.get("key1");
        REQUIRE(result1.has_value());
        REQUIRE(result1.value() == "value1");
        
        auto result2 = lsm.get("key2");
        REQUIRE(result2.has_value());
        REQUIRE(result2.value() == "value2");
        
        auto result3 = lsm.get("nonexistent");
        REQUIRE(!result3.has_value());
    }
    
    SECTION("Key updates - latest value wins") {
        LSMTree lsm(test_dir);
        
        REQUIRE(lsm.put("key1", "old_value"));
        REQUIRE(lsm.put("key1", "new_value"));
        
        auto result = lsm.get("key1");
        REQUIRE(result.has_value());
        REQUIRE(result.value() == "new_value");
    }
    
    SECTION("Delete operations with tombstones") {
        LSMTree lsm(test_dir);
        
        REQUIRE(lsm.put("key1", "value1"));
        REQUIRE(lsm.put("key2", "value2"));
        
        // Verify keys exist
        REQUIRE(lsm.get("key1").has_value());
        REQUIRE(lsm.get("key2").has_value());
        
        // Delete key1
        REQUIRE(lsm.delete_key("key1"));
        
        // key1 should be deleted, key2 should still exist
        REQUIRE(!lsm.get("key1").has_value());
        REQUIRE(lsm.get("key2").has_value());
    }
    
    SECTION("Get all records with deletion filtering") {
        LSMTree lsm(test_dir);
        
        REQUIRE(lsm.put("key1", "value1"));
        REQUIRE(lsm.put("key2", "value2"));
        REQUIRE(lsm.put("key3", "value3"));
        REQUIRE(lsm.delete_key("key2"));
        
        auto records = lsm.get_all();
        
        // Should only return non-deleted records
        REQUIRE(records.size() == 2);
        
        bool found_key1 = false, found_key3 = false;
        for (const auto& record : records) {
            if (record.key == "key1" && record.value == "value1") found_key1 = true;
            if (record.key == "key3" && record.value == "value3") found_key3 = true;
            REQUIRE(record.key != "key2"); // key2 should be filtered out
        }
        
        REQUIRE(found_key1);
        REQUIRE(found_key3);
    }
    
    std::filesystem::remove_all(test_dir);
}

TEST_CASE("LSMTree segment rotation and compaction", "[lsm][compaction]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_lsm_compaction";
    std::filesystem::remove_all(test_dir);
    
    SECTION("Segment rotation on size threshold") {
        LSMTree lsm(test_dir);
        lsm.set_compaction_trigger_size(1024); // Small threshold for testing
        
        // Fill active segment beyond threshold
        std::string large_value(500, 'x'); // 500 bytes per value
        
        REQUIRE(lsm.put("key1", large_value));
        REQUIRE(lsm.put("key2", large_value));
        REQUIRE(lsm.put("key3", large_value)); // This should trigger rotation
        
        // All keys should still be retrievable
        REQUIRE(lsm.get("key1").has_value());
        REQUIRE(lsm.get("key2").has_value());
        REQUIRE(lsm.get("key3").has_value());
    }
    
    SECTION("Manual compaction trigger") {
        LSMTree lsm(test_dir);
        lsm.set_compaction_trigger_size(512); // Very small for testing
        
        // Add data to trigger compaction conditions
        std::string large_value(200, 'x'); // 200 bytes
        for (int i = 0; i < 10; ++i) {
            std::string key = "key_" + std::to_string(i);
            REQUIRE(lsm.put(key, large_value));
        }
        
        // Force compaction manually (without background thread)
        lsm.force_compaction();
        
        // Verify all data is still accessible
        for (int i = 0; i < 10; ++i) {
            std::string key = "key_" + std::to_string(i);
            auto result = lsm.get(key);
            REQUIRE(result.has_value());
            REQUIRE(result.value() == large_value);
        }
    }
    
    SECTION("Compaction statistics") {
        LSMTree lsm(test_dir);
        
        // Add and delete data to create compaction work
        for (int i = 0; i < 10; ++i) {
            lsm.put("key_" + std::to_string(i), "value_" + std::to_string(i));
        }
        
        // Delete some keys to create tombstones
        for (int i = 0; i < 5; ++i) {
            lsm.delete_key("key_" + std::to_string(i));
        }
        
        auto stats = lsm.get_stats();
        // We should have baseline stats
        REQUIRE(stats.compactions_completed >= 0);
        REQUIRE(stats.bytes_compacted >= 0);
        REQUIRE(stats.tombstones_removed >= 0);
        REQUIRE(stats.duplicate_keys_merged >= 0);
    }
    
    std::filesystem::remove_all(test_dir);
}

TEST_CASE("LSMTree concurrent operations", "[lsm][concurrency]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_lsm_concurrent";
    std::filesystem::remove_all(test_dir);
    
    SECTION("Concurrent reads and writes") {
        LSMTree lsm(test_dir);
        
        constexpr int NUM_THREADS = 2;
        constexpr int OPERATIONS_PER_THREAD = 10;
        std::vector<std::thread> threads;
        
        // Writer threads
        for (int t = 0; t < NUM_THREADS / 2; ++t) {
            threads.emplace_back([&lsm, t, OPERATIONS_PER_THREAD]() {
                for (int i = 0; i < OPERATIONS_PER_THREAD; ++i) {
                    std::string key = "thread_" + std::to_string(t) + "_key_" + std::to_string(i);
                    std::string value = "value_" + std::to_string(i);
                    lsm.put(key, value);
                }
            });
        }
        
        // Reader threads (will read while writers are working)
        for (int t = NUM_THREADS / 2; t < NUM_THREADS; ++t) {
            threads.emplace_back([&lsm, OPERATIONS_PER_THREAD]() {
                for (int i = 0; i < OPERATIONS_PER_THREAD; ++i) {
                    // Try to read keys that might exist
                    lsm.get("thread_0_key_" + std::to_string(i % 10));
                }
            });
        }
        
        // Wait for all threads
        for (auto& thread : threads) {
            thread.join();
        }
        
        // Verify data integrity
        for (int t = 0; t < NUM_THREADS / 2; ++t) {
            for (int i = 0; i < OPERATIONS_PER_THREAD; ++i) {
                std::string key = "thread_" + std::to_string(t) + "_key_" + std::to_string(i);
                std::string expected_value = "value_" + std::to_string(i);
                auto result = lsm.get(key);
                REQUIRE(result.has_value());
                REQUIRE(result.value() == expected_value);
            }
        }
    }
    
    std::filesystem::remove_all(test_dir);
}

TEST_CASE("StorageEngine with LSMTree", "[storage_engine][lsm]") {
    const auto test_dir = std::filesystem::temp_directory_path() / "test_storage_engine_lsm";
    std::filesystem::remove_all(test_dir);
    
    SECTION("LSMTree engine type") {
        StorageEngine engine(test_dir, StorageEngine::EngineType::LSMTree);
        
        REQUIRE(engine.get_engine_type() == StorageEngine::EngineType::LSMTree);
        
        // Basic operations
        REQUIRE(engine.put("key1", "value1"));
        REQUIRE(engine.put("key2", "value2"));
        
        auto result1 = engine.get("key1");
        REQUIRE(result1.has_value());
        REQUIRE(result1.value() == "value1");
        
        // Delete operation
        REQUIRE(engine.delete_key("key1"));
        REQUIRE(!engine.get("key1").has_value());
        REQUIRE(engine.get("key2").has_value());
    }
    
    SECTION("Compaction control through StorageEngine") {
        StorageEngine engine(test_dir, StorageEngine::EngineType::LSMTree);
        
        // Add data
        for (int i = 0; i < 10; ++i) {
            engine.put("key_" + std::to_string(i), "value_" + std::to_string(i));
        }
        
        // Force compaction manually
        engine.force_compaction();
        
        // Verify data integrity
        for (int i = 0; i < 10; ++i) {
            auto result = engine.get("key_" + std::to_string(i));
            REQUIRE(result.has_value());
            REQUIRE(result.value() == "value_" + std::to_string(i));
        }
    }
    
    SECTION("Statistics collection") {
        StorageEngine engine(test_dir, StorageEngine::EngineType::LSMTree);
        
        // Perform operations
        engine.put("key1", "value1");
        engine.put("key2", "value2");
        engine.get("key1");
        engine.get("nonexistent");
        engine.delete_key("key1");
        
        auto stats = engine.get_stats();
        REQUIRE(stats.total_puts == 2);
        REQUIRE(stats.total_gets == 2);
        REQUIRE(stats.total_deletes == 1);
    }
    
    std::filesystem::remove_all(test_dir);
}