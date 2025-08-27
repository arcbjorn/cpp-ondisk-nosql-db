#include <catch2/catch_test_macros.hpp>
#include "storage/btree_index.hpp"
#include <random>
#include <algorithm>
#include <chrono>

using namespace ishikura::storage;

TEST_CASE("BTreeIndex basic operations", "[btree]") {
    BTreeIndex index;
    
    SECTION("Empty index") {
        REQUIRE(index.empty());
        REQUIRE(index.size() == 0);
        REQUIRE(index.height() == 1);
        
        auto result = index.find("nonexistent");
        REQUIRE(!result.has_value());
    }
    
    SECTION("Single insertion and lookup") {
        index.insert("key1", 100, 1000);
        
        REQUIRE(!index.empty());
        REQUIRE(index.size() == 1);
        
        auto result = index.find("key1");
        REQUIRE(result.has_value());
        REQUIRE(result->key == "key1");
        REQUIRE(result->file_offset == 100);
        REQUIRE(result->timestamp == 1000);
        
        auto missing = index.find("missing");
        REQUIRE(!missing.has_value());
    }
    
    SECTION("Multiple insertions") {
        index.insert("apple", 100, 1000);
        index.insert("banana", 200, 2000);
        index.insert("cherry", 300, 3000);
        
        REQUIRE(index.size() == 3);
        
        auto apple = index.find("apple");
        auto banana = index.find("banana");
        auto cherry = index.find("cherry");
        
        REQUIRE(apple.has_value());
        REQUIRE(banana.has_value());
        REQUIRE(cherry.has_value());
        
        REQUIRE(apple->file_offset == 100);
        REQUIRE(banana->file_offset == 200);
        REQUIRE(cherry->file_offset == 300);
    }
    
    SECTION("Key updates with newer timestamp") {
        index.insert("key1", 100, 1000);
        index.insert("key1", 200, 2000); // Update with newer timestamp
        
        REQUIRE(index.size() == 1); // Size should remain 1
        
        auto result = index.find("key1");
        REQUIRE(result.has_value());
        REQUIRE(result->file_offset == 200); // Should have updated offset
        REQUIRE(result->timestamp == 2000);   // Should have updated timestamp
    }
    
    SECTION("Key updates with older timestamp ignored") {
        index.insert("key1", 200, 2000);
        index.insert("key1", 100, 1000); // Try to update with older timestamp
        
        REQUIRE(index.size() == 1);
        
        auto result = index.find("key1");
        REQUIRE(result.has_value());
        REQUIRE(result->file_offset == 200); // Should keep newer offset
        REQUIRE(result->timestamp == 2000);   // Should keep newer timestamp
    }
    
    SECTION("Range scan") {
        index.insert("apple", 100, 1000);
        index.insert("banana", 200, 2000);
        index.insert("cherry", 300, 3000);
        index.insert("date", 400, 4000);
        index.insert("elderberry", 500, 5000);
        
        auto results = index.range_scan("banana", "date");
        REQUIRE(results.size() == 3);
        
        // Results should be in sorted order
        REQUIRE(results[0].key == "banana");
        REQUIRE(results[1].key == "cherry");
        REQUIRE(results[2].key == "date");
    }
    
    SECTION("Clear operation") {
        index.insert("key1", 100, 1000);
        index.insert("key2", 200, 2000);
        
        REQUIRE(index.size() == 2);
        
        index.clear();
        
        REQUIRE(index.empty());
        REQUIRE(index.size() == 0);
        REQUIRE(!index.find("key1").has_value());
        REQUIRE(!index.find("key2").has_value());
    }
}

TEST_CASE("BTreeIndex stress test", "[btree][performance]") {
    BTreeIndex index;
    constexpr size_t NUM_KEYS = 10000;
    
    SECTION("Large number of insertions") {
        std::vector<std::string> keys;
        keys.reserve(NUM_KEYS);
        
        // Generate random keys
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 25);
        
        for (size_t i = 0; i < NUM_KEYS; ++i) {
            std::string key = "key_";
            for (int j = 0; j < 10; ++j) {
                key += static_cast<char>('a' + dis(gen));
            }
            keys.push_back(key);
        }
        
        // Insert all keys
        auto start = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < keys.size(); ++i) {
            index.insert(keys[i], i * 100, i * 1000);
        }
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        INFO("Insertion time: " << duration.count() << " microseconds");
        INFO("Average per insertion: " << (duration.count() / NUM_KEYS) << " microseconds");
        
        REQUIRE(index.size() <= NUM_KEYS); // May be less due to duplicates
        
        // Test lookups
        start = std::chrono::high_resolution_clock::now();
        size_t found_count = 0;
        for (const auto& key : keys) {
            if (index.find(key).has_value()) {
                ++found_count;
            }
        }
        end = std::chrono::high_resolution_clock::now();
        
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        INFO("Lookup time: " << duration.count() << " microseconds");
        INFO("Average per lookup: " << (duration.count() / NUM_KEYS) << " microseconds");
        INFO("Tree height: " << index.height());
        
        REQUIRE(found_count > 0);
    }
    
    SECTION("Sequential insertions maintain balance") {
        // Insert keys in sequential order
        for (size_t i = 0; i < 1000; ++i) {
            std::string key = "key_" + std::to_string(i);
            index.insert(key, i * 100, i * 1000);
        }
        
        REQUIRE(index.size() == 1000);
        
        // Height should be logarithmic
        size_t height = index.height();
        INFO("Tree height for 1000 sequential keys: " << height);
        REQUIRE(height < 10); // Should be well-balanced
        
        // All keys should be findable
        for (size_t i = 0; i < 1000; ++i) {
            std::string key = "key_" + std::to_string(i);
            auto result = index.find(key);
            REQUIRE(result.has_value());
            REQUIRE(result->file_offset == i * 100);
        }
    }
}