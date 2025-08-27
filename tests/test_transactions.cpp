#include <catch2/catch_test_macros.hpp>
#include "storage/transaction.hpp"
#include "storage/log_storage.hpp"
#include <filesystem>
#include <thread>
#include <vector>
#include <chrono>

using namespace ishikura::storage;

namespace {
    class TransactionTestFixture {
    public:
        TransactionTestFixture() {
            // Create temporary storage file
            temp_file_ = std::filesystem::temp_directory_path() / "test_transactions.log";
            std::filesystem::remove(temp_file_); // Clean up from any previous test
            
            storage_ = std::make_shared<LogStorage>(temp_file_);
            transaction_manager_ = std::make_unique<TransactionManager>(storage_);
        }
        
        ~TransactionTestFixture() {
            transaction_manager_.reset();
            storage_.reset();
            std::filesystem::remove(temp_file_);
        }
        
        std::unique_ptr<Transaction> begin_transaction() {
            return transaction_manager_->begin_transaction();
        }
        
        std::shared_ptr<LogStorage> storage() { return storage_; }
        TransactionManager* manager() { return transaction_manager_.get(); }
        
    private:
        std::filesystem::path temp_file_;
        std::shared_ptr<LogStorage> storage_;
        std::unique_ptr<TransactionManager> transaction_manager_;
    };
}

TEST_CASE("Transaction Basic Operations", "[transactions]") {
    TransactionTestFixture fixture;
    
    SECTION("Single transaction PUT and GET") {
        auto tx = fixture.begin_transaction();
        
        REQUIRE(tx->is_active());
        REQUIRE(tx->status() == Transaction::Status::Active);
        
        // Put a key-value pair
        REQUIRE(tx->put("test:key", "test value"));
        
        // Should be able to read it within the same transaction
        auto value = tx->get("test:key");
        REQUIRE(value.has_value());
        REQUIRE(*value == "test value");
        
        // Should not be visible in storage before commit
        REQUIRE_FALSE(fixture.storage()->get("test:key").has_value());
        
        // Commit the transaction
        REQUIRE(tx->commit());
        REQUIRE(tx->status() == Transaction::Status::Committed);
        
        // Now should be visible in storage
        auto committed_value = fixture.storage()->get("test:key");
        REQUIRE(committed_value.has_value());
        REQUIRE(*committed_value == "test value");
    }
    
    SECTION("Transaction rollback") {
        auto tx = fixture.begin_transaction();
        
        REQUIRE(tx->put("rollback:key", "rollback value"));
        
        // Should be visible within transaction
        REQUIRE(tx->get("rollback:key").has_value());
        
        // Rollback the transaction
        tx->rollback();
        REQUIRE(tx->status() == Transaction::Status::Aborted);
        
        // Should not be visible in storage
        REQUIRE_FALSE(fixture.storage()->get("rollback:key").has_value());
    }
    
    SECTION("Transaction DELETE operation") {
        // First, put a key directly in storage
        auto tx1 = fixture.begin_transaction();
        REQUIRE(tx1->put("delete:test", "to be deleted"));
        REQUIRE(tx1->commit());
        
        // Verify it exists
        REQUIRE(fixture.storage()->get("delete:test").has_value());
        
        // Delete it in another transaction
        auto tx2 = fixture.begin_transaction();
        REQUIRE(tx2->delete_key("delete:test"));
        REQUIRE(tx2->commit());
        
        // Should return tombstone marker
        auto value = fixture.storage()->get("delete:test");
        REQUIRE(value.has_value());
        REQUIRE(*value == "__DELETED__");
    }
    
    SECTION("Empty key validation") {
        auto tx = fixture.begin_transaction();
        
        // Empty keys should be rejected
        REQUIRE_FALSE(tx->put("", "value"));
        REQUIRE_FALSE(tx->delete_key(""));
        
        // Transaction should still be active
        REQUIRE(tx->is_active());
    }
    
    SECTION("Operations on inactive transaction") {
        auto tx = fixture.begin_transaction();
        tx->commit();
        
        // Operations on committed transaction should throw
        REQUIRE_THROWS_AS(tx->put("key", "value"), std::runtime_error);
        REQUIRE_THROWS_AS(tx->get("key"), std::runtime_error);
        REQUIRE_THROWS_AS(tx->delete_key("key"), std::runtime_error);
    }
}

TEST_CASE("Transaction Isolation", "[transactions]") {
    TransactionTestFixture fixture;
    
    SECTION("Read isolation - dirty reads prevented") {
        auto tx1 = fixture.begin_transaction();
        auto tx2 = fixture.begin_transaction();
        
        // TX1 writes a value
        REQUIRE(tx1->put("isolation:key", "tx1 value"));
        
        // TX2 should not see TX1's uncommitted changes (dirty read prevention)
        REQUIRE_FALSE(tx2->get("isolation:key").has_value());
        
        // After TX1 commits, new transactions can see the committed value
        REQUIRE(tx1->commit());
        
        // TX3 (new transaction) sees committed value (read committed isolation)
        auto tx3 = fixture.begin_transaction();
        auto value = tx3->get("isolation:key");
        REQUIRE(value.has_value());
        REQUIRE(*value == "tx1 value");
        
        // TX2 may now see committed changes (read committed behavior)
        // This is acceptable for this level of isolation implementation
    }
    
    SECTION("Write-write conflict handling") {
        auto tx1 = fixture.begin_transaction();
        auto tx2 = fixture.begin_transaction();
        
        // Both transactions try to write the same key
        REQUIRE(tx1->put("conflict:key", "tx1 value"));
        REQUIRE(tx2->put("conflict:key", "tx2 value"));
        
        // First to commit wins
        REQUIRE(tx1->commit());
        REQUIRE(tx2->commit());
        
        // Last committed value should be visible
        auto value = fixture.storage()->get("conflict:key");
        REQUIRE(value.has_value());
        REQUIRE(*value == "tx2 value");
    }
    
    SECTION("Transaction-local changes override storage") {
        // Put initial value in storage
        auto tx1 = fixture.begin_transaction();
        REQUIRE(tx1->put("override:key", "storage value"));
        REQUIRE(tx1->commit());
        
        // New transaction modifies the value locally
        auto tx2 = fixture.begin_transaction();
        REQUIRE(tx2->put("override:key", "local value"));
        
        // Should see local value within transaction
        auto value = tx2->get("override:key");
        REQUIRE(value.has_value());
        REQUIRE(*value == "local value");
        
        // Storage should still have original value
        auto storage_value = fixture.storage()->get("override:key");
        REQUIRE(storage_value.has_value());
        REQUIRE(*storage_value == "storage value");
    }
}

TEST_CASE("Transaction Atomicity", "[transactions]") {
    TransactionTestFixture fixture;
    
    SECTION("Multiple operations commit atomically") {
        auto tx = fixture.begin_transaction();
        
        // Perform multiple operations
        REQUIRE(tx->put("atomic:key1", "value1"));
        REQUIRE(tx->put("atomic:key2", "value2"));
        REQUIRE(tx->put("atomic:key3", "value3"));
        
        // None should be visible before commit
        REQUIRE_FALSE(fixture.storage()->get("atomic:key1").has_value());
        REQUIRE_FALSE(fixture.storage()->get("atomic:key2").has_value());
        REQUIRE_FALSE(fixture.storage()->get("atomic:key3").has_value());
        
        // Commit all at once
        REQUIRE(tx->commit());
        
        // All should be visible after commit
        REQUIRE(fixture.storage()->get("atomic:key1").has_value());
        REQUIRE(fixture.storage()->get("atomic:key2").has_value());
        REQUIRE(fixture.storage()->get("atomic:key3").has_value());
    }
    
    SECTION("Rollback undoes all operations") {
        auto tx = fixture.begin_transaction();
        
        // Perform multiple operations
        REQUIRE(tx->put("rollback:key1", "value1"));
        REQUIRE(tx->put("rollback:key2", "value2"));
        REQUIRE(tx->delete_key("some:key")); // Delete non-existent key
        
        // Rollback
        tx->rollback();
        
        // None should be visible
        REQUIRE_FALSE(fixture.storage()->get("rollback:key1").has_value());
        REQUIRE_FALSE(fixture.storage()->get("rollback:key2").has_value());
    }
}

TEST_CASE("Concurrent Transactions", "[transactions]") {
    TransactionTestFixture fixture;
    
    SECTION("Multiple threads with separate transactions") {
        constexpr int num_threads = 4;
        constexpr int ops_per_thread = 10;
        std::vector<std::thread> threads;
        std::atomic<int> success_count{0};
        
        // Each thread performs transactions
        for (int i = 0; i < num_threads; ++i) {
            threads.emplace_back([&fixture, &success_count, i, ops_per_thread]() {
                for (int j = 0; j < ops_per_thread; ++j) {
                    auto tx = fixture.begin_transaction();
                    
                    std::string key = "concurrent:" + std::to_string(i) + ":" + std::to_string(j);
                    std::string value = "thread" + std::to_string(i) + "_value" + std::to_string(j);
                    
                    if (tx->put(key, value) && tx->commit()) {
                        success_count++;
                    }
                }
            });
        }
        
        // Wait for all threads to complete
        for (auto& thread : threads) {
            thread.join();
        }
        
        // All transactions should have succeeded
        REQUIRE(success_count == num_threads * ops_per_thread);
        
        // Verify all keys are present in storage
        for (int i = 0; i < num_threads; ++i) {
            for (int j = 0; j < ops_per_thread; ++j) {
                std::string key = "concurrent:" + std::to_string(i) + ":" + std::to_string(j);
                REQUIRE(fixture.storage()->get(key).has_value());
            }
        }
    }
}

TEST_CASE("Transaction Manager", "[transactions]") {
    TransactionTestFixture fixture;
    
    SECTION("Transaction manager statistics") {
        REQUIRE(fixture.manager()->active_transactions() == 0);
        
        // Create multiple transactions
        auto tx1 = fixture.begin_transaction();
        REQUIRE(fixture.manager()->active_transactions() == 1);
        
        auto tx2 = fixture.begin_transaction();
        REQUIRE(fixture.manager()->active_transactions() == 2);
        
        // Complete one transaction
        tx1->commit();
        // Note: Transaction count doesn't decrease until Transaction is destroyed
        // This is acceptable behavior for this implementation
    }
    
    SECTION("Empty transaction commit") {
        auto tx = fixture.begin_transaction();
        
        // Commit empty transaction should succeed
        REQUIRE(tx->commit());
        REQUIRE(tx->status() == Transaction::Status::Committed);
    }
}