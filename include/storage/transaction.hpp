#pragma once

#include <string>
#include <string_view>
#include <optional>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <shared_mutex>

namespace nosql_db::storage {

class LogStorage;

/**
 * Transaction provides ACID guarantees for database operations.
 * 
 * Features:
 * - Atomicity: All operations commit together or rollback
 * - Consistency: Transactions maintain database invariants
 * - Isolation: Concurrent transactions don't interfere
 * - Durability: Committed changes survive crashes
 */
class Transaction {
public:
    enum class Status {
        Active,      // Transaction is ongoing
        Committed,   // Transaction has been committed
        Aborted      // Transaction has been rolled back
    };

    explicit Transaction(std::shared_ptr<LogStorage> storage);
    ~Transaction();

    // Disable copy construction/assignment (transactions are unique)
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    
    // Enable move construction/assignment
    Transaction(Transaction&&) = default;
    Transaction& operator=(Transaction&&) = default;

    // Transaction operations
    bool put(std::string_view key, std::string_view value);
    std::optional<std::string> get(std::string_view key) const;
    bool delete_key(std::string_view key);
    
    // Transaction lifecycle
    bool commit();
    void rollback();
    
    // Transaction status
    Status status() const { return status_; }
    bool is_active() const { return status_ == Status::Active; }

private:
    struct Operation {
        enum Type { Put, Delete };
        Type type;
        std::string key;
        std::string value;  // Empty for deletes
    };

    std::shared_ptr<LogStorage> storage_;
    Status status_;
    
    // Transaction-local changes (not yet committed)
    std::unordered_map<std::string, Operation> operations_;
    
    // Lock management
    mutable std::shared_mutex lock_;
    
    // Helper methods
    void ensure_active() const;
    bool apply_operations();
};

/**
 * TransactionManager coordinates multiple transactions and handles
 * concurrency control with coarse-grained locking.
 */
class TransactionManager {
public:
    explicit TransactionManager(std::shared_ptr<LogStorage> storage);
    
    // Create a new transaction
    std::unique_ptr<Transaction> begin_transaction();
    
    // Get statistics
    size_t active_transactions() const;

private:
    std::shared_ptr<LogStorage> storage_;
    
    // Coarse-grained storage lock for now
    // TODO: Implement fine-grained locking later
    mutable std::shared_mutex storage_lock_;
    
    // Transaction tracking
    mutable std::mutex transactions_mutex_;
    size_t active_count_{0};
    
    friend class Transaction;
    
    // Lock acquisition methods for transactions
    std::shared_lock<std::shared_mutex> acquire_read_lock() const;
    std::unique_lock<std::shared_mutex> acquire_write_lock() const;
};

} // namespace nosql_db::storage