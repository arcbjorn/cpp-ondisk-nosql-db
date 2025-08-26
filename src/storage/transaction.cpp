#include "storage/transaction.hpp"
#include "storage/log_storage.hpp"
#include <spdlog/spdlog.h>
#include <stdexcept>

namespace nosql_db::storage {

// Transaction Implementation

Transaction::Transaction(std::shared_ptr<LogStorage> storage)
    : storage_(std::move(storage)), status_(Status::Active) {
    spdlog::debug("Transaction created");
}

Transaction::~Transaction() {
    if (status_ == Status::Active) {
        spdlog::warn("Transaction destroyed without commit/rollback - auto-rolling back");
        rollback();
    }
}

void Transaction::ensure_active() const {
    if (status_ != Status::Active) {
        throw std::runtime_error("Operation on inactive transaction");
    }
}

bool Transaction::put(std::string_view key, std::string_view value) {
    std::unique_lock lock(lock_);
    ensure_active();
    
    if (key.empty()) {
        spdlog::warn("Transaction PUT: empty key rejected");
        return false;
    }
    
    // Store operation in transaction buffer
    operations_[std::string(key)] = {
        Operation::Put,
        std::string(key),
        std::string(value)
    };
    
    spdlog::debug("Transaction PUT: key='{}', value_size={}", key, value.size());
    return true;
}

std::optional<std::string> Transaction::get(std::string_view key) const {
    std::shared_lock lock(lock_);
    ensure_active();
    
    // Check transaction-local changes first
    auto it = operations_.find(std::string(key));
    if (it != operations_.end()) {
        if (it->second.type == Operation::Delete) {
            return std::nullopt; // Key was deleted in this transaction
        } else {
            return it->second.value; // Return modified value
        }
    }
    
    // Fall back to committed storage
    return storage_->get(key);
}

bool Transaction::delete_key(std::string_view key) {
    std::unique_lock lock(lock_);
    ensure_active();
    
    if (key.empty()) {
        spdlog::warn("Transaction DELETE: empty key rejected");
        return false;
    }
    
    // Store delete operation in transaction buffer
    operations_[std::string(key)] = {
        Operation::Delete,
        std::string(key),
        "" // Empty value for deletes
    };
    
    spdlog::debug("Transaction DELETE: key='{}'", key);
    return true;
}

bool Transaction::commit() {
    std::unique_lock lock(lock_);
    ensure_active();
    
    if (operations_.empty()) {
        // Empty transaction - nothing to commit
        status_ = Status::Committed;
        spdlog::debug("Transaction committed (empty)");
        return true;
    }
    
    // Apply all operations atomically
    bool success = apply_operations();
    
    if (success) {
        status_ = Status::Committed;
        spdlog::info("Transaction committed with {} operations", operations_.size());
    } else {
        status_ = Status::Aborted;
        spdlog::error("Transaction commit failed - rolled back");
    }
    
    return success;
}

void Transaction::rollback() {
    std::unique_lock lock(lock_);
    
    if (status_ != Status::Active) {
        return; // Already committed or aborted
    }
    
    status_ = Status::Aborted;
    operations_.clear();
    
    spdlog::info("Transaction rolled back");
}

bool Transaction::apply_operations() {
    // Apply operations in deterministic order (sorted by key)
    // This helps prevent deadlocks in fine-grained locking scenarios
    
    std::vector<std::pair<std::string, Operation*>> sorted_ops;
    for (auto& [key, op] : operations_) {
        sorted_ops.emplace_back(key, &op);
    }
    std::sort(sorted_ops.begin(), sorted_ops.end());
    
    // Apply each operation to storage
    for (const auto& [key, op] : sorted_ops) {
        bool success = false;
        
        if (op->type == Operation::Put) {
            success = storage_->append(op->key, op->value);
        } else { // Delete
            success = storage_->append(op->key, "__DELETED__");
        }
        
        if (!success) {
            spdlog::error("Failed to apply transaction operation: key='{}'", op->key);
            return false;
        }
    }
    
    // Ensure durability by syncing to disk
    storage_->sync();
    return true;
}

// TransactionManager Implementation

TransactionManager::TransactionManager(std::shared_ptr<LogStorage> storage)
    : storage_(std::move(storage)) {
    spdlog::info("TransactionManager initialized");
}

std::unique_ptr<Transaction> TransactionManager::begin_transaction() {
    std::lock_guard lock(transactions_mutex_);
    ++active_count_;
    
    spdlog::debug("Transaction started (active: {})", active_count_);
    return std::make_unique<Transaction>(storage_);
}

size_t TransactionManager::active_transactions() const {
    std::lock_guard lock(transactions_mutex_);
    return active_count_;
}

std::shared_lock<std::shared_mutex> TransactionManager::acquire_read_lock() const {
    return std::shared_lock<std::shared_mutex>(storage_lock_);
}

std::unique_lock<std::shared_mutex> TransactionManager::acquire_write_lock() const {
    return std::unique_lock<std::shared_mutex>(storage_lock_);
}

} // namespace nosql_db::storage