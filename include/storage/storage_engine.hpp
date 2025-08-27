#pragma once

#include "storage/lsm_tree.hpp"
#include "storage/transaction.hpp"
#include <memory>
#include <filesystem>

namespace ishikura::storage {

/**
 * StorageEngine provides a unified interface to the storage layer
 * with LSM-Tree optimization and transaction support.
 * 
 * This class serves as the main storage interface, coordinating
 * between LSM-Tree compaction and transaction management.
 */
class StorageEngine {
public:
    enum class EngineType {
        SimpleLog,  // Basic LogStorage (original implementation)
        LSMTree     // LSM-Tree with compaction (optimized)
    };

    explicit StorageEngine(const std::filesystem::path& data_directory, 
                          EngineType type = EngineType::LSMTree);
    ~StorageEngine();

    // Disable copy construction/assignment
    StorageEngine(const StorageEngine&) = delete;
    StorageEngine& operator=(const StorageEngine&) = delete;

    // Storage operations
    bool put(std::string_view key, std::string_view value);
    std::optional<std::string> get(std::string_view key) const;
    bool delete_key(std::string_view key);
    std::vector<Record> get_all() const;
    
    // Transaction support
    std::unique_ptr<Transaction> begin_transaction();
    
    // Engine management
    void start_compaction();
    void stop_compaction();
    void force_compaction();
    
    // Statistics and monitoring
    struct EngineStats {
        uint64_t total_puts{0};
        uint64_t total_gets{0};
        uint64_t total_deletes{0};
        uint64_t cache_hits{0};
        uint64_t cache_misses{0};
        LSMTree::CompactionStats::Snapshot compaction;
    };
    
    EngineStats get_stats() const;
    EngineType get_engine_type() const { return engine_type_; }
    uint64_t get_total_size() const;
    
    // Configuration
    void enable_write_cache(bool enable) { write_cache_enabled_ = enable; }
    void set_compaction_trigger_size(uint64_t bytes);

private:
    EngineType engine_type_;
    std::filesystem::path data_dir_;
    
    // Storage backends
    std::unique_ptr<LSMTree> lsm_tree_;
    std::shared_ptr<LogStorage> simple_log_; // Fallback for SimpleLog mode
    
    // Transaction management
    std::unique_ptr<TransactionManager> transaction_manager_;
    
    // Statistics
    mutable EngineStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Configuration
    std::atomic<bool> write_cache_enabled_{true};
    
    // Helper methods
    void update_stats_get() const;
    void update_stats_put() const;
    void update_stats_delete() const;
};

} // namespace ishikura::storage