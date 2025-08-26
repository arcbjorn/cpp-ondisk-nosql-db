#include "storage/storage_engine.hpp"
#include <spdlog/spdlog.h>

namespace nosql_db::storage {

StorageEngine::StorageEngine(const std::filesystem::path& data_directory, EngineType type)
    : engine_type_(type), data_dir_(data_directory) {
    
    // Create data directory if it doesn't exist
    std::filesystem::create_directories(data_dir_);
    
    switch (engine_type_) {
        case EngineType::LSMTree: {
            auto lsm_dir = data_dir_ / "lsm";
            lsm_tree_ = std::make_unique<LSMTree>(lsm_dir);
            
            // Use LSMTree as the underlying storage for transactions
            // For now, we'll use a simple LogStorage for transaction coordination
            // In a full implementation, we'd integrate LSMTree directly with transactions
            auto tx_log = data_dir_ / "transactions.log";
            simple_log_ = std::make_shared<LogStorage>(tx_log);
            transaction_manager_ = std::make_unique<TransactionManager>(simple_log_);
            
            spdlog::info("StorageEngine initialized with LSM-Tree backend");
            break;
        }
        
        case EngineType::SimpleLog: {
            auto log_file = data_dir_ / "simple.log";
            simple_log_ = std::make_shared<LogStorage>(log_file);
            transaction_manager_ = std::make_unique<TransactionManager>(simple_log_);
            
            spdlog::info("StorageEngine initialized with SimpleLog backend");
            break;
        }
    }
}

StorageEngine::~StorageEngine() {
    stop_compaction();
}

bool StorageEngine::put(std::string_view key, std::string_view value) {
    update_stats_put();
    
    switch (engine_type_) {
        case EngineType::LSMTree:
            return lsm_tree_->put(key, value);
            
        case EngineType::SimpleLog:
            return simple_log_->append(key, value);
    }
    
    return false;
}

std::optional<std::string> StorageEngine::get(std::string_view key) const {
    update_stats_get();
    
    switch (engine_type_) {
        case EngineType::LSMTree:
            return lsm_tree_->get(key);
            
        case EngineType::SimpleLog:
            return simple_log_->get(key);
    }
    
    return std::nullopt;
}

bool StorageEngine::delete_key(std::string_view key) {
    update_stats_delete();
    
    switch (engine_type_) {
        case EngineType::LSMTree:
            return lsm_tree_->delete_key(key);
            
        case EngineType::SimpleLog:
            return simple_log_->append(key, "__DELETED__");
    }
    
    return false;
}

std::vector<Record> StorageEngine::get_all() const {
    switch (engine_type_) {
        case EngineType::LSMTree:
            return lsm_tree_->get_all();
            
        case EngineType::SimpleLog:
            return simple_log_->get_all();
    }
    
    return {};
}

std::unique_ptr<Transaction> StorageEngine::begin_transaction() {
    return transaction_manager_->begin_transaction();
}

void StorageEngine::start_compaction() {
    if (engine_type_ == EngineType::LSMTree && lsm_tree_) {
        lsm_tree_->start_compaction();
        spdlog::info("StorageEngine: LSM-Tree compaction started");
    }
}

void StorageEngine::stop_compaction() {
    if (engine_type_ == EngineType::LSMTree && lsm_tree_) {
        lsm_tree_->stop_compaction();
        spdlog::info("StorageEngine: LSM-Tree compaction stopped");
    }
}

void StorageEngine::force_compaction() {
    if (engine_type_ == EngineType::LSMTree && lsm_tree_) {
        lsm_tree_->force_compaction();
        spdlog::debug("StorageEngine: LSM-Tree compaction forced");
    }
}

StorageEngine::EngineStats StorageEngine::get_stats() const {
    std::lock_guard lock(stats_mutex_);
    auto stats = stats_;
    
    if (engine_type_ == EngineType::LSMTree && lsm_tree_) {
        stats.compaction = lsm_tree_->get_stats();
    }
    
    return stats;
}

uint64_t StorageEngine::get_total_size() const {
    switch (engine_type_) {
        case EngineType::LSMTree:
            return lsm_tree_ ? lsm_tree_->get_total_size() : 0;
            
        case EngineType::SimpleLog: {
            if (!simple_log_) return 0;
            
            std::error_code ec;
            return std::filesystem::file_size(simple_log_->get_file_path(), ec);
        }
    }
    
    return 0;
}

void StorageEngine::set_compaction_trigger_size(uint64_t bytes) {
    if (engine_type_ == EngineType::LSMTree && lsm_tree_) {
        lsm_tree_->set_compaction_trigger_size(bytes);
    }
}

void StorageEngine::update_stats_get() const {
    std::lock_guard lock(stats_mutex_);
    stats_.total_gets++;
}

void StorageEngine::update_stats_put() const {
    std::lock_guard lock(stats_mutex_);
    stats_.total_puts++;
}

void StorageEngine::update_stats_delete() const {
    std::lock_guard lock(stats_mutex_);
    stats_.total_deletes++;
}

} // namespace nosql_db::storage