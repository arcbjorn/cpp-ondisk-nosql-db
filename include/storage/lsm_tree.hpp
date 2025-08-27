#pragma once

#include "storage/log_storage.hpp"
#include <filesystem>
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <string>
#include <unordered_set>

namespace ishikura::storage {

/**
 * LSMTree implements a Log-Structured Merge Tree for efficient storage
 * with background compaction to manage space and performance.
 * 
 * Key features:
 * - Multiple levels (L0, L1, L2...) with size-tiered compaction
 * - Background compaction thread for garbage collection
 * - Tombstone removal and duplicate key elimination
 * - Concurrent compaction with ongoing reads/writes
 */
class LSMTree {
public:
    struct CompactionStats {
        std::atomic<uint64_t> compactions_completed{0};
        std::atomic<uint64_t> bytes_compacted{0};
        std::atomic<uint64_t> tombstones_removed{0};
        std::atomic<uint64_t> duplicate_keys_merged{0};
        
        // Convert to non-atomic struct for safe copying
        struct Snapshot {
            uint64_t compactions_completed;
            uint64_t bytes_compacted;
            uint64_t tombstones_removed;
            uint64_t duplicate_keys_merged;
        };
        
        Snapshot get_snapshot() const {
            return {
                compactions_completed.load(),
                bytes_compacted.load(),
                tombstones_removed.load(),
                duplicate_keys_merged.load()
            };
        }
    };

    explicit LSMTree(const std::filesystem::path& base_directory);
    ~LSMTree();

    // Disable copy construction/assignment (LSMTree manages resources)
    LSMTree(const LSMTree&) = delete;
    LSMTree& operator=(const LSMTree&) = delete;

    // Storage operations (thread-safe)
    bool put(std::string_view key, std::string_view value);
    std::optional<std::string> get(std::string_view key) const;
    bool delete_key(std::string_view key);
    std::vector<Record> get_all() const;
    
    // Compaction control
    void start_compaction();
    void stop_compaction();
    void force_compaction(); // Manual trigger
    
    // Statistics and monitoring
    CompactionStats::Snapshot get_stats() const { return stats_.get_snapshot(); }
    size_t get_level_count() const;
    uint64_t get_total_size() const;
    
    // Configuration
    void set_compaction_trigger_size(uint64_t bytes) { compaction_trigger_size_ = bytes; }
    void set_max_level_size_multiplier(uint64_t multiplier) { level_size_multiplier_ = multiplier; }

private:
    struct LevelInfo {
        std::vector<std::shared_ptr<LogStorage>> segments;
        uint64_t total_size{0};
        uint64_t max_size_threshold{0};
        
        LevelInfo(uint64_t threshold) : max_size_threshold(threshold) {}
    };

    std::filesystem::path base_dir_;
    std::vector<std::unique_ptr<LevelInfo>> levels_;
    
    // Current active segment for writes (L0)
    std::shared_ptr<LogStorage> active_segment_;
    std::atomic<uint32_t> next_segment_id_{0};
    
    // Compaction management
    std::atomic<bool> compaction_running_{false};
    std::thread compaction_thread_;
    mutable std::mutex compaction_mutex_;
    std::condition_variable compaction_cv_;
    
    // Statistics
    mutable CompactionStats stats_;
    
    // Configuration
    uint64_t compaction_trigger_size_{1024 * 1024}; // 1MB default
    uint64_t level_size_multiplier_{10}; // Each level 10x larger than previous
    
    // Thread safety for reads/writes
    mutable std::shared_mutex tree_mutex_;
    
    // Internal methods
    std::filesystem::path get_segment_path(uint32_t level, uint32_t segment_id) const;
    std::shared_ptr<LogStorage> create_new_segment(uint32_t level);
    void rotate_active_segment();
    
    // Compaction implementation
    void compaction_worker();
    void compact_level(uint32_t level);
    std::shared_ptr<LogStorage> merge_segments(const std::vector<std::shared_ptr<LogStorage>>& segments, uint32_t target_level);
    void cleanup_old_segments(const std::vector<std::shared_ptr<LogStorage>>& old_segments);
    
    // Level management
    void ensure_level_exists(uint32_t level);
    void ensure_level_exists_unlocked(uint32_t level); // Must hold tree_mutex_
    bool should_compact_level(uint32_t level) const;
    void promote_segment_to_next_level(std::shared_ptr<LogStorage> segment, uint32_t from_level);
    
    // Helper methods
    std::vector<Record> merge_records(const std::vector<std::vector<Record>>& record_sets) const;
    bool is_tombstone(const std::string& value) const { return value == "__DELETED__"; }
};

} // namespace ishikura::storage