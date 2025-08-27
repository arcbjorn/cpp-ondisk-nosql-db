#include "storage/lsm_tree.hpp"
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include <algorithm>
#include <chrono>
#include <map>

namespace ishikura::storage {

LSMTree::LSMTree(const std::filesystem::path& base_directory)
    : base_dir_(base_directory) {
    
    // Create base directory if it doesn't exist
    std::filesystem::create_directories(base_dir_);
    
    // Initialize level 0
    ensure_level_exists(0);
    
    // Create initial active segment
    active_segment_ = create_new_segment(0);
    
    spdlog::info("LSMTree initialized at: {}", base_dir_.string());
}

LSMTree::~LSMTree() {
    stop_compaction();
}

std::filesystem::path LSMTree::get_segment_path(uint32_t level, uint32_t segment_id) const {
    return base_dir_ / fmt::format("L{}_segment_{}.log", level, segment_id);
}

std::shared_ptr<LogStorage> LSMTree::create_new_segment(uint32_t level) {
    auto segment_id = next_segment_id_++;
    auto path = get_segment_path(level, segment_id);
    
    auto segment = std::make_shared<LogStorage>(path);
    if (!segment->is_open()) {
        spdlog::error("Failed to create segment: {}", path.string());
        return nullptr;
    }
    
    spdlog::debug("Created new segment: L{}_segment_{}", level, segment_id);
    return segment;
}

void LSMTree::ensure_level_exists(uint32_t level) {
    std::unique_lock lock(tree_mutex_);
    ensure_level_exists_unlocked(level);
}

void LSMTree::ensure_level_exists_unlocked(uint32_t level) {
    while (levels_.size() <= level) {
        uint64_t threshold = compaction_trigger_size_;
        for (size_t i = 0; i < levels_.size(); ++i) {
            threshold *= level_size_multiplier_;
        }
        
        levels_.push_back(std::make_unique<LevelInfo>(threshold));
        spdlog::debug("Created level {} with threshold {} bytes", levels_.size() - 1, threshold);
    }
}

bool LSMTree::put(std::string_view key, std::string_view value) {
    bool success;
    bool should_rotate = false;
    
    {
        std::shared_lock lock(tree_mutex_);
        
        if (!active_segment_ || !active_segment_->is_open()) {
            spdlog::error("No active segment available for write");
            return false;
        }
        
        success = active_segment_->append(key, value);
        if (success) {
            // Check if we need to rotate the active segment
            std::error_code ec;
            auto file_size = std::filesystem::file_size(active_segment_->get_file_path(), ec);
            
            if (!ec && file_size >= compaction_trigger_size_) {
                should_rotate = true;
            }
        }
    } // Release shared_lock here
    
    // Rotate outside of shared_lock to avoid deadlock
    if (should_rotate) {
        rotate_active_segment();
    }
    
    return success;
}

std::optional<std::string> LSMTree::get(std::string_view key) const {
    std::shared_lock lock(tree_mutex_);
    
    // Search from newest to oldest (L0 active segment first)
    if (active_segment_) {
        auto result = active_segment_->get(key);
        if (result && !is_tombstone(*result)) {
            return result;
        } else if (result && is_tombstone(*result)) {
            return std::nullopt; // Key was deleted
        }
    }
    
    // Search through all levels from L0 to highest level
    for (const auto& level : levels_) {
        // Search segments in reverse order (newest first within level)
        for (auto it = level->segments.rbegin(); it != level->segments.rend(); ++it) {
            auto result = (*it)->get(key);
            if (result) {
                if (is_tombstone(*result)) {
                    return std::nullopt; // Key was deleted
                }
                return result;
            }
        }
    }
    
    return std::nullopt; // Key not found
}

bool LSMTree::delete_key(std::string_view key) {
    // Use tombstone marker for deletion
    return put(key, "__DELETED__");
}

std::vector<Record> LSMTree::get_all() const {
    std::shared_lock lock(tree_mutex_);
    std::map<std::string, Record> merged_records;
    
    // Collect all records from all segments
    std::vector<std::vector<Record>> all_record_sets;
    
    // Add active segment records
    if (active_segment_) {
        all_record_sets.push_back(active_segment_->get_all());
    }
    
    // Add records from all levels
    for (const auto& level : levels_) {
        for (const auto& segment : level->segments) {
            all_record_sets.push_back(segment->get_all());
        }
    }
    
    // Merge records, keeping the latest version of each key
    auto merged = merge_records(all_record_sets);
    
    // Filter out tombstones
    std::vector<Record> result;
    for (const auto& record : merged) {
        if (!is_tombstone(record.value)) {
            result.push_back(record);
        }
    }
    
    return result;
}

void LSMTree::rotate_active_segment() {
    std::unique_lock lock(tree_mutex_);
    
    if (!active_segment_) return;
    
    // Move current active segment to L0
    ensure_level_exists_unlocked(0);
    levels_[0]->segments.push_back(active_segment_);
    levels_[0]->total_size += std::filesystem::file_size(active_segment_->get_file_path());
    
    // Create new active segment
    active_segment_ = create_new_segment(0);
    
    spdlog::debug("Rotated active segment to L0, created new active segment");
    
    // Check if L0 needs compaction (without acquiring lock since we already hold it)
    if (levels_.size() > 0 && 
        (levels_[0]->total_size >= levels_[0]->max_size_threshold ||
         levels_[0]->segments.size() >= 4)) {
        compaction_cv_.notify_one();
    }
}

void LSMTree::start_compaction() {
    if (compaction_running_.exchange(true)) {
        return; // Already running
    }
    
    compaction_thread_ = std::thread([this]() {
        compaction_worker();
    });
    
    spdlog::info("LSMTree compaction started");
}

void LSMTree::stop_compaction() {
    if (!compaction_running_.exchange(false)) {
        return; // Already stopped
    }
    
    compaction_cv_.notify_all();
    
    if (compaction_thread_.joinable()) {
        compaction_thread_.join();
    }
    
    spdlog::info("LSMTree compaction stopped");
}

void LSMTree::force_compaction() {
    if (compaction_running_) {
        // If background compaction is running, just notify
        std::lock_guard lock(compaction_mutex_);
        compaction_cv_.notify_one();
        spdlog::debug("Manual compaction triggered - notified background worker");
    } else {
        // If no background worker, perform compaction synchronously
        for (uint32_t level = 0; level < levels_.size(); ++level) {
            if (should_compact_level(level)) {
                compact_level(level);
                spdlog::debug("Manual compaction completed for level {}", level);
                break; // Only compact one level at a time
            }
        }
    }
}

void LSMTree::compaction_worker() {
    spdlog::info("Compaction worker thread started");
    
    while (compaction_running_) {
        std::unique_lock lock(compaction_mutex_);
        
        // Wait for compaction trigger or stop signal
        compaction_cv_.wait(lock, [this]() {
            if (!compaction_running_) return true;
            
            // Check if any level needs compaction without holding compaction_mutex_
            std::shared_lock tree_lock(tree_mutex_);
            for (size_t i = 0; i < levels_.size(); ++i) {
                const auto& level_info = levels_[i];
                if (level_info->total_size >= level_info->max_size_threshold ||
                    level_info->segments.size() >= 4) {
                    return true;
                }
            }
            return false;
        });
        
        if (!compaction_running_) break;
        
        // Find levels that need compaction
        for (uint32_t level = 0; level < levels_.size(); ++level) {
            if (should_compact_level(level)) {
                lock.unlock();
                compact_level(level);
                lock.lock();
                break; // Only compact one level at a time
            }
        }
    }
    
    spdlog::info("Compaction worker thread stopped");
}

bool LSMTree::should_compact_level(uint32_t level) const {
    std::shared_lock lock(tree_mutex_);
    
    if (level >= levels_.size()) return false;
    
    const auto& level_info = levels_[level];
    return level_info->total_size >= level_info->max_size_threshold ||
           level_info->segments.size() >= 4; // Also compact if too many segments
}

void LSMTree::compact_level(uint32_t level) {
    spdlog::info("Starting compaction of level {}", level);
    auto start_time = std::chrono::steady_clock::now();
    
    std::vector<std::shared_ptr<LogStorage>> segments_to_compact;
    uint64_t total_bytes_before = 0;
    
    {
        std::shared_lock lock(tree_mutex_);
        if (level >= levels_.size()) return;
        
        segments_to_compact = levels_[level]->segments;
        for (const auto& segment : segments_to_compact) {
            total_bytes_before += std::filesystem::file_size(segment->get_file_path());
        }
    }
    
    if (segments_to_compact.empty()) return;
    
    // Merge segments
    auto merged_segment = merge_segments(segments_to_compact, level + 1);
    if (!merged_segment) {
        spdlog::error("Failed to merge segments for level {}", level);
        return;
    }
    
    // Atomically update the tree structure
    {
        std::unique_lock lock(tree_mutex_);
        
        // Ensure target level exists
        ensure_level_exists_unlocked(level + 1);
        
        // Remove old segments from current level
        levels_[level]->segments.clear();
        levels_[level]->total_size = 0;
        
        // Add merged segment to next level
        uint64_t merged_size = std::filesystem::file_size(merged_segment->get_file_path());
        levels_[level + 1]->segments.push_back(merged_segment);
        levels_[level + 1]->total_size += merged_size;
        
        // Update statistics
        stats_.compactions_completed++;
        stats_.bytes_compacted += total_bytes_before;
        
        spdlog::info("Compacted level {} - {} segments -> 1 segment, {} -> {} bytes",
                    level, segments_to_compact.size(), total_bytes_before, merged_size);
    }
    
    // Clean up old segment files
    cleanup_old_segments(segments_to_compact);
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    spdlog::info("Level {} compaction completed in {}ms", level, duration.count());
}

std::shared_ptr<LogStorage> LSMTree::merge_segments(const std::vector<std::shared_ptr<LogStorage>>& segments, uint32_t target_level) {
    auto merged_segment = create_new_segment(target_level);
    if (!merged_segment) return nullptr;
    
    // Collect all records from segments
    std::vector<std::vector<Record>> record_sets;
    for (const auto& segment : segments) {
        record_sets.push_back(segment->get_all());
    }
    
    // Merge and deduplicate records
    auto merged_records = merge_records(record_sets);
    
    // Write merged records to new segment
    uint64_t tombstones_removed = 0;
    uint64_t duplicates_merged = 0;
    
    for (const auto& record : merged_records) {
        if (is_tombstone(record.value)) {
            tombstones_removed++;
            // Skip tombstones during compaction (garbage collection)
            continue;
        }
        
        if (!merged_segment->append(record.key, record.value)) {
            spdlog::error("Failed to write record during compaction");
            return nullptr;
        }
    }
    
    // Update statistics
    stats_.tombstones_removed += tombstones_removed;
    stats_.duplicate_keys_merged += duplicates_merged;
    
    spdlog::debug("Merged {} segments: removed {} tombstones, {} total records",
                 segments.size(), tombstones_removed, merged_records.size());
    
    return merged_segment;
}

std::vector<Record> LSMTree::merge_records(const std::vector<std::vector<Record>>& record_sets) const {
    std::map<std::string, Record> latest_records;
    
    // Process record sets in reverse order (newest first)
    for (auto it = record_sets.rbegin(); it != record_sets.rend(); ++it) {
        for (const auto& record : *it) {
            auto existing = latest_records.find(record.key);
            if (existing == latest_records.end() || record.timestamp > existing->second.timestamp) {
                latest_records[record.key] = record;
            }
        }
    }
    
    // Convert to vector and sort by key for consistent ordering
    std::vector<Record> result;
    result.reserve(latest_records.size());
    
    for (const auto& [key, record] : latest_records) {
        result.push_back(record);
    }
    
    return result;
}

void LSMTree::cleanup_old_segments(const std::vector<std::shared_ptr<LogStorage>>& old_segments) {
    for (const auto& segment : old_segments) {
        std::error_code ec;
        std::filesystem::remove(segment->get_file_path(), ec);
        if (ec) {
            spdlog::warn("Failed to remove old segment file: {} - {}", 
                        segment->get_file_path().string(), ec.message());
        }
    }
}

size_t LSMTree::get_level_count() const {
    std::shared_lock lock(tree_mutex_);
    return levels_.size();
}

uint64_t LSMTree::get_total_size() const {
    std::shared_lock lock(tree_mutex_);
    uint64_t total = 0;
    
    // Add active segment size
    if (active_segment_) {
        std::error_code ec;
        total += std::filesystem::file_size(active_segment_->get_file_path(), ec);
    }
    
    // Add all level sizes
    for (const auto& level : levels_) {
        total += level->total_size;
    }
    
    return total;
}

} // namespace ishikura::storage