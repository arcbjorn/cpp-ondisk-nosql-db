#pragma once

#include "network/binary_protocol.hpp"
#include "storage/storage_engine.hpp"
#include <memory>
#include <vector>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <thread>
#include <unordered_map>

namespace nosql_db::network {

/**
 * Streaming operations for large result sets and real-time data
 */

class StreamingSession {
public:
    enum class StreamState {
        IDLE,
        ACTIVE,
        PAUSED,
        COMPLETED,
        ERROR
    };
    
    struct StreamConfig {
        size_t batch_size = 100;           // Items per batch
        size_t max_buffer_size = 1000;    // Max items to buffer
        std::chrono::milliseconds flush_interval{100}; // Auto-flush interval
        bool enable_compression = false;
        bool ordered_delivery = true;
    };

    StreamingSession(uint64_t stream_id);
    StreamingSession(uint64_t stream_id, const StreamConfig& config);
    ~StreamingSession();

    // Stream control
    bool start();
    bool pause();
    bool resume();
    bool stop();
    
    // Data operations
    bool add_data(const std::string& key, const std::string& value);
    bool add_batch(const std::vector<std::pair<std::string, std::string>>& items);
    size_t pending_items() const { return pending_count_.load(); }
    
    // Stream state
    uint64_t stream_id() const { return stream_id_; }
    StreamState state() const { return state_.load(); }
    bool is_active() const { return state_.load() == StreamState::ACTIVE; }
    
    // Statistics
    struct StreamStats {
        std::atomic<uint64_t> total_items_sent{0};
        std::atomic<uint64_t> total_batches_sent{0};
        std::atomic<uint64_t> total_bytes_sent{0};
        std::atomic<uint64_t> items_buffered{0};
        std::atomic<uint64_t> flush_count{0};
    };
    
    const StreamStats& stats() const { return stats_; }
    
    // Callbacks for data delivery
    using DataCallback = std::function<bool(const BinaryMessage&)>;
    void set_data_callback(DataCallback callback) { data_callback_ = std::move(callback); }

private:
    uint64_t stream_id_;
    StreamConfig config_;
    std::atomic<StreamState> state_{StreamState::IDLE};
    std::atomic<size_t> pending_count_{0};
    
    // Data buffer
    std::queue<std::pair<std::string, std::string>> data_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    
    // Streaming thread
    std::thread stream_thread_;
    std::atomic<bool> should_stop_{false};
    
    // Statistics
    StreamStats stats_;
    
    // Data delivery
    DataCallback data_callback_;
    
    // Internal methods
    void stream_worker();
    bool flush_batch();
    BinaryMessage create_stream_data_message(const std::vector<std::pair<std::string, std::string>>& batch);
};

/**
 * Streaming manager for handling multiple concurrent streams
 */
class StreamingManager {
public:
    StreamingManager();
    ~StreamingManager();

    // Stream lifecycle
    uint64_t create_stream();
    uint64_t create_stream(const StreamingSession::StreamConfig& config);
    bool start_stream(uint64_t stream_id);
    bool stop_stream(uint64_t stream_id);
    bool remove_stream(uint64_t stream_id);
    
    // Stream operations
    bool add_to_stream(uint64_t stream_id, const std::string& key, const std::string& value);
    bool add_batch_to_stream(uint64_t stream_id, const std::vector<std::pair<std::string, std::string>>& items);
    
    // Stream management
    std::shared_ptr<StreamingSession> get_stream(uint64_t stream_id);
    std::vector<uint64_t> get_active_stream_ids() const;
    size_t active_stream_count() const;
    
    // Global statistics
    struct GlobalStreamStats {
        std::atomic<uint64_t> total_streams_created{0};
        std::atomic<uint64_t> active_streams{0};
        std::atomic<uint64_t> completed_streams{0};
        std::atomic<uint64_t> failed_streams{0};
        std::atomic<uint64_t> total_items_streamed{0};
        std::atomic<uint64_t> total_bytes_streamed{0};
    };
    
    const GlobalStreamStats& stats() const { return global_stats_; }

private:
    std::unordered_map<uint64_t, std::shared_ptr<StreamingSession>> streams_;
    mutable std::shared_mutex streams_mutex_;
    std::atomic<uint64_t> next_stream_id_{1};
    
    GlobalStreamStats global_stats_;
};

/**
 * Batch operation utilities for high-throughput scenarios
 */
namespace BatchOps {

struct BatchItem {
    enum Type { PUT, GET, DELETE } type;
    std::string key;
    std::string value; // Only used for PUT operations
    
    BatchItem(Type t, std::string k, std::string v = "") 
        : type(t), key(std::move(k)), value(std::move(v)) {}
};

struct BatchResult {
    StatusCode status;
    std::string value; // Only set for GET operations
    std::chrono::microseconds execution_time{0};
};

/**
 * High-performance batch processor
 */
class BatchProcessor {
public:
    struct BatchConfig {
        size_t max_batch_size = 1000;
        std::chrono::milliseconds timeout{5000}; // 5 seconds
        bool enable_parallelization = true;
        size_t worker_threads = std::thread::hardware_concurrency();
        bool preserve_order = false;
    };

    explicit BatchProcessor(std::shared_ptr<storage::StorageEngine> storage);
    explicit BatchProcessor(std::shared_ptr<storage::StorageEngine> storage, 
                          const BatchConfig& config);
    ~BatchProcessor();

    // Batch operations
    std::vector<BatchResult> execute_batch(const std::vector<BatchItem>& items);
    
    // Async batch operations
    using BatchCallback = std::function<void(std::vector<BatchResult>)>;
    bool execute_batch_async(const std::vector<BatchItem>& items, BatchCallback callback);
    
    // Statistics
    struct BatchStats {
        std::atomic<uint64_t> batches_executed{0};
        std::atomic<uint64_t> items_processed{0};
        std::atomic<uint64_t> total_execution_time_us{0};
        std::atomic<uint64_t> cache_hits{0};
        std::atomic<uint64_t> cache_misses{0};
    };
    
    const BatchStats& stats() const { return stats_; }
    void reset_stats();
    
    // Configuration
    const BatchConfig& config() const { return config_; }

private:
    BatchConfig config_;
    std::shared_ptr<storage::StorageEngine> storage_;
    
    // Worker thread pool
    std::vector<std::thread> worker_threads_;
    std::queue<std::function<void()>> work_queue_;
    std::mutex work_mutex_;
    std::condition_variable work_cv_;
    std::atomic<bool> workers_running_{false};
    
    BatchStats stats_;
    
    void worker_loop();
    BatchResult execute_single_item(const BatchItem& item);
};

} // namespace BatchOps

} // namespace nosql_db::network