#include "network/streaming.hpp"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <chrono>
#include <future>
#include <shared_mutex>

namespace nosql_db::network {

// StreamingSession implementation
StreamingSession::StreamingSession(uint64_t stream_id)
    : StreamingSession(stream_id, StreamConfig{}) {
}

StreamingSession::StreamingSession(uint64_t stream_id, const StreamConfig& config)
    : stream_id_(stream_id), config_(config), should_stop_(false) {
    spdlog::debug("StreamingSession {} created with batch_size: {}, max_buffer: {}",
                 stream_id_, config_.batch_size, config_.max_buffer_size);
}

StreamingSession::~StreamingSession() {
    stop();
}

bool StreamingSession::start() {
    if (state_.load() != StreamState::IDLE) {
        return false;
    }
    
    state_.store(StreamState::ACTIVE);
    should_stop_.store(false);
    
    stream_thread_ = std::thread(&StreamingSession::stream_worker, this);
    
    spdlog::debug("StreamingSession {} started", stream_id_);
    return true;
}

bool StreamingSession::pause() {
    StreamState expected = StreamState::ACTIVE;
    return state_.compare_exchange_strong(expected, StreamState::PAUSED);
}

bool StreamingSession::resume() {
    StreamState expected = StreamState::PAUSED;
    if (state_.compare_exchange_strong(expected, StreamState::ACTIVE)) {
        queue_cv_.notify_all();
        return true;
    }
    return false;
}

bool StreamingSession::stop() {
    StreamState current = state_.load();
    if (current == StreamState::COMPLETED || current == StreamState::IDLE) {
        return true;
    }
    
    should_stop_.store(true);
    state_.store(StreamState::COMPLETED);
    queue_cv_.notify_all();
    
    if (stream_thread_.joinable()) {
        stream_thread_.join();
    }
    
    spdlog::debug("StreamingSession {} stopped", stream_id_);
    return true;
}

bool StreamingSession::add_data(const std::string& key, const std::string& value) {
    if (state_.load() == StreamState::COMPLETED || state_.load() == StreamState::ERROR) {
        return false;
    }
    
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        
        // Check buffer limits
        if (data_queue_.size() >= config_.max_buffer_size) {
            spdlog::warn("StreamingSession {} buffer full, dropping data", stream_id_);
            return false;
        }
        
        data_queue_.emplace(key, value);
        pending_count_.fetch_add(1);
        stats_.items_buffered.fetch_add(1);
    }
    
    queue_cv_.notify_one();
    return true;
}

bool StreamingSession::add_batch(const std::vector<std::pair<std::string, std::string>>& items) {
    if (state_.load() == StreamState::COMPLETED || state_.load() == StreamState::ERROR) {
        return false;
    }
    
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        
        // Check if we can fit all items
        if (data_queue_.size() + items.size() > config_.max_buffer_size) {
            spdlog::warn("StreamingSession {} cannot fit batch of {} items", stream_id_, items.size());
            return false;
        }
        
        for (const auto& [key, value] : items) {
            data_queue_.emplace(key, value);
        }
        
        pending_count_.fetch_add(items.size());
        stats_.items_buffered.fetch_add(items.size());
    }
    
    queue_cv_.notify_one();
    return true;
}

void StreamingSession::stream_worker() {
    spdlog::debug("Stream worker {} started", stream_id_);
    
    auto last_flush = std::chrono::steady_clock::now();
    
    while (!should_stop_.load()) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        
        // Wait for data or timeout
        queue_cv_.wait_for(lock, config_.flush_interval, [this] {
            return should_stop_.load() || !data_queue_.empty() || 
                   state_.load() == StreamState::ACTIVE;
        });
        
        if (should_stop_.load()) break;
        
        // Skip processing if paused
        if (state_.load() == StreamState::PAUSED) {
            continue;
        }
        
        auto now = std::chrono::steady_clock::now();
        bool should_flush = false;
        
        // Flush conditions
        if (data_queue_.size() >= config_.batch_size) {
            should_flush = true; // Batch size reached
        } else if (!data_queue_.empty() && (now - last_flush) >= config_.flush_interval) {
            should_flush = true; // Timeout reached
        }
        
        if (should_flush && !data_queue_.empty()) {
            lock.unlock();
            if (flush_batch()) {
                last_flush = now;
            }
        }
    }
    
    // Flush remaining data on shutdown
    std::unique_lock<std::mutex> lock(queue_mutex_);
    if (!data_queue_.empty()) {
        lock.unlock();
        flush_batch();
    }
    
    spdlog::debug("Stream worker {} finished", stream_id_);
}

bool StreamingSession::flush_batch() {
    std::vector<std::pair<std::string, std::string>> batch;
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        
        size_t batch_size = std::min(data_queue_.size(), config_.batch_size);
        batch.reserve(batch_size);
        
        for (size_t i = 0; i < batch_size && !data_queue_.empty(); ++i) {
            batch.push_back(std::move(data_queue_.front()));
            data_queue_.pop();
        }
        
        pending_count_.fetch_sub(batch.size());
    }
    
    if (batch.empty()) {
        return false;
    }
    
    // Create stream data message
    auto message = create_stream_data_message(batch);
    
    // Send via callback if available
    if (data_callback_) {
        bool success = data_callback_(message);
        if (success) {
            stats_.total_items_sent.fetch_add(batch.size());
            stats_.total_batches_sent.fetch_add(1);
            stats_.total_bytes_sent.fetch_add(message.total_size());
            stats_.flush_count.fetch_add(1);
        } else {
            spdlog::error("StreamingSession {} data callback failed", stream_id_);
            state_.store(StreamState::ERROR);
            return false;
        }
    }
    
    return true;
}

BinaryMessage StreamingSession::create_stream_data_message(
    const std::vector<std::pair<std::string, std::string>>& batch) {
    
    auto message = MessageBuilder::create_query_response(stream_id_, StatusCode::SUCCESS, batch);
    message.set_type(MessageType::STREAM_DATA);
    
    if (config_.enable_compression) {
        message.set_flag(MessageFlags::COMPRESSED);
    }
    
    return message;
}

// StreamingManager implementation
StreamingManager::StreamingManager() {
    spdlog::debug("StreamingManager initialized");
}

StreamingManager::~StreamingManager() {
    // Stop all active streams
    std::vector<uint64_t> active_ids;
    {
        std::shared_lock<std::shared_mutex> lock(streams_mutex_);
        for (const auto& [id, stream] : streams_) {
            active_ids.push_back(id);
        }
    }
    
    for (uint64_t id : active_ids) {
        stop_stream(id);
    }
}

uint64_t StreamingManager::create_stream() {
    return create_stream(StreamingSession::StreamConfig{});
}

uint64_t StreamingManager::create_stream(const StreamingSession::StreamConfig& config) {
    uint64_t stream_id = next_stream_id_.fetch_add(1);
    auto stream = std::make_shared<StreamingSession>(stream_id, config);
    
    {
        std::unique_lock<std::shared_mutex> lock(streams_mutex_);
        streams_[stream_id] = stream;
    }
    
    global_stats_.total_streams_created.fetch_add(1);
    spdlog::debug("Created stream {}", stream_id);
    return stream_id;
}

bool StreamingManager::start_stream(uint64_t stream_id) {
    auto stream = get_stream(stream_id);
    if (!stream) {
        return false;
    }
    
    if (stream->start()) {
        global_stats_.active_streams.fetch_add(1);
        return true;
    }
    
    return false;
}

bool StreamingManager::stop_stream(uint64_t stream_id) {
    auto stream = get_stream(stream_id);
    if (!stream) {
        return false;
    }
    
    if (stream->stop()) {
        global_stats_.active_streams.fetch_sub(1);
        global_stats_.completed_streams.fetch_add(1);
        return true;
    }
    
    return false;
}

bool StreamingManager::remove_stream(uint64_t stream_id) {
    stop_stream(stream_id);
    
    std::unique_lock<std::shared_mutex> lock(streams_mutex_);
    auto it = streams_.find(stream_id);
    if (it != streams_.end()) {
        streams_.erase(it);
        spdlog::debug("Removed stream {}", stream_id);
        return true;
    }
    
    return false;
}

bool StreamingManager::add_to_stream(uint64_t stream_id, const std::string& key, const std::string& value) {
    auto stream = get_stream(stream_id);
    if (!stream) {
        return false;
    }
    
    if (stream->add_data(key, value)) {
        global_stats_.total_items_streamed.fetch_add(1);
        return true;
    }
    
    return false;
}

bool StreamingManager::add_batch_to_stream(uint64_t stream_id, 
                                          const std::vector<std::pair<std::string, std::string>>& items) {
    auto stream = get_stream(stream_id);
    if (!stream) {
        return false;
    }
    
    if (stream->add_batch(items)) {
        global_stats_.total_items_streamed.fetch_add(items.size());
        return true;
    }
    
    return false;
}

std::shared_ptr<StreamingSession> StreamingManager::get_stream(uint64_t stream_id) {
    std::shared_lock<std::shared_mutex> lock(streams_mutex_);
    auto it = streams_.find(stream_id);
    return (it != streams_.end()) ? it->second : nullptr;
}

std::vector<uint64_t> StreamingManager::get_active_stream_ids() const {
    std::shared_lock<std::shared_mutex> lock(streams_mutex_);
    std::vector<uint64_t> active_ids;
    
    for (const auto& [id, stream] : streams_) {
        if (stream && stream->is_active()) {
            active_ids.push_back(id);
        }
    }
    
    return active_ids;
}

size_t StreamingManager::active_stream_count() const {
    return global_stats_.active_streams.load();
}

// BatchProcessor implementation  
namespace BatchOps {

BatchProcessor::BatchProcessor(std::shared_ptr<storage::StorageEngine> storage)
    : BatchProcessor(std::move(storage), BatchConfig{}) {
}

BatchProcessor::BatchProcessor(std::shared_ptr<storage::StorageEngine> storage, 
                              const BatchConfig& config)
    : config_(config), storage_(std::move(storage)), workers_running_(false) {
    
    if (!storage_) {
        throw std::invalid_argument("Storage engine cannot be null");
    }
    
    // Start worker threads if parallelization is enabled
    if (config_.enable_parallelization && config_.worker_threads > 0) {
        workers_running_.store(true);
        worker_threads_.reserve(config_.worker_threads);
        
        for (size_t i = 0; i < config_.worker_threads; ++i) {
            worker_threads_.emplace_back(&BatchProcessor::worker_loop, this);
        }
    }
    
    spdlog::debug("BatchProcessor initialized with {} worker threads", 
                 config_.enable_parallelization ? config_.worker_threads : 0);
}

BatchProcessor::~BatchProcessor() {
    workers_running_.store(false);
    work_cv_.notify_all();
    
    for (auto& worker : worker_threads_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

std::vector<BatchResult> BatchProcessor::execute_batch(const std::vector<BatchItem>& items) {
    auto start_time = std::chrono::steady_clock::now();
    std::vector<BatchResult> results;
    results.reserve(items.size());
    
    if (config_.enable_parallelization && items.size() > 10) {
        // Use async execution for large batches
        std::vector<std::future<BatchResult>> futures;
        futures.reserve(items.size());
        
        for (const auto& item : items) {
            auto promise = std::make_shared<std::promise<BatchResult>>();
            futures.push_back(promise->get_future());
            
            {
                std::lock_guard<std::mutex> lock(work_mutex_);
                work_queue_.push([this, item, promise]() {
                    auto result = execute_single_item(item);
                    promise->set_value(result);
                });
            }
            work_cv_.notify_one();
        }
        
        // Collect results
        for (auto& future : futures) {
            results.push_back(future.get());
        }
        
        // Reorder results if required
        if (config_.preserve_order) {
            // Results are already in order since we process futures sequentially
        }
    } else {
        // Sequential execution for small batches
        for (const auto& item : items) {
            results.push_back(execute_single_item(item));
        }
    }
    
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    stats_.batches_executed.fetch_add(1);
    stats_.items_processed.fetch_add(items.size());
    stats_.total_execution_time_us.fetch_add(duration.count());
    
    return results;
}

bool BatchProcessor::execute_batch_async(const std::vector<BatchItem>& items, BatchCallback callback) {
    if (!callback) {
        return false;
    }
    
    // Execute in background thread
    std::thread([this, items, callback = std::move(callback)]() {
        auto results = execute_batch(items);
        callback(std::move(results));
    }).detach();
    
    return true;
}

BatchResult BatchProcessor::execute_single_item(const BatchItem& item) {
    auto start_time = std::chrono::steady_clock::now();
    BatchResult result;
    result.status = StatusCode::SUCCESS;
    
    try {
        switch (item.type) {
            case BatchItem::PUT: {
                bool success = storage_->put(item.key, item.value);
                result.status = success ? StatusCode::SUCCESS : StatusCode::STORAGE_ERROR;
                break;
            }
            
            case BatchItem::GET: {
                auto value = storage_->get(item.key);
                if (value) {
                    result.status = StatusCode::SUCCESS;
                    result.value = *value;
                    stats_.cache_hits.fetch_add(1);
                } else {
                    result.status = StatusCode::KEY_NOT_FOUND;
                    stats_.cache_misses.fetch_add(1);
                }
                break;
            }
            
            case BatchItem::DELETE: {
                bool success = storage_->delete_key(item.key);
                result.status = success ? StatusCode::SUCCESS : StatusCode::KEY_NOT_FOUND;
                break;
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("BatchProcessor error processing item {}: {}", item.key, e.what());
        result.status = StatusCode::SERVER_ERROR;
    }
    
    auto end_time = std::chrono::steady_clock::now();
    result.execution_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    return result;
}

void BatchProcessor::worker_loop() {
    while (workers_running_.load()) {
        std::function<void()> task;
        
        {
            std::unique_lock<std::mutex> lock(work_mutex_);
            work_cv_.wait(lock, [this] { return !work_queue_.empty() || !workers_running_.load(); });
            
            if (!workers_running_.load()) break;
            
            if (!work_queue_.empty()) {
                task = std::move(work_queue_.front());
                work_queue_.pop();
            }
        }
        
        if (task) {
            task();
        }
    }
}

void BatchProcessor::reset_stats() {
    stats_.batches_executed.store(0);
    stats_.items_processed.store(0);
    stats_.total_execution_time_us.store(0);
    stats_.cache_hits.store(0);
    stats_.cache_misses.store(0);
}

} // namespace BatchOps

} // namespace nosql_db::network