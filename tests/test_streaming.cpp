#include <catch2/catch_test_macros.hpp>
#include "network/streaming.hpp"
#include "storage/storage_engine.hpp"
#include <thread>
#include <chrono>
#include <filesystem>

using namespace nosql_db::network;
using namespace nosql_db::storage;

TEST_CASE("StreamingSession - Basic Functionality", "[network][streaming]") {
    StreamingSession::StreamConfig config;
    config.batch_size = 5;
    config.max_buffer_size = 20;
    config.flush_interval = std::chrono::milliseconds(100);
    
    StreamingSession session(1, config);
    
    SECTION("Initial state") {
        REQUIRE(session.stream_id() == 1);
        REQUIRE(session.state() == StreamingSession::StreamState::IDLE);
        REQUIRE_FALSE(session.is_active());
        REQUIRE(session.pending_items() == 0);
    }
    
    SECTION("State transitions") {
        REQUIRE(session.start());
        REQUIRE(session.state() == StreamingSession::StreamState::ACTIVE);
        REQUIRE(session.is_active());
        
        REQUIRE(session.pause());
        REQUIRE(session.state() == StreamingSession::StreamState::PAUSED);
        REQUIRE_FALSE(session.is_active());
        
        REQUIRE(session.resume());
        REQUIRE(session.state() == StreamingSession::StreamState::ACTIVE);
        REQUIRE(session.is_active());
        
        REQUIRE(session.stop());
        REQUIRE(session.state() == StreamingSession::StreamState::COMPLETED);
        REQUIRE_FALSE(session.is_active());
    }
    
    SECTION("Data addition") {
        REQUIRE(session.start());
        
        REQUIRE(session.add_data("key1", "value1"));
        REQUIRE(session.pending_items() == 1);
        
        std::vector<std::pair<std::string, std::string>> batch = {
            {"key2", "value2"},
            {"key3", "value3"},
            {"key4", "value4"}
        };
        
        REQUIRE(session.add_batch(batch));
        REQUIRE(session.pending_items() == 4); // 1 + 3
        
        session.stop();
    }
    
    SECTION("Buffer overflow protection") {
        REQUIRE(session.start());
        
        // Fill buffer to capacity
        for (size_t i = 0; i < config.max_buffer_size; ++i) {
            std::string key = "key" + std::to_string(i);
            std::string value = "value" + std::to_string(i);
            REQUIRE(session.add_data(key, value));
        }
        
        // Next addition should fail
        REQUIRE_FALSE(session.add_data("overflow", "data"));
        
        session.stop();
    }
}

TEST_CASE("StreamingSession - Data Callback", "[network][streaming]") {
    StreamingSession::StreamConfig config;
    config.batch_size = 3;
    config.flush_interval = std::chrono::milliseconds(50);
    
    StreamingSession session(2, config);
    
    SECTION("Callback execution") {
        std::vector<BinaryMessage> received_messages;
        std::mutex callback_mutex;
        
        session.set_data_callback([&](const BinaryMessage& msg) -> bool {
            std::lock_guard<std::mutex> lock(callback_mutex);
            received_messages.push_back(msg);
            return true; // Success
        });
        
        REQUIRE(session.start());
        
        // Add data to trigger batching
        session.add_data("test1", "data1");
        session.add_data("test2", "data2");
        session.add_data("test3", "data3"); // Should trigger batch flush
        
        // Wait for callback execution
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        {
            std::lock_guard<std::mutex> lock(callback_mutex);
            REQUIRE_FALSE(received_messages.empty());
        }
        
        session.stop();
    }
    
    SECTION("Callback failure handling") {
        bool callback_called = false;
        
        session.set_data_callback([&](const BinaryMessage&) -> bool {
            callback_called = true;
            return false; // Simulate failure
        });
        
        REQUIRE(session.start());
        
        // Add enough data to trigger batch
        session.add_data("test1", "data1");
        session.add_data("test2", "data2");
        session.add_data("test3", "data3");
        
        // Wait for processing
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        REQUIRE(callback_called);
        // Session should transition to error state after callback failure
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        REQUIRE(session.state() == StreamingSession::StreamState::ERROR);
    }
}

TEST_CASE("StreamingManager - Session Management", "[network][streaming]") {
    StreamingManager manager;
    
    SECTION("Stream creation and retrieval") {
        uint64_t stream_id = manager.create_stream();
        REQUIRE(stream_id > 0);
        
        auto stream = manager.get_stream(stream_id);
        REQUIRE(stream != nullptr);
        REQUIRE(stream->stream_id() == stream_id);
        
        REQUIRE(manager.active_stream_count() == 0); // Not started yet
    }
    
    SECTION("Stream lifecycle") {
        uint64_t stream_id = manager.create_stream();
        
        REQUIRE(manager.start_stream(stream_id));
        REQUIRE(manager.active_stream_count() == 1);
        
        auto active_ids = manager.get_active_stream_ids();
        REQUIRE(active_ids.size() == 1);
        REQUIRE(active_ids[0] == stream_id);
        
        REQUIRE(manager.stop_stream(stream_id));
        REQUIRE(manager.active_stream_count() == 0);
        
        REQUIRE(manager.remove_stream(stream_id));
        auto removed_stream = manager.get_stream(stream_id);
        REQUIRE(removed_stream == nullptr);
    }
    
    SECTION("Multiple streams") {
        std::vector<uint64_t> stream_ids;
        
        for (int i = 0; i < 5; ++i) {
            uint64_t id = manager.create_stream();
            stream_ids.push_back(id);
            REQUIRE(manager.start_stream(id));
        }
        
        REQUIRE(manager.active_stream_count() == 5);
        
        auto active_ids = manager.get_active_stream_ids();
        REQUIRE(active_ids.size() == 5);
        
        // Stop all streams
        for (uint64_t id : stream_ids) {
            REQUIRE(manager.stop_stream(id));
        }
        
        REQUIRE(manager.active_stream_count() == 0);
    }
    
    SECTION("Data operations") {
        uint64_t stream_id = manager.create_stream();
        REQUIRE(manager.start_stream(stream_id));
        
        REQUIRE(manager.add_to_stream(stream_id, "key1", "value1"));
        
        std::vector<std::pair<std::string, std::string>> batch = {
            {"key2", "value2"},
            {"key3", "value3"}
        };
        REQUIRE(manager.add_batch_to_stream(stream_id, batch));
        
        auto stream = manager.get_stream(stream_id);
        REQUIRE(stream->pending_items() >= 3);
        
        manager.stop_stream(stream_id);
    }
}

TEST_CASE("BatchProcessor - Basic Operations", "[network][streaming]") {
    // Create temporary storage for testing
    auto temp_dir = std::filesystem::temp_directory_path() / "test_batch_processor";
    std::filesystem::create_directories(temp_dir);
    
    auto storage = std::make_shared<StorageEngine>(temp_dir, StorageEngine::EngineType::SimpleLog);
    
    BatchOps::BatchProcessor::BatchConfig config;
    config.max_batch_size = 10;
    config.enable_parallelization = false; // Disable for predictable testing
    config.worker_threads = 2;
    
    BatchOps::BatchProcessor processor(storage, config);
    
    SECTION("Single item operations") {
        std::vector<BatchOps::BatchItem> items = {
            {BatchOps::BatchItem::PUT, "test_key", "test_value"}
        };
        
        auto results = processor.execute_batch(items);
        REQUIRE(results.size() == 1);
        REQUIRE(results[0].status == StatusCode::SUCCESS);
        REQUIRE(results[0].execution_time.count() > 0);
        
        // Verify data was stored
        std::vector<BatchOps::BatchItem> get_items = {
            {BatchOps::BatchItem::GET, "test_key", ""}
        };
        
        auto get_results = processor.execute_batch(get_items);
        REQUIRE(get_results.size() == 1);
        REQUIRE(get_results[0].status == StatusCode::SUCCESS);
        REQUIRE(get_results[0].value == "test_value");
    }
    
    SECTION("Mixed operations batch") {
        std::vector<BatchOps::BatchItem> items = {
            {BatchOps::BatchItem::PUT, "batch_key1", "batch_value1"},
            {BatchOps::BatchItem::PUT, "batch_key2", "batch_value2"},
            {BatchOps::BatchItem::GET, "batch_key1", ""},
            {BatchOps::BatchItem::DELETE, "batch_key2", ""},
            {BatchOps::BatchItem::GET, "batch_key2", ""} // Should not find
        };
        
        auto results = processor.execute_batch(items);
        REQUIRE(results.size() == 5);
        
        // PUT operations should succeed
        REQUIRE(results[0].status == StatusCode::SUCCESS);
        REQUIRE(results[1].status == StatusCode::SUCCESS);
        
        // GET should find the value
        REQUIRE(results[2].status == StatusCode::SUCCESS);
        REQUIRE(results[2].value == "batch_value1");
        
        // DELETE should succeed
        REQUIRE(results[3].status == StatusCode::SUCCESS);
        
        // GET after DELETE should fail
        REQUIRE(results[4].status == StatusCode::KEY_NOT_FOUND);
    }
    
    SECTION("Large batch processing") {
        std::vector<BatchOps::BatchItem> large_batch;
        
        // Create 50 PUT operations
        for (int i = 0; i < 50; ++i) {
            std::string key = "large_key_" + std::to_string(i);
            std::string value = "large_value_" + std::to_string(i);
            large_batch.emplace_back(BatchOps::BatchItem::PUT, key, value);
        }
        
        auto results = processor.execute_batch(large_batch);
        REQUIRE(results.size() == 50);
        
        // All should succeed
        for (const auto& result : results) {
            REQUIRE(result.status == StatusCode::SUCCESS);
        }
        
        // Verify statistics
        const auto& stats = processor.stats();
        REQUIRE(stats.batches_executed.load() >= 1);
        REQUIRE(stats.items_processed.load() >= 50);
    }
    
    SECTION("Statistics tracking") {
        const auto& initial_stats = processor.stats();
        auto initial_batches = initial_stats.batches_executed.load();
        auto initial_items = initial_stats.items_processed.load();
        
        std::vector<BatchOps::BatchItem> items = {
            {BatchOps::BatchItem::PUT, "stats_key1", "stats_value1"},
            {BatchOps::BatchItem::GET, "nonexistent", ""},
            {BatchOps::BatchItem::PUT, "stats_key2", "stats_value2"}
        };
        
        auto results = processor.execute_batch(items);
        
        const auto& final_stats = processor.stats();
        REQUIRE(final_stats.batches_executed.load() == initial_batches + 1);
        REQUIRE(final_stats.items_processed.load() == initial_items + 3);
        REQUIRE(final_stats.cache_misses.load() >= 1); // GET on nonexistent key
        REQUIRE(final_stats.total_execution_time_us.load() > 0);
    }
    
    // Cleanup
    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("BatchProcessor - Async Operations", "[network][streaming]") {
    auto temp_dir = std::filesystem::temp_directory_path() / "test_async_batch";
    std::filesystem::create_directories(temp_dir);
    
    auto storage = std::make_shared<StorageEngine>(temp_dir, StorageEngine::EngineType::SimpleLog);
    BatchOps::BatchProcessor processor(storage);
    
    SECTION("Async batch execution") {
        std::vector<BatchOps::BatchItem> items = {
            {BatchOps::BatchItem::PUT, "async_key1", "async_value1"},
            {BatchOps::BatchItem::PUT, "async_key2", "async_value2"}
        };
        
        std::vector<BatchOps::BatchResult> async_results;
        std::mutex result_mutex;
        std::condition_variable result_cv;
        bool callback_called = false;
        
        auto callback = [&](std::vector<BatchOps::BatchResult> results) {
            std::lock_guard<std::mutex> lock(result_mutex);
            async_results = std::move(results);
            callback_called = true;
            result_cv.notify_one();
        };
        
        REQUIRE(processor.execute_batch_async(items, callback));
        
        // Wait for callback
        std::unique_lock<std::mutex> lock(result_mutex);
        result_cv.wait_for(lock, std::chrono::seconds(5), [&] { return callback_called; });
        
        REQUIRE(callback_called);
        REQUIRE(async_results.size() == 2);
        REQUIRE(async_results[0].status == StatusCode::SUCCESS);
        REQUIRE(async_results[1].status == StatusCode::SUCCESS);
    }
    
    // Cleanup
    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("BatchProcessor - Configuration", "[network][streaming]") {
    auto temp_dir = std::filesystem::temp_directory_path() / "test_config_batch";
    std::filesystem::create_directories(temp_dir);
    
    auto storage = std::make_shared<StorageEngine>(temp_dir, StorageEngine::EngineType::SimpleLog);
    
    SECTION("Custom configuration") {
        BatchOps::BatchProcessor::BatchConfig config;
        config.max_batch_size = 25;
        config.timeout = std::chrono::milliseconds(10000);
        config.enable_parallelization = true;
        config.worker_threads = 4;
        config.preserve_order = true;
        
        BatchOps::BatchProcessor processor(storage, config);
        
        const auto& retrieved_config = processor.config();
        REQUIRE(retrieved_config.max_batch_size == 25);
        REQUIRE(retrieved_config.timeout == std::chrono::milliseconds(10000));
        REQUIRE(retrieved_config.enable_parallelization == true);
        REQUIRE(retrieved_config.worker_threads == 4);
        REQUIRE(retrieved_config.preserve_order == true);
    }
    
    SECTION("Statistics reset") {
        BatchOps::BatchProcessor processor(storage);
        
        // Execute some operations
        std::vector<BatchOps::BatchItem> items = {
            {BatchOps::BatchItem::PUT, "reset_key", "reset_value"}
        };
        processor.execute_batch(items);
        
        // Verify statistics exist
        const auto& stats = processor.stats();
        REQUIRE(stats.batches_executed.load() > 0);
        REQUIRE(stats.items_processed.load() > 0);
        
        // Reset statistics
        processor.reset_stats();
        
        // Verify reset
        const auto& reset_stats = processor.stats();
        REQUIRE(reset_stats.batches_executed.load() == 0);
        REQUIRE(reset_stats.items_processed.load() == 0);
        REQUIRE(reset_stats.total_execution_time_us.load() == 0);
    }
    
    // Cleanup
    std::filesystem::remove_all(temp_dir);
}

TEST_CASE("StreamingSession - Statistics", "[network][streaming]") {
    StreamingSession::StreamConfig config;
    config.batch_size = 2;
    config.flush_interval = std::chrono::milliseconds(50);
    
    StreamingSession session(100, config);
    
    SECTION("Statistics tracking") {
        const auto& initial_stats = session.stats();
        REQUIRE(initial_stats.total_items_sent.load() == 0);
        REQUIRE(initial_stats.total_batches_sent.load() == 0);
        
        // Set up callback to simulate successful data delivery
        session.set_data_callback([](const BinaryMessage& msg) -> bool {
            return true; // Always succeed
        });
        
        REQUIRE(session.start());
        
        // Add data to trigger batching
        session.add_data("stat1", "data1");
        session.add_data("stat2", "data2"); // Should trigger batch
        
        // Wait for processing
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        const auto& final_stats = session.stats();
        REQUIRE(final_stats.total_batches_sent.load() >= 1);
        REQUIRE(final_stats.total_items_sent.load() >= 2);
        REQUIRE(final_stats.flush_count.load() >= 1);
        
        session.stop();
    }
}