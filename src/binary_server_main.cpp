#include "network/binary_server.hpp"
#include "storage/storage_engine.hpp"
#include <spdlog/spdlog.h>
#include <iostream>
#include <csignal>
#include <filesystem>

namespace {
    volatile sig_atomic_t g_shutdown = 0;
    
    void signal_handler(int signal) {
        if (signal == SIGINT || signal == SIGTERM) {
            g_shutdown = 1;
            spdlog::info("Shutdown signal received");
        }
    }
}

int main(int argc, char* argv[]) {
    // Set up logging
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%f] [%l] %v");
    
    // Parse command line arguments
    std::string host = "0.0.0.0";
    uint16_t port = 9090;
    std::string data_dir = "data";
    size_t max_connections = 1000;
    size_t worker_threads = std::thread::hardware_concurrency();
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--data-dir" && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (arg == "--max-connections" && i + 1 < argc) {
            max_connections = static_cast<size_t>(std::stoi(argv[++i]));
        } else if (arg == "--worker-threads" && i + 1 < argc) {
            worker_threads = static_cast<size_t>(std::stoi(argv[++i]));
        } else if (arg == "--debug") {
            spdlog::set_level(spdlog::level::debug);
        } else if (arg == "--help") {
            std::cout << "NoSQL Database Binary Server\n\n"
                      << "Usage: " << argv[0] << " [options]\n\n"
                      << "Options:\n"
                      << "  --host <host>             Host to bind to (default: 0.0.0.0)\n"
                      << "  --port <port>             Port to listen on (default: 9090)\n"
                      << "  --data-dir <dir>          Directory for data files (default: data)\n"
                      << "  --max-connections <n>     Maximum concurrent connections (default: 1000)\n"
                      << "  --worker-threads <n>      Number of worker threads (default: CPU cores)\n"
                      << "  --debug                   Enable debug logging\n"
                      << "  --help                    Show this help message\n\n"
                      << "Binary Protocol Operations:\n"
                      << "  PUT      Store key-value pair\n"
                      << "  GET      Retrieve value by key\n"
                      << "  DELETE   Delete key\n"
                      << "  QUERY    Execute query (GET, RANGE, PREFIX, PATTERN, SCAN, COUNT)\n"
                      << "  BATCH    Execute multiple operations atomically\n"
                      << "  PING     Health check\n";
            return 0;
        }
    }
    
    try {
        // Initialize storage engine with LSM-Tree
        std::filesystem::path storage_dir = std::filesystem::path(data_dir);
        auto storage_engine = std::make_shared<nosql_db::storage::StorageEngine>(
            storage_dir, nosql_db::storage::StorageEngine::EngineType::LSMTree);
        
        // Start compaction for optimal performance
        storage_engine->start_compaction();
        
        spdlog::info("StorageEngine initialized with LSM-Tree at: {}", storage_dir.string());
        
        // Set up signal handlers for graceful shutdown
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
        
        // Configure binary server
        nosql_db::network::BinaryServer::ServerConfig config;
        config.host = host;
        config.port = port;
        config.max_connections = max_connections;
        config.worker_threads = worker_threads;
        config.client_timeout = std::chrono::seconds(300); // 5 minutes
        config.keepalive_interval = std::chrono::seconds(60); // 1 minute
        config.enable_compression = false;
        config.enable_batching = true;
        
        // Create and start binary server
        nosql_db::network::BinaryServer server(storage_engine, config);
        
        if (!server.start()) {
            spdlog::error("Failed to start binary server");
            return 1;
        }
        
        spdlog::info("NoSQL Database Binary Server started");
        spdlog::info("Listening on {}:{}", host, port);
        spdlog::info("Data directory: {}", data_dir);
        spdlog::info("Max connections: {}, Worker threads: {}", max_connections, worker_threads);
        spdlog::info("Press Ctrl+C to stop");
        
        // Wait for shutdown signal
        while (!g_shutdown) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            // Print statistics every 30 seconds
            static auto last_stats_time = std::chrono::steady_clock::now();
            auto now = std::chrono::steady_clock::now();
            if (now - last_stats_time >= std::chrono::seconds(30)) {
                const auto& stats = server.stats();
                spdlog::info("Server stats: {} active connections, {} total requests, {} total responses, "
                           "{} errors, {} timeouts",
                           stats.active_connections.load(),
                           stats.total_requests.load(),
                           stats.total_responses.load(),
                           stats.errors.load(),
                           stats.timeouts.load());
                last_stats_time = now;
            }
        }
        
        // Graceful shutdown
        spdlog::info("Stopping server...");
        server.stop();
        
        spdlog::info("Server stopped gracefully");
        return 0;
        
    } catch (const std::exception& e) {
        spdlog::error("Server error: {}", e.what());
        return 1;
    }
}