#include "api/kv_controller.hpp"
#include "storage/log_storage.hpp"
#include <spdlog/spdlog.h>
#include <httplib.h>
#include <memory>
#include <csignal>
#include <iostream>
#include <thread>
#include <chrono>
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
    int port = 8080;
    std::string data_dir = "data";
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if (arg == "--data-dir" && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (arg == "--debug") {
            spdlog::set_level(spdlog::level::debug);
        } else if (arg == "--help") {
            std::cout << "NoSQL Database HTTP Server\n\n"
                      << "Usage: " << argv[0] << " [options]\n\n"
                      << "Options:\n"
                      << "  --host <host>     Host to bind to (default: 0.0.0.0)\n"
                      << "  --port <port>     Port to listen on (default: 8080)\n"
                      << "  --data-dir <dir>  Directory for data files (default: data)\n"
                      << "  --debug           Enable debug logging\n"
                      << "  --help            Show this help message\n\n"
                      << "API Endpoints:\n"
                      << "  PUT    /api/v1/kv/{key}     Store key-value pair\n"
                      << "  GET    /api/v1/kv/{key}     Retrieve value by key\n"
                      << "  DELETE /api/v1/kv/{key}     Delete key\n"
                      << "  GET    /api/v1/kv          List all keys\n"
                      << "  GET    /api/v1/health      Health check\n";
            return 0;
        }
    }
    
    try {
        // Initialize storage
        std::filesystem::path log_file = std::filesystem::path(data_dir) / "nosql.log";
        auto storage = std::make_shared<nosql_db::storage::LogStorage>(log_file);
        
        if (!storage->is_open()) {
            spdlog::error("Failed to initialize storage at: {}", log_file.string());
            return 1;
        }
        
        spdlog::info("Storage initialized: {}", log_file.string());
        
        // Set up signal handlers for graceful shutdown
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);
        
        // Create HTTP server
        httplib::Server server;
        
        // Set up request logging middleware
        server.set_pre_routing_handler([](const httplib::Request& req, httplib::Response&) {
            spdlog::debug("{} {} - {}", req.method, req.path, req.remote_addr);
            return httplib::Server::HandlerResponse::Unhandled;
        });
        
        // Register API controller
        nosql_db::api::KvController controller(storage);
        controller.register_routes(server);
        
        // Set server configuration
        server.set_keep_alive_max_count(100);
        server.set_read_timeout(30, 0);  // 30 seconds
        server.set_write_timeout(30, 0); // 30 seconds
        
        // Start server in a separate thread
        spdlog::info("Starting NoSQL Database HTTP Server");
        spdlog::info("Listening on http://{}:{}", host, port);
        spdlog::info("Data directory: {}", data_dir);
        spdlog::info("Press Ctrl+C to stop");
        
        // Start server with graceful shutdown capability
        std::thread server_thread([&]() {
            server.listen(host.c_str(), port);
        });
        
        // Wait for shutdown signal
        while (!g_shutdown) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        // Graceful shutdown
        spdlog::info("Stopping server...");
        server.stop();
        
        if (server_thread.joinable()) {
            server_thread.join();
        }
        
        spdlog::info("Server stopped gracefully");
        return 0;
        
    } catch (const std::exception& e) {
        spdlog::error("Server error: {}", e.what());
        return 1;
    }
}