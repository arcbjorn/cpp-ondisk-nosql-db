#include "storage/storage_engine.hpp"
#include "network/tls_server.hpp"
#include "network/metrics.hpp"
#include <iostream>
#include <filesystem>
#include <signal.h>
#include <thread>
#include <csignal>
#include <iomanip>

using namespace ishikura::network;
using namespace ishikura::storage;

// Global server instance for signal handling
std::unique_ptr<TLSServer> g_server;

void signal_handler(int signum) {
    std::cout << "\nReceived signal " << signum << ". Shutting down gracefully..." << std::endl;
    if (g_server) {
        g_server->stop();
    }
    exit(0);
}

void setup_signal_handlers() {
    signal(SIGINT, signal_handler);   // Ctrl+C
    signal(SIGTERM, signal_handler);  // Termination request
    signal(SIGPIPE, SIG_IGN);         // Ignore broken pipe
}

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n"
              << "Options:\n"
              << "  --host <host>         Server host (default: 0.0.0.0)\n"
              << "  --port <port>         Server port (default: 9443)\n"
              << "  --data-dir <path>     Data directory (default: ./tls_data)\n"
              << "  --cert <file>         Certificate file (default: server.crt)\n"
              << "  --key <file>          Private key file (default: server.key)\n"
              << "  --ca <file>           CA certificate file (optional)\n"
              << "  --require-client-cert Require client certificates\n"
              << "  --generate-cert       Generate self-signed certificate\n"
              << "  --workers <n>         Number of worker threads (default: 4)\n"
              << "  --help               Show this help message\n";
}

int main(int argc, char* argv[]) {
    std::cout << "IshikuraDB（石蔵） TLS Server" << std::endl;
    std::cout << "===================" << std::endl;
    
    // Setup signal handlers
    setup_signal_handlers();
    
    // Configuration
    TLSServer::ServerConfig config;
    std::string data_dir = "./tls_data";
    bool generate_cert = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg == "--host" && i + 1 < argc) {
            config.host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            config.port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--data-dir" && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (arg == "--cert" && i + 1 < argc) {
            config.tls_config.cert_file = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            config.tls_config.key_file = argv[++i];
        } else if (arg == "--ca" && i + 1 < argc) {
            config.tls_config.ca_file = argv[++i];
        } else if (arg == "--require-client-cert") {
            config.tls_config.require_client_cert = true;
        } else if (arg == "--generate-cert") {
            generate_cert = true;
        } else if (arg == "--workers" && i + 1 < argc) {
            config.worker_threads = std::stoi(argv[++i]);
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }
    
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Host: " << config.host << std::endl;
    std::cout << "  Port: " << config.port << std::endl;
    std::cout << "  Data directory: " << data_dir << std::endl;
    std::cout << "  Certificate: " << config.tls_config.cert_file << std::endl;
    std::cout << "  Private key: " << config.tls_config.key_file << std::endl;
    std::cout << "  Worker threads: " << config.worker_threads << std::endl;
    std::cout << "  Require client cert: " << (config.tls_config.require_client_cert ? "Yes" : "No") << std::endl;
    std::cout << std::endl;
    
    // Generate self-signed certificate if requested
    if (generate_cert) {
        std::cout << "Generating self-signed certificate..." << std::endl;
        
        tls_utils::CertificateInfo cert_info;
        cert_info.common_name = config.host == "0.0.0.0" ? "localhost" : config.host;
        
        if (!tls_utils::generate_self_signed_certificate(
                config.tls_config.cert_file, 
                config.tls_config.key_file, 
                cert_info)) {
            std::cerr << "Failed to generate certificate" << std::endl;
            return 1;
        }
        
        std::cout << "Certificate generated successfully." << std::endl;
        std::cout << std::endl;
    }
    
    // Check if certificate files exist
    if (!std::filesystem::exists(config.tls_config.cert_file)) {
        std::cerr << "Certificate file not found: " << config.tls_config.cert_file << std::endl;
        std::cerr << "Use --generate-cert to create a self-signed certificate" << std::endl;
        return 1;
    }
    
    if (!std::filesystem::exists(config.tls_config.key_file)) {
        std::cerr << "Private key file not found: " << config.tls_config.key_file << std::endl;
        std::cerr << "Use --generate-cert to create a self-signed certificate" << std::endl;
        return 1;
    }
    
    // Validate certificate files
    std::cout << "Validating certificate files..." << std::endl;
    
    if (!tls_utils::validate_certificate_file(config.tls_config.cert_file)) {
        std::cerr << "Invalid certificate file: " << config.tls_config.cert_file << std::endl;
        return 1;
    }
    
    if (!tls_utils::validate_private_key_file(config.tls_config.key_file)) {
        std::cerr << "Invalid private key file: " << config.tls_config.key_file << std::endl;
        return 1;
    }
    
    if (!tls_utils::validate_certificate_key_pair(config.tls_config.cert_file, config.tls_config.key_file)) {
        std::cerr << "Certificate and private key do not match" << std::endl;
        return 1;
    }
    
    // Print certificate information
    auto expiry = tls_utils::get_certificate_expiry(config.tls_config.cert_file);
    auto subject = tls_utils::get_certificate_subject(config.tls_config.cert_file);
    auto issuer = tls_utils::get_certificate_issuer(config.tls_config.cert_file);
    auto san_list = tls_utils::get_certificate_san_list(config.tls_config.cert_file);
    
    std::cout << "Certificate Information:" << std::endl;
    std::cout << "  Subject: " << subject << std::endl;
    std::cout << "  Issuer: " << issuer << std::endl;
    
    auto now = std::chrono::system_clock::now();
    auto time_t_expiry = std::chrono::system_clock::to_time_t(expiry);
    std::cout << "  Expires: " << std::ctime(&time_t_expiry);
    
    if (expiry < now) {
        std::cerr << "WARNING: Certificate has expired!" << std::endl;
    } else {
        auto days_until_expiry = std::chrono::duration_cast<std::chrono::hours>(expiry - now).count() / 24;
        std::cout << "  Days until expiry: " << days_until_expiry << std::endl;
    }
    
    if (!san_list.empty()) {
        std::cout << "  Subject Alternative Names:" << std::endl;
        for (const auto& san : san_list) {
            std::cout << "    " << san << std::endl;
        }
    }
    
    std::cout << std::endl;
    
    // Create data directory
    try {
        if (!std::filesystem::exists(data_dir)) {
            std::filesystem::create_directories(data_dir);
            std::cout << "Created data directory: " << data_dir << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to create data directory: " << e.what() << std::endl;
        return 1;
    }
    
    // Initialize storage engine
    std::cout << "Initializing storage engine..." << std::endl;
    auto storage = std::make_shared<ishikura::storage::StorageEngine>(data_dir, ishikura::storage::StorageEngine::EngineType::SimpleLog);
    
    // Create and start TLS server
    std::cout << "Starting TLS server..." << std::endl;
    g_server = std::make_unique<TLSServer>(storage, config);
    
    if (!g_server->start()) {
        std::cerr << "Failed to start TLS server" << std::endl;
        return 1;
    }
    
    std::cout << std::endl;
    std::cout << "TLS Server is running!" << std::endl;
    std::cout << "Connect using: openssl s_client -connect " << config.host << ":" << config.port << std::endl;
    std::cout << "Or use the TLS client application" << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    std::cout << std::endl;
    
    // Start metrics reporting thread
    std::thread metrics_thread([&]() {
        auto metrics = g_server->metrics();
        auto start_time = std::chrono::steady_clock::now();
        
        while (g_server->is_running()) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            
            if (!g_server->is_running()) break;
            
            auto now = std::chrono::steady_clock::now();
            auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
            
            std::cout << "\n=== Server Statistics (Uptime: " << uptime.count() << "s) ===" << std::endl;
            std::cout << "Connections: " << metrics->connection_metrics().total_connections.load() 
                      << " total, " << metrics->connection_metrics().active_connections.load() << " active" << std::endl;
            std::cout << "Requests: " << metrics->request_metrics().total_requests.load() 
                      << " total, " << metrics->request_metrics().successful_requests.load() << " successful" << std::endl;
            std::cout << "Bandwidth: " << metrics->bandwidth_metrics().bytes_sent.load() << " bytes sent, "
                      << metrics->bandwidth_metrics().bytes_received.load() << " bytes received" << std::endl;
            std::cout << "Errors: " << metrics->error_metrics().protocol_errors.load() << " protocol, "
                      << metrics->error_metrics().network_errors.load() << " network, "
                      << metrics->error_metrics().timeout_errors.load() << " timeout" << std::endl;
            
            if (metrics->request_metrics().total_requests.load() > 0) {
                std::cout << "Avg Response Time: " << std::fixed << std::setprecision(2) 
                          << metrics->get_average_response_time_ms() << "ms" << std::endl;
                std::cout << "Error Rate: " << std::fixed << std::setprecision(2) 
                          << metrics->get_error_rate() << "%" << std::endl;
            }
            std::cout << std::endl;
        }
    });
    
    // Main server loop
    while (g_server->is_running()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Check certificate expiry (daily check)
        static auto last_cert_check = std::chrono::system_clock::now();
        auto now = std::chrono::system_clock::now();
        
        if (now - last_cert_check > std::chrono::hours(24)) {
            auto current_expiry = g_server->get_certificate_expiry();
            if (current_expiry < now + std::chrono::hours(24 * 7)) { // 7 days warning
                std::cerr << "WARNING: Certificate expires in less than 7 days!" << std::endl;
            }
            last_cert_check = now;
        }
    }
    
    // Wait for metrics thread to finish
    if (metrics_thread.joinable()) {
        metrics_thread.join();
    }
    
    std::cout << "TLS Server stopped." << std::endl;
    return 0;
}