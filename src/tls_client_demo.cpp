#include "network/tls_server.hpp"
#include "network/metrics.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <sstream>
#include <iomanip>

using namespace nosql_db::network;

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options] [command]\n"
              << "Options:\n"
              << "  --host <host>         Server host (default: localhost)\n"
              << "  --port <port>         Server port (default: 9443)\n"
              << "  --cert <file>         Client certificate file (optional)\n"
              << "  --key <file>          Client private key file (optional)\n"
              << "  --ca <file>           CA certificate file (optional)\n"
              << "  --no-verify           Don't verify server certificate\n"
              << "  --no-hostname-check   Don't verify hostname\n"
              << "  --help               Show this help message\n"
              << "\n"
              << "Commands:\n"
              << "  interactive           Start interactive mode (default)\n"
              << "  put <key> <value>     Store a key-value pair\n"
              << "  get <key>             Retrieve value for key\n"
              << "  delete <key>          Delete a key\n"
              << "  ping                  Test connection\n"
              << "  query <query>         Execute query\n"
              << "  benchmark             Run performance benchmark\n";
}

void print_connection_info(const TLSClient& client) {
    std::cout << "TLS Connection Information:" << std::endl;
    std::cout << "  Protocol: " << client.get_protocol_version() << std::endl;
    std::cout << "  Cipher: " << client.get_cipher_name() << std::endl;
    std::cout << "  Server Certificate:" << std::endl;
    std::cout << "    Subject: " << client.get_server_certificate_subject() << std::endl;
    std::cout << "    Issuer: " << client.get_server_certificate_issuer() << std::endl;
    std::cout << "    Verified: " << (client.is_server_cert_verified() ? "Yes" : "No") << std::endl;
    std::cout << std::endl;
}

void run_interactive_mode(TLSClient& client) {
    std::cout << "Interactive TLS Client Mode" << std::endl;
    std::cout << "Commands: put <key> <value>, get <key>, delete <key>, query <query>, ping, quit" << std::endl;
    std::cout << std::endl;
    
    std::string command;
    while (std::cout << "tls> " && std::getline(std::cin, command)) {
        if (command.empty()) continue;
        
        std::istringstream iss(command);
        std::string cmd;
        iss >> cmd;
        
        if (cmd == "quit" || cmd == "exit") {
            break;
        } else if (cmd == "ping") {
            auto start = std::chrono::steady_clock::now();
            bool success = client.ping();
            auto duration = std::chrono::steady_clock::now() - start;
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
            
            if (success) {
                std::cout << "PONG (time: " << ms.count() << "ms)" << std::endl;
            } else {
                std::cout << "PING failed" << std::endl;
            }
            
        } else if (cmd == "put") {
            std::string key, value;
            if (iss >> key >> value) {
                bool success = client.put(key, value);
                std::cout << (success ? "OK" : "FAILED") << std::endl;
            } else {
                std::cout << "Usage: put <key> <value>" << std::endl;
            }
            
        } else if (cmd == "get") {
            std::string key;
            if (iss >> key) {
                auto result = client.get(key);
                if (result.has_value()) {
                    std::cout << "\"" << *result << "\"" << std::endl;
                } else {
                    std::cout << "Key not found" << std::endl;
                }
            } else {
                std::cout << "Usage: get <key>" << std::endl;
            }
            
        } else if (cmd == "delete") {
            std::string key;
            if (iss >> key) {
                bool success = client.delete_key(key);
                std::cout << (success ? "OK" : "FAILED") << std::endl;
            } else {
                std::cout << "Usage: delete <key>" << std::endl;
            }
            
        } else if (cmd == "query") {
            std::string query;
            std::getline(iss, query);
            if (!query.empty()) {
                query = query.substr(1); // Remove leading space
                auto results = client.query(query);
                std::cout << "Results (" << results.size() << " items):" << std::endl;
                for (const auto& [key, value] : results) {
                    std::cout << "  " << key << " => " << value << std::endl;
                }
            } else {
                std::cout << "Usage: query <query>" << std::endl;
            }
            
        } else if (cmd == "help") {
            std::cout << "Commands:" << std::endl;
            std::cout << "  put <key> <value> - Store a key-value pair" << std::endl;
            std::cout << "  get <key>         - Retrieve value for key" << std::endl;
            std::cout << "  delete <key>      - Delete a key" << std::endl;
            std::cout << "  query <query>     - Execute query (SCAN, PREFIX key:, etc.)" << std::endl;
            std::cout << "  ping              - Test connection" << std::endl;
            std::cout << "  quit/exit         - Exit interactive mode" << std::endl;
            
        } else {
            std::cout << "Unknown command: " << cmd << std::endl;
            std::cout << "Type 'help' for available commands" << std::endl;
        }
    }
}

void run_benchmark(TLSClient& client) {
    std::cout << "Running TLS Client Benchmark..." << std::endl;
    std::cout << std::endl;
    
    const int num_operations = 1000;
    const int num_keys = 100;
    
    // Benchmark PUT operations
    std::cout << "Benchmarking PUT operations..." << std::endl;
    auto start = std::chrono::steady_clock::now();
    int successful_puts = 0;
    
    for (int i = 0; i < num_operations; ++i) {
        std::string key = "benchmark_key_" + std::to_string(i % num_keys);
        std::string value = "benchmark_value_" + std::to_string(i);
        
        if (client.put(key, value)) {
            successful_puts++;
        }
    }
    
    auto put_duration = std::chrono::steady_clock::now() - start;
    auto put_ms = std::chrono::duration_cast<std::chrono::milliseconds>(put_duration);
    
    std::cout << "PUT Results:" << std::endl;
    std::cout << "  Operations: " << num_operations << std::endl;
    std::cout << "  Successful: " << successful_puts << std::endl;
    std::cout << "  Failed: " << (num_operations - successful_puts) << std::endl;
    std::cout << "  Total time: " << put_ms.count() << "ms" << std::endl;
    std::cout << "  Ops/sec: " << (num_operations * 1000) / put_ms.count() << std::endl;
    std::cout << "  Avg latency: " << (double)put_ms.count() / num_operations << "ms" << std::endl;
    std::cout << std::endl;
    
    // Benchmark GET operations
    std::cout << "Benchmarking GET operations..." << std::endl;
    start = std::chrono::steady_clock::now();
    int successful_gets = 0;
    
    for (int i = 0; i < num_operations; ++i) {
        std::string key = "benchmark_key_" + std::to_string(i % num_keys);
        
        auto result = client.get(key);
        if (result.has_value()) {
            successful_gets++;
        }
    }
    
    auto get_duration = std::chrono::steady_clock::now() - start;
    auto get_ms = std::chrono::duration_cast<std::chrono::milliseconds>(get_duration);
    
    std::cout << "GET Results:" << std::endl;
    std::cout << "  Operations: " << num_operations << std::endl;
    std::cout << "  Successful: " << successful_gets << std::endl;
    std::cout << "  Failed: " << (num_operations - successful_gets) << std::endl;
    std::cout << "  Total time: " << get_ms.count() << "ms" << std::endl;
    std::cout << "  Ops/sec: " << (num_operations * 1000) / get_ms.count() << std::endl;
    std::cout << "  Avg latency: " << (double)get_ms.count() / num_operations << "ms" << std::endl;
    std::cout << std::endl;
    
    // Benchmark batch operations
    std::cout << "Benchmarking BATCH operations..." << std::endl;
    std::vector<TLSClient::BatchItem> batch_ops;
    
    // Create mixed batch
    for (int i = 0; i < 100; ++i) {
        std::string key = "batch_key_" + std::to_string(i);
        std::string value = "batch_value_" + std::to_string(i);
        
        batch_ops.emplace_back(TLSClient::BatchOperation::PUT, key, value);
        if (i % 3 == 0) {
            batch_ops.emplace_back(TLSClient::BatchOperation::GET, key, "");
        }
    }
    
    start = std::chrono::steady_clock::now();
    auto batch_results = client.batch_execute(batch_ops);
    auto batch_duration = std::chrono::steady_clock::now() - start;
    auto batch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(batch_duration);
    
    int successful_batch = 0;
    for (auto result : batch_results) {
        if (result == StatusCode::SUCCESS) {
            successful_batch++;
        }
    }
    
    std::cout << "BATCH Results:" << std::endl;
    std::cout << "  Operations: " << batch_ops.size() << std::endl;
    std::cout << "  Successful: " << successful_batch << std::endl;
    std::cout << "  Failed: " << (batch_ops.size() - successful_batch) << std::endl;
    std::cout << "  Total time: " << batch_ms.count() << "ms" << std::endl;
    std::cout << "  Ops/sec: " << (batch_ops.size() * 1000) / batch_ms.count() << std::endl;
    std::cout << "  Avg latency: " << (double)batch_ms.count() / batch_ops.size() << "ms" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "NoSQL DB TLS Client Demo" << std::endl;
    std::cout << "========================" << std::endl;
    
    // Configuration
    TLSClient::ClientConfig config;
    std::string command = "interactive";
    std::vector<std::string> args;
    
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
        } else if (arg == "--cert" && i + 1 < argc) {
            config.cert_file = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            config.key_file = argv[++i];
        } else if (arg == "--ca" && i + 1 < argc) {
            config.ca_file = argv[++i];
        } else if (arg == "--no-verify") {
            config.verify_server_cert = false;
        } else if (arg == "--no-hostname-check") {
            config.verify_hostname = false;
        } else if (arg.substr(0, 2) == "--") {
            std::cerr << "Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        } else {
            if (command == "interactive") {
                command = arg;
            } else {
                args.push_back(arg);
            }
        }
    }
    
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Host: " << config.host << std::endl;
    std::cout << "  Port: " << config.port << std::endl;
    std::cout << "  Verify server cert: " << (config.verify_server_cert ? "Yes" : "No") << std::endl;
    std::cout << "  Verify hostname: " << (config.verify_hostname ? "Yes" : "No") << std::endl;
    if (!config.cert_file.empty()) {
        std::cout << "  Client cert: " << config.cert_file << std::endl;
    }
    if (!config.ca_file.empty()) {
        std::cout << "  CA file: " << config.ca_file << std::endl;
    }
    std::cout << std::endl;
    
    // Create and connect TLS client
    std::cout << "Connecting to TLS server..." << std::endl;
    TLSClient client(config);
    
    if (!client.connect()) {
        std::cerr << "Failed to connect to TLS server" << std::endl;
        return 1;
    }
    
    std::cout << "Connected successfully!" << std::endl;
    print_connection_info(client);
    
    // Execute command
    if (command == "interactive") {
        run_interactive_mode(client);
        
    } else if (command == "ping") {
        bool success = client.ping();
        std::cout << (success ? "PONG" : "PING failed") << std::endl;
        return success ? 0 : 1;
        
    } else if (command == "put") {
        if (args.size() != 2) {
            std::cerr << "Usage: put <key> <value>" << std::endl;
            return 1;
        }
        bool success = client.put(args[0], args[1]);
        std::cout << (success ? "OK" : "FAILED") << std::endl;
        return success ? 0 : 1;
        
    } else if (command == "get") {
        if (args.size() != 1) {
            std::cerr << "Usage: get <key>" << std::endl;
            return 1;
        }
        auto result = client.get(args[0]);
        if (result.has_value()) {
            std::cout << *result << std::endl;
            return 0;
        } else {
            std::cout << "Key not found" << std::endl;
            return 1;
        }
        
    } else if (command == "delete") {
        if (args.size() != 1) {
            std::cerr << "Usage: delete <key>" << std::endl;
            return 1;
        }
        bool success = client.delete_key(args[0]);
        std::cout << (success ? "OK" : "FAILED") << std::endl;
        return success ? 0 : 1;
        
    } else if (command == "query") {
        if (args.empty()) {
            std::cerr << "Usage: query <query>" << std::endl;
            return 1;
        }
        std::string query = args[0];
        for (size_t i = 1; i < args.size(); ++i) {
            query += " " + args[i];
        }
        auto results = client.query(query);
        for (const auto& [key, value] : results) {
            std::cout << key << " => " << value << std::endl;
        }
        return 0;
        
    } else if (command == "benchmark") {
        run_benchmark(client);
        return 0;
        
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}