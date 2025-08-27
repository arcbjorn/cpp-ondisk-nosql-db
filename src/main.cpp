#include "storage/log_storage.hpp"
#include <spdlog/spdlog.h>
#include <iostream>

int main() {
    spdlog::set_level(spdlog::level::debug);
    spdlog::info("IshikuraDB（石蔵） starting...");
    
    ishikura::storage::LogStorage storage("data/test.log");
    
    if (!storage.is_open()) {
        spdlog::error("Failed to initialize storage");
        return 1;
    }
    
    storage.append("user:123", R"({"name": "John", "age": 30})");
    storage.append("user:456", R"({"name": "Jane", "age": 25})");
    storage.append("user:123", R"({"name": "John", "age": 31})");
    
    if (auto value = storage.get("user:123")) {
        spdlog::info("Found user:123 = {}", *value);
    }
    
    auto all_records = storage.get_all();
    spdlog::info("Total records: {}", all_records.size());
    
    storage.sync();
    spdlog::info("IshikuraDB（石蔵） shutting down...");
    
    return 0;
}