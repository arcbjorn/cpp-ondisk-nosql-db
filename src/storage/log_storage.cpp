#include "storage/log_storage.hpp"
#include <spdlog/spdlog.h>
#include <chrono>
#include <format>

namespace nosql_db::storage {

LogStorage::LogStorage(const std::filesystem::path& log_file) 
    : log_path_(log_file) {
    
    std::filesystem::create_directories(log_path_.parent_path());
    
    // Create file if it doesn't exist
    if (!std::filesystem::exists(log_path_)) {
        std::ofstream create_file(log_path_, std::ios::binary);
        spdlog::debug("Created new file: {}", log_path_.string());
        create_file.close();
    }
    
    // Open for reading and writing
    file_.open(log_path_, std::ios::binary | std::ios::in | std::ios::out);
    
    spdlog::debug("File open state: is_open={}, good={}, fail={}, bad={}", 
                  file_.is_open(), file_.good(), file_.fail(), file_.bad());
    
    if (!file_.is_open()) {
        spdlog::error("Failed to open log file: {}", log_path_.string());
        return;
    }
    
    spdlog::info("LogStorage opened: {}", log_path_.string());
    rebuild_index();
}

LogStorage::~LogStorage() {
    if (file_.is_open()) {
        file_.close();
        spdlog::info("LogStorage closed: {}", log_path_.string());
    }
}

bool LogStorage::append(std::string_view key, std::string_view value) {
    if (!file_.is_open()) {
        spdlog::error("Log file is not open");
        return false;
    }
    
    if (key.empty()) {
        spdlog::warn("Attempting to append empty key");
        return false;
    }
    
    auto timestamp = current_timestamp();
    
    // Get current file size as offset before writing
    file_.seekp(0, std::ios::end);
    auto file_offset = static_cast<std::uint64_t>(file_.tellp());
    
    spdlog::debug("Before write: file_offset={}, file.good()={}", file_offset, file_.good());
    
    // Ensure we're at end before writing
    serialize_record(key, value, timestamp);
    
    spdlog::debug("After write: file.good()={}, file.tellp()={}", file_.good(), static_cast<std::uint64_t>(file_.tellp()));
    
    // Only add to index if file operations succeeded
    if (file_.good() && file_offset != UINT64_MAX) {
        index_.insert(std::string(key), file_offset, timestamp);
    }
    
    spdlog::debug("Appended record: key={}, value={}, timestamp={}", 
                  key, value, timestamp);
    return true;
}

std::optional<std::string> LogStorage::get(std::string_view key) const {
    if (!file_.is_open()) {
        spdlog::error("Log file is not open");
        return std::nullopt;
    }
    
    // For now, use scanning approach to ensure correctness
    // TODO: Fix index-based lookup after basic functionality works
    file_.clear();
    file_.seekg(0, std::ios::beg);
    
    std::string latest_value;
    bool found = false;
    
    while (auto record = deserialize_record()) {
        if (record->key == key) {
            latest_value = record->value;
            found = true;
        }
    }
    
    return found ? std::optional<std::string>{latest_value} : std::nullopt;
}

std::vector<Record> LogStorage::get_all() const {
    std::vector<Record> records;
    
    if (!file_.is_open()) {
        spdlog::error("Log file is not open");
        return records;
    }
    
    file_.clear();
    file_.seekg(0, std::ios::beg);
    
    while (auto record = deserialize_record()) {
        records.push_back(std::move(*record));
    }
    
    return records;
}

void LogStorage::sync() {
    if (file_.is_open()) {
        file_.flush();
        spdlog::debug("Log file synced");
    }
}

bool LogStorage::is_open() const {
    return file_.is_open();
}

void LogStorage::serialize_record(std::string_view key, std::string_view value, std::uint64_t timestamp) {
    auto key_size = static_cast<std::uint32_t>(key.size());
    auto value_size = static_cast<std::uint32_t>(value.size());
    
    file_.seekp(0, std::ios::end);
    
    file_.write(reinterpret_cast<const char*>(&key_size), sizeof(key_size));
    file_.write(reinterpret_cast<const char*>(&value_size), sizeof(value_size));
    file_.write(reinterpret_cast<const char*>(&timestamp), sizeof(timestamp));
    file_.write(key.data(), key_size);
    file_.write(value.data(), value_size);
    
    // Ensure data is written to disk
    file_.flush();
}

std::optional<Record> LogStorage::deserialize_record() const {
    std::uint32_t key_size, value_size;
    std::uint64_t timestamp;
    
    // Read header
    if (!file_.read(reinterpret_cast<char*>(&key_size), sizeof(key_size))) {
        return std::nullopt;
    }
    if (!file_.read(reinterpret_cast<char*>(&value_size), sizeof(value_size))) {
        return std::nullopt;
    }
    if (!file_.read(reinterpret_cast<char*>(&timestamp), sizeof(timestamp))) {
        return std::nullopt;
    }
    
    // Validate sizes
    if (key_size > 1024 * 1024 || value_size > 16 * 1024 * 1024) {
        spdlog::error("Invalid record sizes: key_size={}, value_size={}", key_size, value_size);
        return std::nullopt;
    }
    
    // Read key and value
    std::string key(key_size, '\0');
    std::string value(value_size, '\0');
    
    if (key_size > 0 && !file_.read(key.data(), key_size)) {
        return std::nullopt;
    }
    if (value_size > 0 && !file_.read(value.data(), value_size)) {
        return std::nullopt;
    }
    
    return Record{std::move(key), std::move(value), timestamp};
}

std::uint64_t LogStorage::current_timestamp() const {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
}

std::uint64_t LogStorage::get_file_position() const {
    file_.seekp(0, std::ios::end);
    return static_cast<std::uint64_t>(file_.tellp());
}

void LogStorage::rebuild_index() {
    index_.clear();
    
    if (!file_.is_open()) {
        return;
    }
    
    // Clear error flags and seek to beginning for reading
    file_.clear();
    file_.seekg(0, std::ios::beg);
    
    while (true) {
        std::uint64_t offset = static_cast<std::uint64_t>(file_.tellg());
        
        auto record = deserialize_record();
        if (!record) {
            break;
        }
        
        index_.insert(record->key, offset, record->timestamp);
    }
    
    // After reading, clear error flags and prepare for writing
    file_.clear();
    file_.seekp(0, std::ios::end);
    
    spdlog::info("Rebuilt B+Tree index with {} entries", index_.size());
}

} // namespace nosql_db::storage