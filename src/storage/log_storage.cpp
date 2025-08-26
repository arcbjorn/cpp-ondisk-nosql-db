#include "storage/log_storage.hpp"
#include <spdlog/spdlog.h>
#include <chrono>
#include <format>

namespace nosql_db::storage {

LogStorage::LogStorage(const std::filesystem::path& log_file) 
    : log_path_(log_file) {
    
    std::filesystem::create_directories(log_path_.parent_path());
    
    file_.open(log_path_, std::ios::binary | std::ios::in | std::ios::out | std::ios::app);
    
    if (!file_.is_open()) {
        file_.clear();
        file_.open(log_path_, std::ios::binary | std::ios::out);
        file_.close();
        file_.open(log_path_, std::ios::binary | std::ios::in | std::ios::out);
    }
    
    if (file_.is_open()) {
        spdlog::info("LogStorage opened: {}", log_path_.string());
        rebuild_index();
    } else {
        spdlog::error("Failed to open log file: {}", log_path_.string());
    }
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
    auto file_offset = get_file_position();
    
    serialize_record(key, value, timestamp);
    index_.insert(std::string(key), file_offset, timestamp);
    
    spdlog::debug("Appended record: key={}, value={}, timestamp={}", 
                  key, value, timestamp);
    return true;
}

std::optional<std::string> LogStorage::get(std::string_view key) const {
    if (!file_.is_open()) {
        spdlog::error("Log file is not open");
        return std::nullopt;
    }
    
    // Use index for fast lookup
    auto index_entry = index_.find(std::string(key));
    if (!index_entry) {
        return std::nullopt;
    }
    
    // Seek to the indexed position and read the record
    file_.clear();
    file_.seekg(index_entry->file_offset, std::ios::beg);
    
    auto record = deserialize_record();
    if (record && record->key == key) {
        return record->value;
    }
    
    spdlog::warn("Index inconsistency detected for key '{}'", key);
    return std::nullopt;
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
}

std::optional<Record> LogStorage::deserialize_record() const {
    std::uint32_t key_size, value_size;
    std::uint64_t timestamp;
    
    if (!file_.read(reinterpret_cast<char*>(&key_size), sizeof(key_size)) ||
        !file_.read(reinterpret_cast<char*>(&value_size), sizeof(value_size)) ||
        !file_.read(reinterpret_cast<char*>(&timestamp), sizeof(timestamp))) {
        return std::nullopt;
    }
    
    if (key_size > 1024 * 1024 || value_size > 16 * 1024 * 1024) {
        spdlog::error("Invalid record sizes: key_size={}, value_size={}", key_size, value_size);
        return std::nullopt;
    }
    
    std::string key(key_size, '\0');
    std::string value(value_size, '\0');
    
    if (!file_.read(key.data(), key_size) ||
        !file_.read(value.data(), value_size)) {
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
    // Save current position
    auto current_pos = file_.tellp();
    
    // Seek to end to get file size
    file_.seekp(0, std::ios::end);
    auto end_pos = static_cast<std::uint64_t>(file_.tellp());
    
    // Restore position
    file_.seekp(current_pos);
    
    return end_pos;
}

void LogStorage::rebuild_index() {
    index_.clear();
    
    if (!file_.is_open()) {
        return;
    }
    
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
    
    spdlog::info("Rebuilt B+Tree index with {} entries", index_.size());
}

} // namespace nosql_db::storage