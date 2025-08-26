#pragma once

#include <filesystem>
#include <fstream>
#include <string_view>
#include <optional>
#include <vector>
#include <cstdint>
#include <shared_mutex>
#include "btree_index.hpp"

namespace nosql_db::storage {

struct Record {
    std::string key;
    std::string value;
    std::uint64_t timestamp;
};

class LogStorage {
public:
    explicit LogStorage(const std::filesystem::path& log_file);
    ~LogStorage();

    bool append(std::string_view key, std::string_view value);
    std::optional<std::string> get(std::string_view key) const;
    std::vector<Record> get_all() const;
    
    void sync();
    bool is_open() const;

private:
    std::filesystem::path log_path_;
    mutable std::fstream file_;
    BTreeIndex index_;
    
    // Thread safety
    mutable std::shared_mutex mutex_;
    
    void serialize_record(std::string_view key, std::string_view value, std::uint64_t timestamp);
    std::optional<Record> deserialize_record() const;
    std::uint64_t current_timestamp() const;
    std::uint64_t get_file_position() const;
    void rebuild_index();
};

} // namespace nosql_db::storage