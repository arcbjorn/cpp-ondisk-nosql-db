#pragma once

#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <cstdint>

namespace ishikura::storage {

struct IndexEntry {
    std::string key;
    std::uint64_t file_offset;
    std::uint64_t timestamp;
    
    IndexEntry() = default;
    IndexEntry(std::string k, std::uint64_t offset, std::uint64_t ts)
        : key(std::move(k)), file_offset(offset), timestamp(ts) {}
};

class BTreeNode {
public:
    static constexpr size_t MIN_DEGREE = 64; // B+Tree degree (order)
    
    std::vector<IndexEntry> entries;
    std::vector<std::unique_ptr<BTreeNode>> children;
    bool is_leaf;
    
    explicit BTreeNode(bool leaf = true) : is_leaf(leaf) {
        entries.reserve(2 * MIN_DEGREE - 1);
        if (!is_leaf) {
            children.reserve(2 * MIN_DEGREE);
        }
    }
    
    bool is_full() const {
        return entries.size() == (2 * MIN_DEGREE - 1);
    }
    
    size_t find_key_index(const std::string& key) const;
};

class BTreeIndex {
public:
    BTreeIndex();
    ~BTreeIndex() = default;
    
    void insert(const std::string& key, std::uint64_t file_offset, std::uint64_t timestamp);
    std::optional<IndexEntry> find(const std::string& key) const;
    std::vector<IndexEntry> range_scan(const std::string& start_key, const std::string& end_key) const;
    
    void clear();
    size_t size() const { return total_entries_; }
    bool empty() const { return total_entries_ == 0; }
    
    // Debug/testing methods
    void print_tree() const;
    size_t height() const;

private:
    std::unique_ptr<BTreeNode> root_;
    size_t total_entries_;
    
    void insert_non_full(BTreeNode* node, const std::string& key, std::uint64_t file_offset, std::uint64_t timestamp);
    void split_child(BTreeNode* parent, size_t index);
    std::optional<IndexEntry> search_node(const BTreeNode* node, const std::string& key) const;
    void collect_range(const BTreeNode* node, const std::string& start_key, 
                      const std::string& end_key, std::vector<IndexEntry>& results) const;
    
    // Helper methods
    size_t calculate_height(const BTreeNode* node) const;
    void print_node(const BTreeNode* node, size_t depth) const;
};

} // namespace ishikura::storage