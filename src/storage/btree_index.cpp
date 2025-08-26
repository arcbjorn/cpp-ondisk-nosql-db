#include "storage/btree_index.hpp"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <iostream>

namespace nosql_db::storage {

size_t BTreeNode::find_key_index(const std::string& key) const {
    auto it = std::lower_bound(entries.begin(), entries.end(), key,
        [](const IndexEntry& entry, const std::string& k) {
            return entry.key < k;
        });
    return std::distance(entries.begin(), it);
}

BTreeIndex::BTreeIndex() : root_(std::make_unique<BTreeNode>(true)), total_entries_(0) {}

void BTreeIndex::insert(const std::string& key, std::uint64_t file_offset, std::uint64_t timestamp) {
    if (root_->is_full()) {
        auto new_root = std::make_unique<BTreeNode>(false);
        new_root->children.push_back(std::move(root_));
        split_child(new_root.get(), 0);
        root_ = std::move(new_root);
    }
    
    insert_non_full(root_.get(), key, file_offset, timestamp);
    ++total_entries_;
    
    spdlog::debug("Inserted key '{}' at offset {} into B+Tree", key, file_offset);
}

void BTreeIndex::insert_non_full(BTreeNode* node, const std::string& key, 
                                 std::uint64_t file_offset, std::uint64_t timestamp) {
    if (node->is_leaf) {
        size_t pos = node->find_key_index(key);
        
        // Check if key already exists - update with latest timestamp
        if (pos < node->entries.size() && node->entries[pos].key == key) {
            if (timestamp > node->entries[pos].timestamp) {
                node->entries[pos].file_offset = file_offset;
                node->entries[pos].timestamp = timestamp;
                spdlog::debug("Updated existing key '{}' with newer timestamp", key);
            }
            --total_entries_; // Don't double count
            return;
        }
        
        // Insert new entry
        node->entries.emplace(node->entries.begin() + pos, key, file_offset, timestamp);
    } else {
        size_t child_index = node->find_key_index(key);
        
        // Ensure we don't go out of bounds
        if (child_index >= node->children.size()) {
            child_index = node->children.size() - 1;
        }
        
        if (node->children[child_index]->is_full()) {
            split_child(node, child_index);
            if (child_index < node->entries.size() && key > node->entries[child_index].key) {
                ++child_index;
            }
        }
        
        insert_non_full(node->children[child_index].get(), key, file_offset, timestamp);
    }
}

void BTreeIndex::split_child(BTreeNode* parent, size_t index) {
    auto full_child = std::move(parent->children[index]);
    auto new_child = std::make_unique<BTreeNode>(full_child->is_leaf);
    
    constexpr size_t mid = BTreeNode::MIN_DEGREE - 1;
    
    // Move half the entries to new node
    new_child->entries.assign(
        std::make_move_iterator(full_child->entries.begin() + mid + 1),
        std::make_move_iterator(full_child->entries.end())
    );
    full_child->entries.resize(mid);
    
    // Move children if not leaf
    if (!full_child->is_leaf) {
        new_child->children.assign(
            std::make_move_iterator(full_child->children.begin() + mid + 1),
            std::make_move_iterator(full_child->children.end())
        );
        full_child->children.resize(mid + 1);
    }
    
    // Insert the middle key into parent
    auto middle_entry = std::move(full_child->entries[mid]);
    parent->entries.insert(parent->entries.begin() + index, std::move(middle_entry));
    
    // Insert children back
    parent->children[index] = std::move(full_child);
    parent->children.insert(parent->children.begin() + index + 1, std::move(new_child));
    
    spdlog::debug("Split child node at index {}", index);
}

std::optional<IndexEntry> BTreeIndex::find(const std::string& key) const {
    return search_node(root_.get(), key);
}

std::optional<IndexEntry> BTreeIndex::search_node(const BTreeNode* node, const std::string& key) const {
    size_t index = node->find_key_index(key);
    
    if (index < node->entries.size() && node->entries[index].key == key) {
        return node->entries[index];
    }
    
    if (node->is_leaf) {
        return std::nullopt;
    }
    
    // Ensure we don't go out of bounds
    if (index >= node->children.size()) {
        index = node->children.size() - 1;
    }
    
    return search_node(node->children[index].get(), key);
}

std::vector<IndexEntry> BTreeIndex::range_scan(const std::string& start_key, const std::string& end_key) const {
    std::vector<IndexEntry> results;
    collect_range(root_.get(), start_key, end_key, results);
    return results;
}

void BTreeIndex::collect_range(const BTreeNode* node, const std::string& start_key,
                              const std::string& end_key, std::vector<IndexEntry>& results) const {
    if (!node) return;
    
    for (size_t i = 0; i < node->entries.size(); ++i) {
        const auto& entry = node->entries[i];
        
        if (entry.key >= start_key && entry.key <= end_key) {
            results.push_back(entry);
        }
        
        if (!node->is_leaf && entry.key >= start_key) {
            collect_range(node->children[i].get(), start_key, end_key, results);
        }
    }
    
    // Check the last child if not a leaf
    if (!node->is_leaf && !node->children.empty()) {
        collect_range(node->children.back().get(), start_key, end_key, results);
    }
}

void BTreeIndex::clear() {
    root_ = std::make_unique<BTreeNode>(true);
    total_entries_ = 0;
    spdlog::debug("B+Tree index cleared");
}

size_t BTreeIndex::height() const {
    return calculate_height(root_.get());
}

size_t BTreeIndex::calculate_height(const BTreeNode* node) const {
    if (!node || node->is_leaf) {
        return 1;
    }
    
    if (node->children.empty()) {
        return 1;
    }
    
    return 1 + calculate_height(node->children[0].get());
}

void BTreeIndex::print_tree() const {
    spdlog::info("B+Tree structure (height: {}, entries: {}):", height(), size());
    print_node(root_.get(), 0);
}

void BTreeIndex::print_node(const BTreeNode* node, size_t depth) const {
    if (!node) return;
    
    std::string indent(depth * 2, ' ');
    std::string node_type = node->is_leaf ? "LEAF" : "INTERNAL";
    
    spdlog::info("{}[{}] Keys: {}", indent, node_type, node->entries.size());
    
    for (const auto& entry : node->entries) {
        spdlog::info("{}  '{}' -> offset:{}, ts:{}", indent, entry.key, entry.file_offset, entry.timestamp);
    }
    
    if (!node->is_leaf) {
        for (const auto& child : node->children) {
            print_node(child.get(), depth + 1);
        }
    }
}

} // namespace nosql_db::storage