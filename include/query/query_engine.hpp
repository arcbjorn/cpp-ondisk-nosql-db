#pragma once

#include "storage/storage_engine.hpp"
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>

namespace ishikura::query {

/**
 * Query result containing matched key-value pairs with metadata
 */
struct QueryResult {
    std::string key;
    std::string value;
    uint64_t timestamp;
    
    QueryResult() = default;
    QueryResult(std::string k, std::string v, uint64_t ts)
        : key(std::move(k)), value(std::move(v)), timestamp(ts) {}
};

/**
 * Query operation types supported by the engine
 */
enum class QueryOp {
    GET,            // Single key lookup: GET key
    RANGE,          // Key range: RANGE start_key end_key  
    PREFIX,         // Prefix match: PREFIX prefix
    PATTERN,        // Pattern match: PATTERN pattern (supports * and ?)
    SCAN,           // Full scan: SCAN [WHERE condition]
    COUNT           // Count matches: COUNT [WHERE condition]
};

/**
 * Query condition for filtering results
 */
struct QueryCondition {
    enum class Type {
        KEY_EQUALS,     // key = "value"
        KEY_PREFIX,     // key LIKE "prefix*"
        KEY_PATTERN,    // key LIKE "patt*rn"  
        KEY_RANGE,      // key BETWEEN "start" AND "end"
        VALUE_EQUALS,   // value = "value"
        VALUE_CONTAINS, // value CONTAINS "substring"
        ALWAYS_TRUE     // No condition (match all)
    };
    
    Type type = Type::ALWAYS_TRUE;
    std::string operand1;
    std::string operand2;  // Used for BETWEEN operations
    
    QueryCondition() = default;
    QueryCondition(Type t, std::string op1, std::string op2 = "")
        : type(t), operand1(std::move(op1)), operand2(std::move(op2)) {}
};

/**
 * Query execution plan with optimization information
 */
struct QueryPlan {
    QueryOp operation;
    QueryCondition condition;
    bool use_index = true;          // Can use B+Tree index
    bool requires_full_scan = false; // Needs to scan all records
    size_t estimated_cost = 0;      // Execution cost estimate
    std::string optimization_notes; // Human-readable optimization info
};

/**
 * Parsed query representation
 */
struct ParsedQuery {
    QueryOp operation;
    std::string target;             // Key/prefix/pattern to query
    QueryCondition where_condition; // Optional WHERE clause
    int limit = -1;                 // Result limit (-1 = no limit)
    int offset = 0;                 // Result offset for pagination
    
    ParsedQuery(QueryOp op, std::string tgt) 
        : operation(op), target(std::move(tgt)) {}
};

/**
 * QueryEngine provides advanced querying capabilities on top of the storage layer
 * 
 * Features:
 * - Range queries with efficient B+Tree traversal
 * - Prefix matching for hierarchical keys
 * - Pattern matching with wildcards (* and ?)
 * - Query optimization and execution planning
 * - Result pagination and limiting
 */
class QueryEngine {
public:
    explicit QueryEngine(std::shared_ptr<storage::StorageEngine> storage);
    
    // Query parsing and execution
    std::vector<QueryResult> execute_query(const std::string& query_string);
    ParsedQuery parse_query(const std::string& query_string);
    QueryPlan create_execution_plan(const ParsedQuery& query);
    std::vector<QueryResult> execute_plan(const QueryPlan& plan, const ParsedQuery& query);
    
    // Direct query operations (bypassing string parsing)
    std::optional<QueryResult> get(const std::string& key);
    std::vector<QueryResult> range_query(const std::string& start_key, const std::string& end_key);
    std::vector<QueryResult> prefix_query(const std::string& prefix);
    std::vector<QueryResult> pattern_query(const std::string& pattern);
    std::vector<QueryResult> scan_all(const QueryCondition& condition = QueryCondition{});
    
    // Statistics and optimization
    size_t count_keys() const;
    size_t count_matching(const QueryCondition& condition) const;
    std::vector<std::string> get_query_statistics() const;
    
    // Configuration
    void set_max_results(size_t max_results) { max_results_ = max_results; }
    void set_enable_query_cache(bool enable) { query_cache_enabled_ = enable; }

private:
    std::shared_ptr<storage::StorageEngine> storage_;
    size_t max_results_ = 10000;  // Safety limit for result sets
    bool query_cache_enabled_ = true;
    
    // Query execution statistics
    mutable size_t queries_executed_ = 0;
    mutable size_t cache_hits_ = 0;
    mutable size_t full_scans_performed_ = 0;
    
    // Internal helper methods
    bool matches_pattern(const std::string& text, const std::string& pattern) const;
    bool matches_condition(const QueryResult& result, const QueryCondition& condition) const;
    std::vector<QueryResult> apply_pagination(std::vector<QueryResult> results, 
                                              int limit, int offset) const;
    
    // Query optimization helpers
    size_t estimate_range_cost(const std::string& start_key, const std::string& end_key) const;
    size_t estimate_prefix_cost(const std::string& prefix) const;
    size_t estimate_scan_cost() const;
    
    // Query parsing helpers
    QueryOp parse_operation(const std::string& op_string);
    QueryCondition parse_where_clause(const std::string& where_clause);
    std::pair<int, int> parse_limit_offset(const std::string& limit_clause);
};

} // namespace ishikura::query