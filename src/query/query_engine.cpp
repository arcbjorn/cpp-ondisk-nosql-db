#include "query/query_engine.hpp"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <regex>
#include <sstream>
#include <cctype>

namespace nosql_db::query {

QueryEngine::QueryEngine(std::shared_ptr<storage::StorageEngine> storage)
    : storage_(std::move(storage)) {
    spdlog::info("QueryEngine initialized");
}

std::vector<QueryResult> QueryEngine::execute_query(const std::string& query_string) {
    queries_executed_++;
    
    try {
        // Parse the query string
        auto parsed_query = parse_query(query_string);
        
        // Create execution plan
        auto plan = create_execution_plan(parsed_query);
        
        spdlog::debug("Executing query: {} (cost: {}, index: {}, scan: {})", 
                     query_string, plan.estimated_cost, plan.use_index, plan.requires_full_scan);
        
        // Execute the plan
        auto results = execute_plan(plan, parsed_query);
        
        // Apply pagination
        if (parsed_query.limit > 0 || parsed_query.offset > 0) {
            results = apply_pagination(std::move(results), parsed_query.limit, parsed_query.offset);
        }
        
        // Apply global max_results limit
        if (results.size() > max_results_) {
            results.resize(max_results_);
        }
        
        spdlog::debug("Query returned {} results", results.size());
        return results;
        
    } catch (const std::exception& e) {
        spdlog::error("Query execution failed: {}", e.what());
        throw;
    }
}

ParsedQuery QueryEngine::parse_query(const std::string& query_string) {
    std::istringstream iss(query_string);
    std::string token;
    std::vector<std::string> tokens;
    
    // Tokenize the query (simple space-based for now)
    while (iss >> token) {
        tokens.push_back(token); // Keep original case for now
    }
    
    // Convert only the operation to uppercase for parsing
    if (!tokens.empty()) {
        std::transform(tokens[0].begin(), tokens[0].end(), tokens[0].begin(), ::toupper);
    }
    
    if (tokens.empty()) {
        throw std::invalid_argument("Empty query");
    }
    
    // Parse operation
    QueryOp operation = parse_operation(tokens[0]);
    
    ParsedQuery parsed_query(operation, "");
    
    switch (operation) {
        case QueryOp::GET:
            if (tokens.size() < 2) throw std::invalid_argument("GET requires a key");
            parsed_query.target = tokens[1];
            break;
            
        case QueryOp::RANGE:
            if (tokens.size() < 3) throw std::invalid_argument("RANGE requires start and end keys");
            parsed_query.target = tokens[1] + ":" + tokens[2]; // Store as "start:end"
            break;
            
        case QueryOp::PREFIX:
            if (tokens.size() < 2) throw std::invalid_argument("PREFIX requires a prefix");
            parsed_query.target = tokens[1];
            break;
            
        case QueryOp::PATTERN:
            if (tokens.size() < 2) throw std::invalid_argument("PATTERN requires a pattern");
            parsed_query.target = tokens[1];
            break;
            
        case QueryOp::SCAN:
        case QueryOp::COUNT:
            // These operations might have WHERE clauses
            break;
    }
    
    // Parse WHERE clause if present (need to check uppercase)
    auto where_it = std::find_if(tokens.begin(), tokens.end(), 
                                 [](const std::string& token) {
                                     std::string upper_token = token;
                                     std::transform(upper_token.begin(), upper_token.end(), upper_token.begin(), ::toupper);
                                     return upper_token == "WHERE";
                                 });
    if (where_it != tokens.end() && std::next(where_it) != tokens.end()) {
        std::string where_clause;
        for (auto it = std::next(where_it); it != tokens.end(); ++it) {
            std::string upper_token = *it;
            std::transform(upper_token.begin(), upper_token.end(), upper_token.begin(), ::toupper);
            if (upper_token == "LIMIT" || upper_token == "OFFSET") break;
            where_clause += *it + " ";
        }
        parsed_query.where_condition = parse_where_clause(where_clause);
    }
    
    // Parse LIMIT and OFFSET (need to check uppercase)
    auto limit_it = std::find_if(tokens.begin(), tokens.end(),
                                 [](const std::string& token) {
                                     std::string upper_token = token;
                                     std::transform(upper_token.begin(), upper_token.end(), upper_token.begin(), ::toupper);
                                     return upper_token == "LIMIT";
                                 });
    if (limit_it != tokens.end() && std::next(limit_it) != tokens.end()) {
        parsed_query.limit = std::stoi(*std::next(limit_it));
    }
    
    auto offset_it = std::find_if(tokens.begin(), tokens.end(),
                                  [](const std::string& token) {
                                      std::string upper_token = token;
                                      std::transform(upper_token.begin(), upper_token.end(), upper_token.begin(), ::toupper);
                                      return upper_token == "OFFSET";
                                  });
    if (offset_it != tokens.end() && std::next(offset_it) != tokens.end()) {
        parsed_query.offset = std::stoi(*std::next(offset_it));
    }
    
    return parsed_query;
}

QueryPlan QueryEngine::create_execution_plan(const ParsedQuery& query) {
    QueryPlan plan;
    plan.operation = query.operation;
    plan.condition = query.where_condition;
    
    switch (query.operation) {
        case QueryOp::GET:
            plan.use_index = true;
            plan.requires_full_scan = false;
            plan.estimated_cost = 1; // O(log n) with B+Tree
            plan.optimization_notes = "Single key lookup using B+Tree index";
            break;
            
        case QueryOp::RANGE: {
            auto colon_pos = query.target.find(':');
            if (colon_pos != std::string::npos) {
                std::string start = query.target.substr(0, colon_pos);
                std::string end = query.target.substr(colon_pos + 1);
                plan.estimated_cost = estimate_range_cost(start, end);
            } else {
                plan.estimated_cost = estimate_scan_cost();
            }
            plan.use_index = true;
            plan.requires_full_scan = false;
            plan.optimization_notes = "Range scan using B+Tree traversal";
            break;
        }
        
        case QueryOp::PREFIX:
            plan.estimated_cost = estimate_prefix_cost(query.target);
            plan.use_index = true;
            plan.requires_full_scan = false;
            plan.optimization_notes = "Prefix scan using B+Tree range";
            break;
            
        case QueryOp::PATTERN:
            // Pattern matching typically requires full scan
            plan.estimated_cost = estimate_scan_cost();
            plan.use_index = false;
            plan.requires_full_scan = true;
            plan.optimization_notes = "Full scan required for pattern matching";
            break;
            
        case QueryOp::SCAN:
        case QueryOp::COUNT:
            plan.estimated_cost = estimate_scan_cost();
            plan.use_index = false;
            plan.requires_full_scan = true;
            plan.optimization_notes = "Full table scan";
            break;
    }
    
    return plan;
}

std::vector<QueryResult> QueryEngine::execute_plan(const QueryPlan& plan, const ParsedQuery& query) {
    std::vector<QueryResult> results;
    
    switch (plan.operation) {
        case QueryOp::GET: {
            auto result = get(query.target);
            if (result) {
                results.push_back(*result);
            }
            break;
        }
        
        case QueryOp::RANGE: {
            auto colon_pos = query.target.find(':');
            if (colon_pos != std::string::npos) {
                std::string start = query.target.substr(0, colon_pos);
                std::string end = query.target.substr(colon_pos + 1);
                results = range_query(start, end);
            }
            break;
        }
        
        case QueryOp::PREFIX:
            results = prefix_query(query.target);
            break;
            
        case QueryOp::PATTERN:
            results = pattern_query(query.target);
            break;
            
        case QueryOp::SCAN:
            results = scan_all(query.where_condition);
            break;
            
        case QueryOp::COUNT: {
            size_t count = count_matching(query.where_condition);
            // For COUNT, return a special result with the count as value
            results.emplace_back("__COUNT__", std::to_string(count), 0);
            break;
        }
    }
    
    if (plan.requires_full_scan) {
        full_scans_performed_++;
    }
    
    return results;
}

std::optional<QueryResult> QueryEngine::get(const std::string& key) {
    auto value = storage_->get(key);
    if (value) {
        return QueryResult(key, *value, 0); // Timestamp not available from storage
    }
    return std::nullopt;
}

std::vector<QueryResult> QueryEngine::range_query(const std::string& start_key, const std::string& end_key) {
    auto all_records = storage_->get_all();
    std::vector<QueryResult> results;
    
    for (const auto& record : all_records) {
        if (record.key >= start_key && record.key <= end_key) {
            results.emplace_back(record.key, record.value, record.timestamp);
        }
    }
    
    // Sort by key for consistent ordering
    std::sort(results.begin(), results.end(), 
              [](const QueryResult& a, const QueryResult& b) {
                  return a.key < b.key;
              });
    
    return results;
}

std::vector<QueryResult> QueryEngine::prefix_query(const std::string& prefix) {
    auto all_records = storage_->get_all();
    std::vector<QueryResult> results;
    
    for (const auto& record : all_records) {
        if (record.key.starts_with(prefix)) {
            results.emplace_back(record.key, record.value, record.timestamp);
        }
    }
    
    std::sort(results.begin(), results.end(),
              [](const QueryResult& a, const QueryResult& b) {
                  return a.key < b.key;
              });
    
    return results;
}

std::vector<QueryResult> QueryEngine::pattern_query(const std::string& pattern) {
    auto all_records = storage_->get_all();
    std::vector<QueryResult> results;
    
    for (const auto& record : all_records) {
        if (matches_pattern(record.key, pattern)) {
            results.emplace_back(record.key, record.value, record.timestamp);
        }
    }
    
    std::sort(results.begin(), results.end(),
              [](const QueryResult& a, const QueryResult& b) {
                  return a.key < b.key;
              });
    
    return results;
}

std::vector<QueryResult> QueryEngine::scan_all(const QueryCondition& condition) {
    auto all_records = storage_->get_all();
    std::vector<QueryResult> results;
    
    for (const auto& record : all_records) {
        QueryResult result(record.key, record.value, record.timestamp);
        if (matches_condition(result, condition)) {
            results.push_back(result);
        }
    }
    
    return results;
}

size_t QueryEngine::count_keys() const {
    return storage_->get_all().size();
}

size_t QueryEngine::count_matching(const QueryCondition& condition) const {
    auto all_records = storage_->get_all();
    size_t count = 0;
    
    for (const auto& record : all_records) {
        QueryResult result(record.key, record.value, record.timestamp);
        if (matches_condition(result, condition)) {
            count++;
        }
    }
    
    return count;
}

std::vector<std::string> QueryEngine::get_query_statistics() const {
    std::vector<std::string> stats;
    stats.push_back("Queries executed: " + std::to_string(queries_executed_));
    stats.push_back("Cache hits: " + std::to_string(cache_hits_));
    stats.push_back("Full scans performed: " + std::to_string(full_scans_performed_));
    return stats;
}

bool QueryEngine::matches_pattern(const std::string& text, const std::string& pattern) const {
    // Convert wildcard pattern to regex
    std::string regex_pattern;
    for (char c : pattern) {
        switch (c) {
            case '*':
                regex_pattern += ".*";
                break;
            case '?':
                regex_pattern += ".";
                break;
            case '.':
            case '^':
            case '$':
            case '+':
            case '(':
            case ')':
            case '[':
            case ']':
            case '{':
            case '}':
            case '|':
            case '\\':
                regex_pattern += "\\";
                regex_pattern += c;
                break;
            default:
                regex_pattern += c;
        }
    }
    
    std::regex regex(regex_pattern);
    return std::regex_match(text, regex);
}

bool QueryEngine::matches_condition(const QueryResult& result, const QueryCondition& condition) const {
    switch (condition.type) {
        case QueryCondition::Type::ALWAYS_TRUE:
            return true;
            
        case QueryCondition::Type::KEY_EQUALS:
            return result.key == condition.operand1;
            
        case QueryCondition::Type::KEY_PREFIX:
            return result.key.starts_with(condition.operand1);
            
        case QueryCondition::Type::KEY_PATTERN:
            return matches_pattern(result.key, condition.operand1);
            
        case QueryCondition::Type::KEY_RANGE:
            return result.key >= condition.operand1 && result.key <= condition.operand2;
            
        case QueryCondition::Type::VALUE_EQUALS:
            return result.value == condition.operand1;
            
        case QueryCondition::Type::VALUE_CONTAINS:
            return result.value.find(condition.operand1) != std::string::npos;
    }
    
    return false;
}

std::vector<QueryResult> QueryEngine::apply_pagination(std::vector<QueryResult> results, 
                                                       int limit, int offset) const {
    if (offset > 0) {
        if (static_cast<size_t>(offset) >= results.size()) {
            return {}; // Offset beyond results
        }
        results.erase(results.begin(), results.begin() + offset);
    }
    
    if (limit > 0 && static_cast<size_t>(limit) < results.size()) {
        results.resize(limit);
    }
    
    return results;
}

size_t QueryEngine::estimate_range_cost(const std::string& start_key, const std::string& end_key) const {
    // Estimate based on key space - in a real implementation, 
    // we'd use index statistics
    return 100; // Placeholder cost
}

size_t QueryEngine::estimate_prefix_cost(const std::string& prefix) const {
    // Estimate based on prefix selectivity
    return 50 + prefix.length() * 10; // Placeholder cost
}

size_t QueryEngine::estimate_scan_cost() const {
    // Full scan cost proportional to table size
    return count_keys();
}

QueryOp QueryEngine::parse_operation(const std::string& op_string) {
    if (op_string == "GET") return QueryOp::GET;
    if (op_string == "RANGE") return QueryOp::RANGE;
    if (op_string == "PREFIX") return QueryOp::PREFIX;
    if (op_string == "PATTERN") return QueryOp::PATTERN;
    if (op_string == "SCAN") return QueryOp::SCAN;
    if (op_string == "COUNT") return QueryOp::COUNT;
    
    throw std::invalid_argument("Unknown operation: " + op_string);
}

QueryCondition QueryEngine::parse_where_clause(const std::string& where_clause) {
    // Simple WHERE clause parsing - in production this would be more sophisticated
    std::istringstream iss(where_clause);
    std::string field, operator_str, value;
    
    if (!(iss >> field >> operator_str >> value)) {
        return QueryCondition{}; // Default to ALWAYS_TRUE
    }
    
    // Remove quotes from value
    if (value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.length() - 2);
    }
    
    if (field == "KEY") {
        if (operator_str == "=") {
            return QueryCondition(QueryCondition::Type::KEY_EQUALS, value);
        } else if (operator_str == "LIKE") {
            return QueryCondition(QueryCondition::Type::KEY_PATTERN, value);
        }
    } else if (field == "VALUE") {
        if (operator_str == "=") {
            return QueryCondition(QueryCondition::Type::VALUE_EQUALS, value);
        } else if (operator_str == "CONTAINS") {
            return QueryCondition(QueryCondition::Type::VALUE_CONTAINS, value);
        }
    }
    
    return QueryCondition{}; // Default fallback
}

std::pair<int, int> QueryEngine::parse_limit_offset(const std::string& limit_clause) {
    // This would parse complex LIMIT/OFFSET clauses
    return {-1, 0}; // Placeholder
}

} // namespace nosql_db::query