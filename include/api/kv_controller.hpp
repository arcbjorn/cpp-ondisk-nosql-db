#pragma once

#include <httplib.h>
#include <nlohmann/json.hpp>
#include "storage/storage_engine.hpp"
#include "storage/transaction.hpp"
#include <memory>
#include <string_view>

namespace ishikura::api {

class KvController {
public:
    explicit KvController(std::shared_ptr<storage::StorageEngine> storage);
    
    // Register all routes with the HTTP server
    void register_routes(httplib::Server& server);

private:
    std::shared_ptr<storage::StorageEngine> storage_;
    std::unique_ptr<storage::TransactionManager> transaction_manager_;
    
    // Route handlers
    void handle_put_key(const httplib::Request& req, httplib::Response& res);
    void handle_get_key(const httplib::Request& req, httplib::Response& res);
    void handle_delete_key(const httplib::Request& req, httplib::Response& res);
    void handle_list_keys(const httplib::Request& req, httplib::Response& res);
    void handle_health(const httplib::Request& req, httplib::Response& res);
    
    // Utility functions
    void send_json_response(httplib::Response& res, int status, const nlohmann::json& data);
    void send_error_response(httplib::Response& res, int status, const std::string& message);
    bool is_valid_key(std::string_view key);
};

} // namespace ishikura::api