#pragma once

#include <httplib.h>
#include <nlohmann/json.hpp>
#include "storage/log_storage.hpp"
#include <memory>
#include <string_view>

namespace nosql_db::api {

class KvController {
public:
    explicit KvController(std::shared_ptr<storage::LogStorage> storage);
    
    // Register all routes with the HTTP server
    void register_routes(httplib::Server& server);

private:
    std::shared_ptr<storage::LogStorage> storage_;
    
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

} // namespace nosql_db::api