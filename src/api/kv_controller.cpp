#include "api/kv_controller.hpp"
#include <spdlog/spdlog.h>
#include <regex>

using json = nlohmann::json;

namespace nosql_db::api {

KvController::KvController(std::shared_ptr<storage::LogStorage> storage)
    : storage_(std::move(storage)) {}

void KvController::register_routes(httplib::Server& server) {
    // Enable CORS for web clients
    server.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // Handle OPTIONS requests (CORS preflight)
    server.Options(R"(/api/v1/.*)", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
        return;
    });

    // Key-value operations
    server.Put(R"(/api/v1/kv/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
        handle_put_key(req, res);
    });

    server.Get(R"(/api/v1/kv/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
        handle_get_key(req, res);
    });

    server.Delete(R"(/api/v1/kv/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
        handle_delete_key(req, res);
    });

    // List all keys (with optional pagination)
    server.Get("/api/v1/kv", [this](const httplib::Request& req, httplib::Response& res) {
        handle_list_keys(req, res);
    });

    // Health check
    server.Get("/api/v1/health", [this](const httplib::Request& req, httplib::Response& res) {
        handle_health(req, res);
    });

    // Default 404 handler (only if no content already set)
    server.set_error_handler([this](const httplib::Request&, httplib::Response& res) {
        if (res.status == 404 && res.body.empty()) {
            send_error_response(res, 404, "Endpoint not found");
        }
    });
}

void KvController::handle_put_key(const httplib::Request& req, httplib::Response& res) {
    try {
        const std::string key = req.matches[1];
        
        if (!is_valid_key(key)) {
            send_error_response(res, 400, "Invalid key format");
            return;
        }

        if (req.body.empty()) {
            send_error_response(res, 400, "Request body cannot be empty");
            return;
        }

        // Validate JSON if Content-Type is application/json
        if (req.get_header_value("Content-Type") == "application/json") {
            try {
                json::parse(req.body); // Validate JSON format
            } catch (const json::exception& e) {
                send_error_response(res, 400, "Invalid JSON format: " + std::string(e.what()));
                return;
            }
        }

        bool success = storage_->append(key, req.body);
        if (!success) {
            send_error_response(res, 500, "Failed to store key-value pair");
            return;
        }

        json response = {
            {"key", key},
            {"status", "stored"},
            {"size", req.body.size()}
        };

        send_json_response(res, 201, response);
        spdlog::info("PUT /api/v1/kv/{} - {} bytes", key, req.body.size());

    } catch (const std::exception& e) {
        spdlog::error("Error in PUT handler: {}", e.what());
        send_error_response(res, 500, "Internal server error");
    }
}

void KvController::handle_get_key(const httplib::Request& req, httplib::Response& res) {
    try {
        const std::string key = req.matches[1];
        
        if (!is_valid_key(key)) {
            send_error_response(res, 400, "Invalid key format");
            return;
        }

        auto value = storage_->get(key);
        if (!value) {
            send_error_response(res, 404, "Key not found");
            return;
        }
        
        // Handle tombstones (deleted keys) as empty response
        if (*value == "__DELETED__") {
            res.set_content("", "text/plain");
            res.status = 200;
            spdlog::debug("GET /api/v1/kv/{} - tombstone (deleted)", key);
            return;
        }

        // Try to parse as JSON and return structured response, or raw value
        try {
            auto parsed = json::parse(*value);
            res.set_content(value->c_str(), "application/json");
        } catch (const json::exception&) {
            // Not valid JSON, return as plain text
            res.set_content(value->c_str(), "text/plain");
        }

        res.status = 200;
        spdlog::debug("GET /api/v1/kv/{} - {} bytes", key, value->size());

    } catch (const std::exception& e) {
        spdlog::error("Error in GET handler: {}", e.what());
        send_error_response(res, 500, "Internal server error");
    }
}

void KvController::handle_delete_key(const httplib::Request& req, httplib::Response& res) {
    try {
        const std::string key = req.matches[1];
        
        if (!is_valid_key(key)) {
            send_error_response(res, 400, "Invalid key format");
            return;
        }

        // Check if key exists before deletion
        auto existing_value = storage_->get(key);
        if (!existing_value) {
            send_error_response(res, 404, "Key not found");
            return;
        }

        // Store a tombstone marker (empty value could represent deletion)
        // In a full implementation, you might want a separate deletion mechanism
        bool success = storage_->append(key, "__DELETED__"); // Tombstone marker
        storage_->sync(); // Ensure data is flushed to disk
        if (!success) {
            send_error_response(res, 500, "Failed to delete key");
            return;
        }

        res.status = 204; // No Content
        spdlog::info("DELETE /api/v1/kv/{}", key);

    } catch (const std::exception& e) {
        spdlog::error("Error in DELETE handler: {}", e.what());
        send_error_response(res, 500, "Internal server error");
    }
}

void KvController::handle_list_keys(const httplib::Request& req, httplib::Response& res) {
    try {
        // Get pagination parameters
        int offset = 0;
        int limit = 100; // Default limit
        
        if (req.has_param("offset")) {
            offset = std::stoi(req.get_param_value("offset"));
            offset = std::max(0, offset);
        }
        
        if (req.has_param("limit")) {
            limit = std::stoi(req.get_param_value("limit"));
            limit = std::clamp(limit, 1, 1000); // Max 1000 items per request
        }

        auto records = storage_->get_all();
        
        // Build unique key list (latest values only)
        std::unordered_map<std::string, std::string> unique_keys;
        for (const auto& record : records) {
            // Skip tombstones (deleted keys)
            if (record.value != "__DELETED__") {
                unique_keys[record.key] = record.value;
            } else {
                unique_keys.erase(record.key); // Remove deleted keys
            }
        }

        // Apply pagination
        json keys_array = json::array();
        int current = 0;
        int added = 0;
        
        for (const auto& [key, value] : unique_keys) {
            if (current >= offset && added < limit) {
                keys_array.push_back({
                    {"key", key},
                    {"size", value.size()}
                });
                added++;
            }
            current++;
            if (added >= limit) break;
        }

        json response = {
            {"keys", keys_array},
            {"total", unique_keys.size()},
            {"offset", offset},
            {"limit", limit},
            {"count", added}
        };

        send_json_response(res, 200, response);
        spdlog::debug("GET /api/v1/kv - returned {} keys (offset={}, limit={})", added, offset, limit);

    } catch (const std::exception& e) {
        spdlog::error("Error in list keys handler: {}", e.what());
        send_error_response(res, 500, "Internal server error");
    }
}

void KvController::handle_health(const httplib::Request& req, httplib::Response& res) {
    json response = {
        {"status", "healthy"},
        {"service", "nosql-db"},
        {"version", "1.0.0"},
        {"storage", "available"}
    };

    send_json_response(res, 200, response);
}

void KvController::send_json_response(httplib::Response& res, int status, const nlohmann::json& data) {
    res.status = status;
    res.set_content(data.dump(2), "application/json");
}

void KvController::send_error_response(httplib::Response& res, int status, const std::string& message) {
    json error_response = {
        {"error", message},
        {"status", status}
    };
    send_json_response(res, status, error_response);
}

bool KvController::is_valid_key(std::string_view key) {
    // Key validation: non-empty, reasonable length, no control characters
    if (key.empty() || key.length() > 256) {
        return false;
    }
    
    // Check for control characters and ensure printable ASCII
    for (char c : key) {
        if (c < 32 || c > 126) {
            return false;
        }
    }
    
    return true;
}

} // namespace nosql_db::api