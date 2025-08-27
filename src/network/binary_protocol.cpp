#include "network/binary_protocol.hpp"
#include <cstring>
#include <algorithm>
#include <sstream>

namespace ishikura::network {

// BinaryMessage implementation
BinaryMessage::BinaryMessage(MessageType type, uint64_t id) : header_(), data_() {
    header_.message_type = static_cast<uint32_t>(type);
    header_.message_id = id;
}

bool BinaryMessage::has_flag(MessageFlags flag) const {
    return (header_.flags & static_cast<uint32_t>(flag)) != 0;
}

void BinaryMessage::set_flag(MessageFlags flag) {
    header_.flags |= static_cast<uint32_t>(flag);
}

void BinaryMessage::clear_flag(MessageFlags flag) {
    header_.flags &= ~static_cast<uint32_t>(flag);
}

void BinaryMessage::set_data(const std::vector<uint8_t>& data) {
    data_ = data;
    update_data_length();
}

void BinaryMessage::set_data(std::vector<uint8_t>&& data) {
    data_ = std::move(data);
    update_data_length();
}

void BinaryMessage::set_data(const void* data, size_t size) {
    data_.assign(static_cast<const uint8_t*>(data), 
                static_cast<const uint8_t*>(data) + size);
    update_data_length();
}

void BinaryMessage::set_data(std::string_view str) {
    set_data(str.data(), str.size());
}

std::string BinaryMessage::data_as_string() const {
    return std::string(reinterpret_cast<const char*>(data_.data()), data_.size());
}

void BinaryMessage::clear_data() {
    data_.clear();
    header_.data_length = 0;
}

std::vector<uint8_t> BinaryMessage::serialize() const {
    std::vector<uint8_t> buffer;
    buffer.reserve(HEADER_SIZE + data_.size());
    
    // Serialize header
    const uint8_t* header_bytes = reinterpret_cast<const uint8_t*>(&header_);
    buffer.insert(buffer.end(), header_bytes, header_bytes + HEADER_SIZE);
    
    // Append data
    if (!data_.empty()) {
        buffer.insert(buffer.end(), data_.begin(), data_.end());
    }
    
    return buffer;
}

bool BinaryMessage::deserialize(const std::vector<uint8_t>& buffer) {
    return deserialize(buffer.data(), buffer.size());
}

bool BinaryMessage::deserialize(const void* buffer, size_t size) {
    if (size < HEADER_SIZE) {
        return false;
    }
    
    // Copy header
    std::memcpy(&header_, buffer, HEADER_SIZE);
    
    // Validate header
    if (header_.magic != PROTOCOL_MAGIC || 
        header_.version != PROTOCOL_VERSION ||
        header_.data_length > MAX_MESSAGE_SIZE) {
        return false;
    }
    
    // Check if we have enough data
    if (size < HEADER_SIZE + header_.data_length) {
        return false;
    }
    
    // Copy data if present
    data_.clear();
    if (header_.data_length > 0) {
        const uint8_t* data_start = static_cast<const uint8_t*>(buffer) + HEADER_SIZE;
        data_.assign(data_start, data_start + header_.data_length);
    }
    
    return true;
}

bool BinaryMessage::is_valid() const {
    return header_.magic == PROTOCOL_MAGIC && 
           header_.version == PROTOCOL_VERSION &&
           header_.data_length == data_.size() &&
           header_.data_length <= MAX_MESSAGE_SIZE;
}

// MessageBuilder implementation
namespace MessageBuilder {

BinaryMessage create_put_request(uint64_t message_id, std::string_view key, std::string_view value) {
    BinaryMessage msg(MessageType::PUT_REQUEST, message_id);
    msg.set_flag(MessageFlags::EXPECTS_RESPONSE);
    
    // Data format: [4 bytes: key_length] [key] [value]
    std::vector<uint8_t> data;
    uint32_t key_length = static_cast<uint32_t>(key.size());
    
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&key_length), 
                reinterpret_cast<const uint8_t*>(&key_length) + 4);
    data.insert(data.end(), key.begin(), key.end());
    data.insert(data.end(), value.begin(), value.end());
    
    msg.set_data(std::move(data));
    return msg;
}

BinaryMessage create_put_response(uint64_t message_id, StatusCode status) {
    BinaryMessage msg(MessageType::PUT_RESPONSE, message_id);
    msg.set_flag(MessageFlags::IS_RESPONSE);
    
    uint32_t status_code = static_cast<uint32_t>(status);
    msg.set_data(&status_code, sizeof(status_code));
    return msg;
}

BinaryMessage create_get_request(uint64_t message_id, std::string_view key) {
    BinaryMessage msg(MessageType::GET_REQUEST, message_id);
    msg.set_flag(MessageFlags::EXPECTS_RESPONSE);
    msg.set_data(key);
    return msg;
}

BinaryMessage create_get_response(uint64_t message_id, StatusCode status, std::string_view value) {
    BinaryMessage msg(MessageType::GET_RESPONSE, message_id);
    msg.set_flag(MessageFlags::IS_RESPONSE);
    
    // Data format: [4 bytes: status] [value]
    std::vector<uint8_t> data;
    uint32_t status_code = static_cast<uint32_t>(status);
    
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&status_code), 
                reinterpret_cast<const uint8_t*>(&status_code) + 4);
    data.insert(data.end(), value.begin(), value.end());
    
    msg.set_data(std::move(data));
    return msg;
}

BinaryMessage create_delete_request(uint64_t message_id, std::string_view key) {
    BinaryMessage msg(MessageType::DELETE_REQUEST, message_id);
    msg.set_flag(MessageFlags::EXPECTS_RESPONSE);
    msg.set_data(key);
    return msg;
}

BinaryMessage create_delete_response(uint64_t message_id, StatusCode status) {
    BinaryMessage msg(MessageType::DELETE_RESPONSE, message_id);
    msg.set_flag(MessageFlags::IS_RESPONSE);
    
    uint32_t status_code = static_cast<uint32_t>(status);
    msg.set_data(&status_code, sizeof(status_code));
    return msg;
}

BinaryMessage create_query_request(uint64_t message_id, std::string_view query) {
    BinaryMessage msg(MessageType::QUERY_REQUEST, message_id);
    msg.set_flag(MessageFlags::EXPECTS_RESPONSE);
    msg.set_data(query);
    return msg;
}

BinaryMessage create_query_response(uint64_t message_id, StatusCode status, 
                                   const std::vector<std::pair<std::string, std::string>>& results) {
    BinaryMessage msg(MessageType::QUERY_RESPONSE, message_id);
    msg.set_flag(MessageFlags::IS_RESPONSE);
    
    // Data format: [4 bytes: status] [4 bytes: result_count] [results...]
    // Each result: [4 bytes: key_length] [key] [4 bytes: value_length] [value]
    std::vector<uint8_t> data;
    
    uint32_t status_code = static_cast<uint32_t>(status);
    uint32_t result_count = static_cast<uint32_t>(results.size());
    
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&status_code), 
                reinterpret_cast<const uint8_t*>(&status_code) + 4);
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&result_count), 
                reinterpret_cast<const uint8_t*>(&result_count) + 4);
    
    for (const auto& [key, value] : results) {
        uint32_t key_length = static_cast<uint32_t>(key.size());
        uint32_t value_length = static_cast<uint32_t>(value.size());
        
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&key_length), 
                    reinterpret_cast<const uint8_t*>(&key_length) + 4);
        data.insert(data.end(), key.begin(), key.end());
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&value_length), 
                    reinterpret_cast<const uint8_t*>(&value_length) + 4);
        data.insert(data.end(), value.begin(), value.end());
    }
    
    msg.set_data(std::move(data));
    return msg;
}

BinaryMessage create_ping(uint64_t message_id) {
    BinaryMessage msg(MessageType::PING, message_id);
    msg.set_flag(MessageFlags::EXPECTS_RESPONSE);
    return msg;
}

BinaryMessage create_pong(uint64_t message_id) {
    BinaryMessage msg(MessageType::PONG, message_id);
    msg.set_flag(MessageFlags::IS_RESPONSE);
    return msg;
}

BinaryMessage create_error(uint64_t message_id, StatusCode status, std::string_view error_message) {
    BinaryMessage msg(MessageType::ERROR, message_id);
    msg.set_flag(MessageFlags::IS_RESPONSE);
    
    // Data format: [4 bytes: status] [error_message]
    std::vector<uint8_t> data;
    uint32_t status_code = static_cast<uint32_t>(status);
    
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&status_code), 
                reinterpret_cast<const uint8_t*>(&status_code) + 4);
    data.insert(data.end(), error_message.begin(), error_message.end());
    
    msg.set_data(std::move(data));
    return msg;
}

BinaryMessage create_batch_request(uint64_t message_id, const std::vector<BinaryMessage>& operations) {
    BinaryMessage msg(MessageType::BATCH_REQUEST, message_id);
    msg.set_flag(MessageFlags::EXPECTS_RESPONSE);
    
    // Data format: [4 bytes: operation_count] [serialized operations...]
    std::vector<uint8_t> data;
    uint32_t operation_count = static_cast<uint32_t>(operations.size());
    
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&operation_count), 
                reinterpret_cast<const uint8_t*>(&operation_count) + 4);
    
    for (const auto& operation : operations) {
        auto serialized = operation.serialize();
        uint32_t size = static_cast<uint32_t>(serialized.size());
        
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&size), 
                    reinterpret_cast<const uint8_t*>(&size) + 4);
        data.insert(data.end(), serialized.begin(), serialized.end());
    }
    
    msg.set_data(std::move(data));
    return msg;
}

BinaryMessage create_batch_response(uint64_t message_id, StatusCode status, 
                                   const std::vector<StatusCode>& operation_results) {
    BinaryMessage msg(MessageType::BATCH_RESPONSE, message_id);
    msg.set_flag(MessageFlags::IS_RESPONSE);
    
    // Data format: [4 bytes: overall_status] [4 bytes: result_count] [4 bytes each: results]
    std::vector<uint8_t> data;
    uint32_t overall_status = static_cast<uint32_t>(status);
    uint32_t result_count = static_cast<uint32_t>(operation_results.size());
    
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&overall_status), 
                reinterpret_cast<const uint8_t*>(&overall_status) + 4);
    data.insert(data.end(), reinterpret_cast<const uint8_t*>(&result_count), 
                reinterpret_cast<const uint8_t*>(&result_count) + 4);
    
    for (StatusCode result : operation_results) {
        uint32_t result_code = static_cast<uint32_t>(result);
        data.insert(data.end(), reinterpret_cast<const uint8_t*>(&result_code), 
                    reinterpret_cast<const uint8_t*>(&result_code) + 4);
    }
    
    msg.set_data(std::move(data));
    return msg;
}

} // namespace MessageBuilder

// MessageParser implementation
namespace MessageParser {

std::optional<PutData> parse_put_request(const BinaryMessage& msg) {
    if (msg.type() != MessageType::PUT_REQUEST || msg.data_size() < 4) {
        return std::nullopt;
    }
    
    const auto& data = msg.data();
    uint32_t key_length;
    std::memcpy(&key_length, data.data(), 4);
    
    if (data.size() < 4 + key_length) {
        return std::nullopt;
    }
    
    PutData result;
    result.key = std::string(data.begin() + 4, data.begin() + 4 + key_length);
    result.value = std::string(data.begin() + 4 + key_length, data.end());
    
    return result;
}

std::optional<GetData> parse_get_request(const BinaryMessage& msg) {
    if (msg.type() != MessageType::GET_REQUEST) {
        return std::nullopt;
    }
    
    GetData result;
    result.key = msg.data_as_string();
    return result;
}

std::optional<DeleteData> parse_delete_request(const BinaryMessage& msg) {
    if (msg.type() != MessageType::DELETE_REQUEST) {
        return std::nullopt;
    }
    
    DeleteData result;
    result.key = msg.data_as_string();
    return result;
}

std::optional<QueryData> parse_query_request(const BinaryMessage& msg) {
    if (msg.type() != MessageType::QUERY_REQUEST) {
        return std::nullopt;
    }
    
    QueryData result;
    result.query = msg.data_as_string();
    return result;
}

ResponseData parse_response(const BinaryMessage& msg) {
    ResponseData result;
    result.status = StatusCode::PROTOCOL_ERROR;
    
    if (msg.data_size() < 4) {
        return result;
    }
    
    const auto& data = msg.data();
    uint32_t status_code;
    std::memcpy(&status_code, data.data(), 4);
    result.status = static_cast<StatusCode>(status_code);
    
    if (msg.type() == MessageType::GET_RESPONSE && data.size() > 4) {
        result.data = std::string(data.begin() + 4, data.end());
    } else if (msg.type() == MessageType::QUERY_RESPONSE && data.size() > 8) {
        uint32_t result_count;
        std::memcpy(&result_count, data.data() + 4, 4);
        
        size_t offset = 8;
        for (uint32_t i = 0; i < result_count && offset < data.size(); ++i) {
            if (offset + 4 > data.size()) break;
            
            uint32_t key_length;
            std::memcpy(&key_length, data.data() + offset, 4);
            offset += 4;
            
            if (offset + key_length > data.size()) break;
            std::string key(data.begin() + offset, data.begin() + offset + key_length);
            offset += key_length;
            
            if (offset + 4 > data.size()) break;
            uint32_t value_length;
            std::memcpy(&value_length, data.data() + offset, 4);
            offset += 4;
            
            if (offset + value_length > data.size()) break;
            std::string value(data.begin() + offset, data.begin() + offset + value_length);
            offset += value_length;
            
            result.results.emplace_back(std::move(key), std::move(value));
        }
    }
    
    return result;
}

std::vector<BinaryMessage> parse_batch_request(const BinaryMessage& msg) {
    std::vector<BinaryMessage> operations;
    
    if (msg.type() != MessageType::BATCH_REQUEST || msg.data_size() < 4) {
        return operations;
    }
    
    const auto& data = msg.data();
    uint32_t operation_count;
    std::memcpy(&operation_count, data.data(), 4);
    
    size_t offset = 4;
    for (uint32_t i = 0; i < operation_count && offset < data.size(); ++i) {
        if (offset + 4 > data.size()) break;
        
        uint32_t operation_size;
        std::memcpy(&operation_size, data.data() + offset, 4);
        offset += 4;
        
        if (offset + operation_size > data.size()) break;
        
        BinaryMessage operation;
        if (operation.deserialize(data.data() + offset, operation_size)) {
            operations.push_back(std::move(operation));
        }
        offset += operation_size;
    }
    
    return operations;
}

std::vector<StatusCode> parse_batch_response(const BinaryMessage& msg) {
    std::vector<StatusCode> results;
    
    if (msg.type() != MessageType::BATCH_RESPONSE || msg.data_size() < 8) {
        return results;
    }
    
    const auto& data = msg.data();
    uint32_t result_count;
    std::memcpy(&result_count, data.data() + 4, 4); // Skip overall status
    
    size_t offset = 8;
    for (uint32_t i = 0; i < result_count && offset + 4 <= data.size(); ++i) {
        uint32_t result_code;
        std::memcpy(&result_code, data.data() + offset, 4);
        results.push_back(static_cast<StatusCode>(result_code));
        offset += 4;
    }
    
    return results;
}

} // namespace MessageParser

} // namespace ishikura::network