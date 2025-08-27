#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <memory>

namespace ishikura::network {

/**
 * Binary protocol for high-performance client-server communication
 * 
 * Message Format:
 * [4 bytes: magic] [4 bytes: version] [4 bytes: message_type] [4 bytes: flags] 
 * [8 bytes: message_id] [4 bytes: data_length] [N bytes: data]
 * 
 * Total header size: 32 bytes
 * Data follows immediately after header
 */

// Protocol constants
constexpr uint32_t PROTOCOL_MAGIC = 0x4E4F5351; // "NOSQ"
constexpr uint32_t PROTOCOL_VERSION = 1;
constexpr size_t HEADER_SIZE = 32;
constexpr size_t MAX_MESSAGE_SIZE = 64 * 1024 * 1024; // 64MB

// Message types
enum class MessageType : uint32_t {
    // Basic operations
    PUT_REQUEST = 0x0001,
    PUT_RESPONSE = 0x0002,
    GET_REQUEST = 0x0003,
    GET_RESPONSE = 0x0004,
    DELETE_REQUEST = 0x0005,
    DELETE_RESPONSE = 0x0006,
    
    // Batch operations
    BATCH_REQUEST = 0x0010,
    BATCH_RESPONSE = 0x0011,
    
    // Query operations
    QUERY_REQUEST = 0x0020,
    QUERY_RESPONSE = 0x0021,
    
    // Streaming operations
    STREAM_START = 0x0030,
    STREAM_DATA = 0x0031,
    STREAM_END = 0x0032,
    
    // Control messages
    PING = 0x0100,
    PONG = 0x0101,
    AUTH_REQUEST = 0x0102,
    AUTH_RESPONSE = 0x0103,
    ERROR = 0x0104,
    
    // Connection management
    CONNECT = 0x0200,
    DISCONNECT = 0x0201,
    HEARTBEAT = 0x0202
};

// Message flags
enum class MessageFlags : uint32_t {
    NONE = 0x0000,
    COMPRESSED = 0x0001,        // Data is compressed
    ENCRYPTED = 0x0002,         // Data is encrypted
    FRAGMENTED = 0x0004,        // Message is fragmented
    LAST_FRAGMENT = 0x0008,     // Last fragment in sequence
    EXPECTS_RESPONSE = 0x0010,  // Client expects a response
    IS_RESPONSE = 0x0020        // This is a response message
};

// Status codes for responses
enum class StatusCode : uint32_t {
    SUCCESS = 0,
    KEY_NOT_FOUND = 1,
    INVALID_REQUEST = 2,
    STORAGE_ERROR = 3,
    PROTOCOL_ERROR = 4,
    AUTHENTICATION_FAILED = 5,
    AUTHORIZATION_FAILED = 6,
    RATE_LIMITED = 7,
    SERVER_ERROR = 8,
    UNSUPPORTED_VERSION = 9,
    MESSAGE_TOO_LARGE = 10
};

#pragma pack(push, 1)
struct MessageHeader {
    uint32_t magic;         // Protocol magic number
    uint32_t version;       // Protocol version
    uint32_t message_type;  // MessageType enum value
    uint32_t flags;         // MessageFlags bitfield
    uint64_t message_id;    // Unique message identifier
    uint32_t data_length;   // Length of data following header
    uint32_t reserved;      // Reserved for future use
    
    MessageHeader() : magic(PROTOCOL_MAGIC), version(PROTOCOL_VERSION),
                     message_type(0), flags(0), message_id(0), 
                     data_length(0), reserved(0) {}
};
#pragma pack(pop)

static_assert(sizeof(MessageHeader) == HEADER_SIZE, "MessageHeader must be exactly 32 bytes");

/**
 * Binary message container for protocol communication
 */
class BinaryMessage {
public:
    BinaryMessage() = default;
    explicit BinaryMessage(MessageType type, uint64_t id = 0);
    
    // Header access
    const MessageHeader& header() const { return header_; }
    MessageHeader& header() { return header_; }
    
    // Message identification
    MessageType type() const { return static_cast<MessageType>(header_.message_type); }
    void set_type(MessageType type) { header_.message_type = static_cast<uint32_t>(type); }
    
    uint64_t message_id() const { return header_.message_id; }
    void set_message_id(uint64_t id) { header_.message_id = id; }
    
    // Flags management
    bool has_flag(MessageFlags flag) const;
    void set_flag(MessageFlags flag);
    void clear_flag(MessageFlags flag);
    
    // Data management
    const std::vector<uint8_t>& data() const { return data_; }
    std::vector<uint8_t>& data() { return data_; }
    
    void set_data(const std::vector<uint8_t>& data);
    void set_data(std::vector<uint8_t>&& data);
    void set_data(const void* data, size_t size);
    void set_data(std::string_view str);
    
    // String helpers
    std::string data_as_string() const;
    void clear_data();
    
    // Serialization
    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& buffer);
    bool deserialize(const void* buffer, size_t size);
    
    // Size information
    size_t total_size() const { return HEADER_SIZE + header_.data_length; }
    size_t data_size() const { return header_.data_length; }
    
    // Validation
    bool is_valid() const;
    
private:
    MessageHeader header_;
    std::vector<uint8_t> data_;
    
    void update_data_length() { header_.data_length = static_cast<uint32_t>(data_.size()); }
};

/**
 * Request/Response message builders for common operations
 */
namespace MessageBuilder {
    
    // PUT operation messages
    BinaryMessage create_put_request(uint64_t message_id, std::string_view key, std::string_view value);
    BinaryMessage create_put_response(uint64_t message_id, StatusCode status);
    
    // GET operation messages  
    BinaryMessage create_get_request(uint64_t message_id, std::string_view key);
    BinaryMessage create_get_response(uint64_t message_id, StatusCode status, std::string_view value = "");
    
    // DELETE operation messages
    BinaryMessage create_delete_request(uint64_t message_id, std::string_view key);
    BinaryMessage create_delete_response(uint64_t message_id, StatusCode status);
    
    // Query operation messages
    BinaryMessage create_query_request(uint64_t message_id, std::string_view query);
    BinaryMessage create_query_response(uint64_t message_id, StatusCode status, 
                                       const std::vector<std::pair<std::string, std::string>>& results = {});
    
    // Control messages
    BinaryMessage create_ping(uint64_t message_id);
    BinaryMessage create_pong(uint64_t message_id);
    BinaryMessage create_error(uint64_t message_id, StatusCode status, std::string_view error_message = "");
    
    // Batch operation messages
    BinaryMessage create_batch_request(uint64_t message_id, const std::vector<BinaryMessage>& operations);
    BinaryMessage create_batch_response(uint64_t message_id, StatusCode status, 
                                       const std::vector<StatusCode>& operation_results = {});
}

/**
 * Message parser utilities
 */
namespace MessageParser {
    
    // Parse request data
    struct PutData { std::string key, value; };
    struct GetData { std::string key; };
    struct DeleteData { std::string key; };
    struct QueryData { std::string query; };
    
    std::optional<PutData> parse_put_request(const BinaryMessage& msg);
    std::optional<GetData> parse_get_request(const BinaryMessage& msg);
    std::optional<DeleteData> parse_delete_request(const BinaryMessage& msg);
    std::optional<QueryData> parse_query_request(const BinaryMessage& msg);
    
    // Parse response data
    struct ResponseData { 
        StatusCode status; 
        std::string data; 
        std::vector<std::pair<std::string, std::string>> results; 
    };
    
    ResponseData parse_response(const BinaryMessage& msg);
    std::vector<BinaryMessage> parse_batch_request(const BinaryMessage& msg);
    std::vector<StatusCode> parse_batch_response(const BinaryMessage& msg);
}

} // namespace ishikura::network