#include "network/binary_server.hpp"
#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <cstring>
#include <thread>

namespace nosql_db::network {

BinaryClient::BinaryClient() : BinaryClient(ClientConfig{}) {
}

BinaryClient::BinaryClient(const ClientConfig& config)
    : config_(config), socket_fd_(-1), connected_(false), next_message_id_(1) {
    spdlog::debug("BinaryClient initialized for {}:{}", config_.host, config_.port);
}

BinaryClient::~BinaryClient() {
    disconnect();
}

bool BinaryClient::connect() {
    if (connected_.load()) {
        spdlog::warn("BinaryClient already connected");
        return true;
    }
    
    if (!create_socket()) {
        return false;
    }
    
    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config_.port);
    
    if (inet_pton(AF_INET, config_.host.c_str(), &server_addr.sin_addr) <= 0) {
        spdlog::error("Invalid server address: {}", config_.host);
        close_socket();
        return false;
    }
    
    // Set socket timeout for connect
    struct timeval timeout;
    timeout.tv_sec = config_.connection_timeout.count();
    timeout.tv_usec = 0;
    
    if (setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(socket_fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        spdlog::warn("Failed to set socket timeout: {}", strerror(errno));
    }
    
    // Connect to server
    if (::connect(socket_fd_, reinterpret_cast<struct sockaddr*>(&server_addr), 
                 sizeof(server_addr)) < 0) {
        spdlog::error("Failed to connect to {}:{}: {}", config_.host, config_.port, strerror(errno));
        close_socket();
        return false;
    }
    
    connected_.store(true);
    spdlog::info("Connected to {}:{}", config_.host, config_.port);
    return true;
}

void BinaryClient::disconnect() {
    if (!connected_.load()) {
        return;
    }
    
    connected_.store(false);
    close_socket();
    spdlog::info("Disconnected from {}:{}", config_.host, config_.port);
}

bool BinaryClient::put(const std::string& key, const std::string& value) {
    if (!connected_.load()) {
        spdlog::error("Client not connected");
        return false;
    }
    
    auto request = MessageBuilder::create_put_request(next_message_id_.fetch_add(1), key, value);
    auto response = send_request(request);
    
    if (!response) {
        return false;
    }
    
    auto response_data = MessageParser::parse_response(*response);
    return response_data.status == StatusCode::SUCCESS;
}

std::optional<std::string> BinaryClient::get(const std::string& key) {
    if (!connected_.load()) {
        spdlog::error("Client not connected");
        return std::nullopt;
    }
    
    auto request = MessageBuilder::create_get_request(next_message_id_.fetch_add(1), key);
    auto response = send_request(request);
    
    if (!response) {
        return std::nullopt;
    }
    
    auto response_data = MessageParser::parse_response(*response);
    if (response_data.status == StatusCode::SUCCESS) {
        return response_data.data;
    }
    
    return std::nullopt;
}

bool BinaryClient::delete_key(const std::string& key) {
    if (!connected_.load()) {
        spdlog::error("Client not connected");
        return false;
    }
    
    auto request = MessageBuilder::create_delete_request(next_message_id_.fetch_add(1), key);
    auto response = send_request(request);
    
    if (!response) {
        return false;
    }
    
    auto response_data = MessageParser::parse_response(*response);
    return response_data.status == StatusCode::SUCCESS;
}

std::vector<std::pair<std::string, std::string>> BinaryClient::query(const std::string& query_str) {
    if (!connected_.load()) {
        spdlog::error("Client not connected");
        return {};
    }
    
    auto request = MessageBuilder::create_query_request(next_message_id_.fetch_add(1), query_str);
    auto response = send_request(request);
    
    if (!response) {
        return {};
    }
    
    auto response_data = MessageParser::parse_response(*response);
    if (response_data.status == StatusCode::SUCCESS) {
        return response_data.results;
    }
    
    return {};
}

std::vector<StatusCode> BinaryClient::batch_execute(const std::vector<BatchOperation>& operations) {
    if (!connected_.load()) {
        spdlog::error("Client not connected");
        return {};
    }
    
    // Convert BatchOperations to BinaryMessages
    std::vector<BinaryMessage> messages;
    messages.reserve(operations.size());
    
    for (const auto& op : operations) {
        uint64_t op_id = next_message_id_.fetch_add(1);
        
        switch (op.type) {
            case BatchOperation::PUT:
                messages.push_back(MessageBuilder::create_put_request(op_id, op.key, op.value));
                break;
            case BatchOperation::GET:
                messages.push_back(MessageBuilder::create_get_request(op_id, op.key));
                break;
            case BatchOperation::DELETE:
                messages.push_back(MessageBuilder::create_delete_request(op_id, op.key));
                break;
        }
    }
    
    auto batch_request = MessageBuilder::create_batch_request(next_message_id_.fetch_add(1), messages);
    auto response = send_request(batch_request);
    
    if (!response) {
        return {};
    }
    
    return MessageParser::parse_batch_response(*response);
}

bool BinaryClient::ping() {
    if (!connected_.load()) {
        spdlog::error("Client not connected");
        return false;
    }
    
    auto request = MessageBuilder::create_ping(next_message_id_.fetch_add(1));
    auto response = send_request(request);
    
    return response && response->type() == MessageType::PONG;
}

bool BinaryClient::create_socket() {
    socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd_ < 0) {
        spdlog::error("Failed to create client socket: {}", strerror(errno));
        return false;
    }
    
    return set_socket_options();
}

void BinaryClient::close_socket() {
    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
}

bool BinaryClient::set_socket_options() {
    if (socket_fd_ < 0) {
        return false;
    }
    
    // Enable keepalive if configured
    if (config_.enable_keepalive) {
        int opt = 1;
        if (setsockopt(socket_fd_, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
            spdlog::warn("Failed to set SO_KEEPALIVE: {}", strerror(errno));
        }
    }
    
    // Set TCP_NODELAY for low latency
    int opt = 1;
    if (setsockopt(socket_fd_, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
        spdlog::warn("Failed to set TCP_NODELAY: {}", strerror(errno));
    }
    
    return true;
}

bool BinaryClient::send_message(const BinaryMessage& message) {
    std::lock_guard<std::mutex> lock(socket_mutex_);
    
    if (!connected_.load()) {
        return false;
    }
    
    auto serialized = message.serialize();
    ssize_t bytes_sent = send(socket_fd_, serialized.data(), serialized.size(), MSG_NOSIGNAL);
    
    if (bytes_sent < 0) {
        spdlog::error("Failed to send message: {}", strerror(errno));
        return false;
    }
    
    return bytes_sent == static_cast<ssize_t>(serialized.size());
}

bool BinaryClient::receive_message(BinaryMessage& message) {
    std::lock_guard<std::mutex> lock(socket_mutex_);
    
    if (!connected_.load()) {
        return false;
    }
    
    // Read header first
    MessageHeader header;
    ssize_t bytes_read = recv(socket_fd_, &header, HEADER_SIZE, MSG_WAITALL);
    
    if (bytes_read != HEADER_SIZE) {
        if (bytes_read == 0) {
            spdlog::info("Server closed connection");
        } else {
            spdlog::error("Failed to read message header: {}", strerror(errno));
        }
        return false;
    }
    
    // Validate header
    if (header.magic != PROTOCOL_MAGIC || header.version != PROTOCOL_VERSION) {
        spdlog::error("Invalid message header from server");
        return false;
    }
    
    // Read data if present
    std::vector<uint8_t> buffer(HEADER_SIZE + header.data_length);
    std::memcpy(buffer.data(), &header, HEADER_SIZE);
    
    if (header.data_length > 0) {
        bytes_read = recv(socket_fd_, buffer.data() + HEADER_SIZE, header.data_length, MSG_WAITALL);
        if (bytes_read != static_cast<ssize_t>(header.data_length)) {
            spdlog::error("Failed to read message data: {}", strerror(errno));
            return false;
        }
    }
    
    return message.deserialize(buffer);
}

std::optional<BinaryMessage> BinaryClient::send_request(const BinaryMessage& request) {
    for (size_t attempt = 0; attempt <= config_.max_retries; ++attempt) {
        if (!send_message(request)) {
            if (attempt < config_.max_retries) {
                spdlog::debug("Retrying request (attempt {}/{})", attempt + 1, config_.max_retries);
                std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
                continue;
            }
            return std::nullopt;
        }
        
        BinaryMessage response;
        if (receive_message(response)) {
            // Verify this is a response to our request
            if (response.message_id() == request.message_id() && 
                response.has_flag(MessageFlags::IS_RESPONSE)) {
                return response;
            } else {
                spdlog::warn("Received unexpected response (id: {}, expected: {})", 
                           response.message_id(), request.message_id());
            }
        }
        
        if (attempt < config_.max_retries) {
            spdlog::debug("Retrying request due to response error (attempt {}/{})", 
                         attempt + 1, config_.max_retries);
            std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
        }
    }
    
    return std::nullopt;
}

} // namespace nosql_db::network