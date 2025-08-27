#include <catch2/catch_test_macros.hpp>
#include "network/binary_protocol.hpp"
#include <vector>

using namespace ishikura::network;

TEST_CASE("BinaryMessage basic functionality", "[binary_protocol][basic]") {
    SECTION("Message creation and serialization") {
        BinaryMessage msg(MessageType::PUT_REQUEST, 12345);
        msg.set_data("test_key=test_value");
        
        REQUIRE(msg.type() == MessageType::PUT_REQUEST);
        REQUIRE(msg.message_id() == 12345);
        REQUIRE(msg.data_as_string() == "test_key=test_value");
        REQUIRE(msg.is_valid());
    }
    
    SECTION("Message serialization and deserialization") {
        BinaryMessage original(MessageType::GET_REQUEST, 54321);
        original.set_data("lookup_key");
        original.set_flag(MessageFlags::EXPECTS_RESPONSE);
        
        auto serialized = original.serialize();
        REQUIRE(serialized.size() == HEADER_SIZE + original.data_size());
        
        BinaryMessage deserialized;
        REQUIRE(deserialized.deserialize(serialized));
        
        REQUIRE(deserialized.type() == MessageType::GET_REQUEST);
        REQUIRE(deserialized.message_id() == 54321);
        REQUIRE(deserialized.data_as_string() == "lookup_key");
        REQUIRE(deserialized.has_flag(MessageFlags::EXPECTS_RESPONSE));
    }
    
    SECTION("Flag management") {
        BinaryMessage msg(MessageType::PUT_REQUEST, 1);
        
        REQUIRE_FALSE(msg.has_flag(MessageFlags::COMPRESSED));
        REQUIRE_FALSE(msg.has_flag(MessageFlags::ENCRYPTED));
        
        msg.set_flag(MessageFlags::COMPRESSED);
        REQUIRE(msg.has_flag(MessageFlags::COMPRESSED));
        REQUIRE_FALSE(msg.has_flag(MessageFlags::ENCRYPTED));
        
        msg.set_flag(MessageFlags::ENCRYPTED);
        REQUIRE(msg.has_flag(MessageFlags::COMPRESSED));
        REQUIRE(msg.has_flag(MessageFlags::ENCRYPTED));
        
        msg.clear_flag(MessageFlags::COMPRESSED);
        REQUIRE_FALSE(msg.has_flag(MessageFlags::COMPRESSED));
        REQUIRE(msg.has_flag(MessageFlags::ENCRYPTED));
    }
    
    SECTION("Empty message handling") {
        BinaryMessage msg(MessageType::PING, 0);
        
        REQUIRE(msg.data_size() == 0);
        REQUIRE(msg.data_as_string().empty());
        REQUIRE(msg.is_valid());
        
        auto serialized = msg.serialize();
        REQUIRE(serialized.size() == HEADER_SIZE);
        
        BinaryMessage deserialized;
        REQUIRE(deserialized.deserialize(serialized));
        REQUIRE(deserialized.data_size() == 0);
    }
}

TEST_CASE("MessageBuilder functionality", "[binary_protocol][builder]") {
    SECTION("PUT request and response") {
        auto request = MessageBuilder::create_put_request(123, "user:alice", "Alice Smith");
        
        REQUIRE(request.type() == MessageType::PUT_REQUEST);
        REQUIRE(request.message_id() == 123);
        REQUIRE(request.has_flag(MessageFlags::EXPECTS_RESPONSE));
        
        auto put_data = MessageParser::parse_put_request(request);
        REQUIRE(put_data.has_value());
        REQUIRE(put_data->key == "user:alice");
        REQUIRE(put_data->value == "Alice Smith");
        
        auto response = MessageBuilder::create_put_response(123, StatusCode::SUCCESS);
        REQUIRE(response.type() == MessageType::PUT_RESPONSE);
        REQUIRE(response.message_id() == 123);
        REQUIRE(response.has_flag(MessageFlags::IS_RESPONSE));
    }
    
    SECTION("GET request and response") {
        auto request = MessageBuilder::create_get_request(456, "user:bob");
        
        REQUIRE(request.type() == MessageType::GET_REQUEST);
        REQUIRE(request.message_id() == 456);
        
        auto get_data = MessageParser::parse_get_request(request);
        REQUIRE(get_data.has_value());
        REQUIRE(get_data->key == "user:bob");
        
        auto response = MessageBuilder::create_get_response(456, StatusCode::SUCCESS, "Bob Jones");
        REQUIRE(response.type() == MessageType::GET_RESPONSE);
        
        auto response_data = MessageParser::parse_response(response);
        REQUIRE(response_data.status == StatusCode::SUCCESS);
        REQUIRE(response_data.data == "Bob Jones");
    }
    
    SECTION("DELETE request and response") {
        auto request = MessageBuilder::create_delete_request(789, "temp:key");
        
        REQUIRE(request.type() == MessageType::DELETE_REQUEST);
        REQUIRE(request.message_id() == 789);
        
        auto delete_data = MessageParser::parse_delete_request(request);
        REQUIRE(delete_data.has_value());
        REQUIRE(delete_data->key == "temp:key");
        
        auto response = MessageBuilder::create_delete_response(789, StatusCode::SUCCESS);
        REQUIRE(response.type() == MessageType::DELETE_RESPONSE);
        
        auto response_data = MessageParser::parse_response(response);
        REQUIRE(response_data.status == StatusCode::SUCCESS);
    }
    
    SECTION("QUERY request and response") {
        auto request = MessageBuilder::create_query_request(999, "RANGE key1 key3");
        
        REQUIRE(request.type() == MessageType::QUERY_REQUEST);
        REQUIRE(request.message_id() == 999);
        
        auto query_data = MessageParser::parse_query_request(request);
        REQUIRE(query_data.has_value());
        REQUIRE(query_data->query == "RANGE key1 key3");
        
        std::vector<std::pair<std::string, std::string>> results = {
            {"key1", "value1"},
            {"key2", "value2"},
            {"key3", "value3"}
        };
        
        auto response = MessageBuilder::create_query_response(999, StatusCode::SUCCESS, results);
        REQUIRE(response.type() == MessageType::QUERY_RESPONSE);
        
        auto response_data = MessageParser::parse_response(response);
        REQUIRE(response_data.status == StatusCode::SUCCESS);
        REQUIRE(response_data.results.size() == 3);
        REQUIRE(response_data.results[0].first == "key1");
        REQUIRE(response_data.results[0].second == "value1");
        REQUIRE(response_data.results[2].first == "key3");
        REQUIRE(response_data.results[2].second == "value3");
    }
    
    SECTION("Control messages") {
        auto ping = MessageBuilder::create_ping(100);
        REQUIRE(ping.type() == MessageType::PING);
        REQUIRE(ping.message_id() == 100);
        REQUIRE(ping.has_flag(MessageFlags::EXPECTS_RESPONSE));
        
        auto pong = MessageBuilder::create_pong(100);
        REQUIRE(pong.type() == MessageType::PONG);
        REQUIRE(pong.message_id() == 100);
        REQUIRE(pong.has_flag(MessageFlags::IS_RESPONSE));
        
        auto error = MessageBuilder::create_error(200, StatusCode::KEY_NOT_FOUND, "Key does not exist");
        REQUIRE(error.type() == MessageType::ERROR);
        REQUIRE(error.message_id() == 200);
        REQUIRE(error.has_flag(MessageFlags::IS_RESPONSE));
        
        auto error_data = MessageParser::parse_response(error);
        REQUIRE(error_data.status == StatusCode::KEY_NOT_FOUND);
    }
}

TEST_CASE("Batch operations", "[binary_protocol][batch]") {
    SECTION("Batch request creation and parsing") {
        std::vector<BinaryMessage> operations;
        operations.push_back(MessageBuilder::create_put_request(1, "key1", "value1"));
        operations.push_back(MessageBuilder::create_get_request(2, "key2"));
        operations.push_back(MessageBuilder::create_delete_request(3, "key3"));
        
        auto batch_request = MessageBuilder::create_batch_request(500, operations);
        REQUIRE(batch_request.type() == MessageType::BATCH_REQUEST);
        REQUIRE(batch_request.message_id() == 500);
        
        auto parsed_operations = MessageParser::parse_batch_request(batch_request);
        REQUIRE(parsed_operations.size() == 3);
        
        REQUIRE(parsed_operations[0].type() == MessageType::PUT_REQUEST);
        REQUIRE(parsed_operations[1].type() == MessageType::GET_REQUEST);
        REQUIRE(parsed_operations[2].type() == MessageType::DELETE_REQUEST);
        
        auto put_data = MessageParser::parse_put_request(parsed_operations[0]);
        REQUIRE(put_data.has_value());
        REQUIRE(put_data->key == "key1");
        REQUIRE(put_data->value == "value1");
    }
    
    SECTION("Batch response creation and parsing") {
        std::vector<StatusCode> results = {
            StatusCode::SUCCESS,
            StatusCode::KEY_NOT_FOUND,
            StatusCode::SUCCESS
        };
        
        auto batch_response = MessageBuilder::create_batch_response(500, StatusCode::SUCCESS, results);
        REQUIRE(batch_response.type() == MessageType::BATCH_RESPONSE);
        REQUIRE(batch_response.message_id() == 500);
        
        auto parsed_results = MessageParser::parse_batch_response(batch_response);
        REQUIRE(parsed_results.size() == 3);
        REQUIRE(parsed_results[0] == StatusCode::SUCCESS);
        REQUIRE(parsed_results[1] == StatusCode::KEY_NOT_FOUND);
        REQUIRE(parsed_results[2] == StatusCode::SUCCESS);
    }
}

TEST_CASE("Protocol validation", "[binary_protocol][validation]") {
    SECTION("Header validation") {
        BinaryMessage msg(MessageType::PUT_REQUEST, 1);
        msg.set_data("test_data");
        
        auto serialized = msg.serialize();
        
        // Corrupt magic number
        serialized[0] = 0xFF;
        
        BinaryMessage corrupted;
        REQUIRE_FALSE(corrupted.deserialize(serialized));
    }
    
    SECTION("Size limits") {
        BinaryMessage msg(MessageType::PUT_REQUEST, 1);
        
        // Test max message size enforcement
        std::string large_data(MAX_MESSAGE_SIZE + 1, 'x');
        msg.set_data(large_data);
        
        // The message should still be valid locally but fail protocol validation
        REQUIRE_FALSE(msg.is_valid());
    }
    
    SECTION("Incomplete message handling") {
        BinaryMessage original(MessageType::GET_REQUEST, 42);
        original.set_data("test_key");
        
        auto serialized = original.serialize();
        
        // Try to deserialize with incomplete data
        BinaryMessage incomplete;
        REQUIRE_FALSE(incomplete.deserialize(serialized.data(), HEADER_SIZE - 1)); // Incomplete header
        REQUIRE_FALSE(incomplete.deserialize(serialized.data(), HEADER_SIZE + 4)); // Incomplete data
    }
}

TEST_CASE("Round-trip compatibility", "[binary_protocol][roundtrip]") {
    SECTION("Complex message round-trip") {
        // Create a complex message with multiple flags and data
        BinaryMessage original(MessageType::QUERY_REQUEST, 987654321);
        original.set_data("PREFIX user: LIMIT 10 OFFSET 20");
        original.set_flag(MessageFlags::EXPECTS_RESPONSE);
        original.set_flag(MessageFlags::COMPRESSED);
        
        // Serialize and deserialize
        auto serialized = original.serialize();
        BinaryMessage copy;
        REQUIRE(copy.deserialize(serialized));
        
        // Verify complete fidelity
        REQUIRE(copy.type() == original.type());
        REQUIRE(copy.message_id() == original.message_id());
        REQUIRE(copy.data_as_string() == original.data_as_string());
        REQUIRE(copy.has_flag(MessageFlags::EXPECTS_RESPONSE));
        REQUIRE(copy.has_flag(MessageFlags::COMPRESSED));
        REQUIRE_FALSE(copy.has_flag(MessageFlags::ENCRYPTED));
        
        // Verify both messages produce identical serialization
        REQUIRE(copy.serialize() == serialized);
    }
}