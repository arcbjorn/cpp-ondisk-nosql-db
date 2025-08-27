#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>
#include "network/metrics.hpp"
#include <chrono>
#include <thread>

using namespace nosql_db::network;
using Catch::Matchers::WithinRel;

TEST_CASE("NetworkMetrics - Basic Functionality", "[network][metrics]") {
    auto metrics = std::make_shared<NetworkMetrics>();
    
    SECTION("Initial state") {
        REQUIRE(metrics->connection_metrics().total_connections.load() == 0);
        REQUIRE(metrics->request_metrics().total_requests.load() == 0);
        REQUIRE(metrics->bandwidth_metrics().bytes_sent.load() == 0);
        REQUIRE(metrics->error_metrics().protocol_errors.load() == 0);
        REQUIRE(metrics->session_metrics().active_sessions.load() == 0);
    }
    
    SECTION("Connection tracking") {
        metrics->record_connection_start();
        metrics->record_connection_start();
        
        REQUIRE(metrics->connection_metrics().total_connections.load() == 2);
        REQUIRE(metrics->connection_metrics().active_connections.load() == 2);
        
        auto duration = std::chrono::microseconds(5000); // 5ms
        metrics->record_connection_end(duration);
        
        REQUIRE(metrics->connection_metrics().active_connections.load() == 1);
        REQUIRE(metrics->connection_metrics().total_connection_time_us.load() == 5000);
        REQUIRE(metrics->connection_metrics().min_connection_time_us.load() == 5000);
        REQUIRE(metrics->connection_metrics().max_connection_time_us.load() == 5000);
    }
    
    SECTION("Request tracking") {
        metrics->record_request_start();
        metrics->record_request_by_type("PUT");
        
        auto response_time = std::chrono::microseconds(2000); // 2ms
        metrics->record_request_end(response_time, true);
        
        REQUIRE(metrics->request_metrics().total_requests.load() == 1);
        REQUIRE(metrics->request_metrics().successful_requests.load() == 1);
        REQUIRE(metrics->request_metrics().failed_requests.load() == 0);
        REQUIRE(metrics->request_metrics().put_requests.load() == 1);
        REQUIRE(metrics->request_metrics().total_response_time_us.load() == 2000);
        
        REQUIRE_THAT(metrics->get_average_response_time_ms(), WithinRel(2.0, 0.01));
        REQUIRE_THAT(metrics->get_error_rate(), WithinRel(0.0, 0.01));
    }
    
    SECTION("Request types tracking") {
        metrics->record_request_by_type("PUT");
        metrics->record_request_by_type("GET");
        metrics->record_request_by_type("DELETE");
        metrics->record_request_by_type("QUERY");
        metrics->record_request_by_type("BATCH");
        metrics->record_request_by_type("PING");
        
        REQUIRE(metrics->request_metrics().put_requests.load() == 1);
        REQUIRE(metrics->request_metrics().get_requests.load() == 1);
        REQUIRE(metrics->request_metrics().delete_requests.load() == 1);
        REQUIRE(metrics->request_metrics().query_requests.load() == 1);
        REQUIRE(metrics->request_metrics().batch_requests.load() == 1);
        REQUIRE(metrics->request_metrics().ping_requests.load() == 1);
    }
    
    SECTION("Bandwidth tracking") {
        metrics->record_bytes_sent(1024);
        metrics->record_bytes_received(512);
        metrics->record_message_sent();
        metrics->record_message_received();
        
        REQUIRE(metrics->bandwidth_metrics().bytes_sent.load() == 1024);
        REQUIRE(metrics->bandwidth_metrics().bytes_received.load() == 512);
        REQUIRE(metrics->bandwidth_metrics().messages_sent.load() == 1);
        REQUIRE(metrics->bandwidth_metrics().messages_received.load() == 1);
    }
    
    SECTION("Error tracking") {
        metrics->record_protocol_error();
        metrics->record_timeout_error();
        metrics->record_network_error();
        metrics->record_serialization_error();
        metrics->record_rate_limit_violation();
        
        REQUIRE(metrics->error_metrics().protocol_errors.load() == 1);
        REQUIRE(metrics->error_metrics().timeout_errors.load() == 1);
        REQUIRE(metrics->error_metrics().network_errors.load() == 1);
        REQUIRE(metrics->error_metrics().serialization_errors.load() == 1);
        REQUIRE(metrics->error_metrics().rate_limit_violations.load() == 1);
    }
    
    SECTION("Session tracking") {
        metrics->record_session_created();
        metrics->record_session_created();
        
        REQUIRE(metrics->session_metrics().active_sessions.load() == 2);
        
        auto session_duration = std::chrono::microseconds(60000000); // 60 seconds
        metrics->record_session_expired(session_duration);
        
        REQUIRE(metrics->session_metrics().active_sessions.load() == 1);
        REQUIRE(metrics->session_metrics().expired_sessions.load() == 1);
        REQUIRE(metrics->session_metrics().average_session_duration_us.load() == 60000000);
    }
    
    SECTION("Compression tracking") {
        metrics->record_compression(1000, 500); // 50% compression
        metrics->record_compression(2000, 800); // 40% compression
        
        REQUIRE(metrics->bandwidth_metrics().compressed_messages.load() == 2);
        REQUIRE_THAT(metrics->get_average_compression_ratio(), WithinRel(45.0, 0.1));
    }
}

TEST_CASE("LatencyHistogram", "[network][metrics]") {
    LatencyHistogram histogram;
    
    SECTION("Initial state") {
        auto buckets = histogram.get_buckets();
        REQUIRE(buckets.size() == LatencyHistogram::BUCKET_COUNT);
        for (auto bucket : buckets) {
            REQUIRE(bucket == 0);
        }
    }
    
    SECTION("Latency recording") {
        // Record various latencies
        histogram.record(std::chrono::microseconds(500));    // < 1ms bucket
        histogram.record(std::chrono::microseconds(3000));   // < 5ms bucket
        histogram.record(std::chrono::microseconds(8000));   // < 10ms bucket
        histogram.record(std::chrono::microseconds(25000));  // < 50ms bucket
        histogram.record(std::chrono::microseconds(75000));  // < 100ms bucket
        histogram.record(std::chrono::microseconds(250000)); // < 500ms bucket
        histogram.record(std::chrono::microseconds(750000)); // < 1s bucket
        histogram.record(std::chrono::microseconds(1500000));// >= 1s bucket
        
        auto buckets = histogram.get_buckets();
        REQUIRE(buckets[0] == 1); // < 1ms
        REQUIRE(buckets[1] == 1); // < 5ms
        REQUIRE(buckets[2] == 1); // < 10ms
        REQUIRE(buckets[3] == 1); // < 50ms
        REQUIRE(buckets[4] == 1); // < 100ms
        REQUIRE(buckets[5] == 1); // < 500ms
        REQUIRE(buckets[6] == 1); // < 1s
        REQUIRE(buckets[7] == 1); // >= 1s
    }
    
    SECTION("Reset functionality") {
        histogram.record(std::chrono::microseconds(1000));
        histogram.record(std::chrono::microseconds(5000));
        
        auto buckets_before = histogram.get_buckets();
        REQUIRE(buckets_before[0] + buckets_before[1] == 2);
        
        histogram.reset();
        
        auto buckets_after = histogram.get_buckets();
        for (auto bucket : buckets_after) {
            REQUIRE(bucket == 0);
        }
    }
}

TEST_CASE("NetworkMetrics - JSON Export", "[network][metrics]") {
    auto metrics = std::make_shared<NetworkMetrics>();
    
    // Add some test data
    metrics->record_connection_start();
    metrics->record_request_start();
    metrics->record_request_by_type("GET");
    metrics->record_request_end(std::chrono::microseconds(1500), true);
    metrics->record_bytes_sent(256);
    metrics->record_bytes_received(128);
    
    SECTION("JSON export format") {
        auto json_str = metrics->to_json();
        REQUIRE_FALSE(json_str.empty());
        REQUIRE(json_str.find("connections") != std::string::npos);
        REQUIRE(json_str.find("requests") != std::string::npos);
        REQUIRE(json_str.find("bandwidth") != std::string::npos);
        REQUIRE(json_str.find("errors") != std::string::npos);
        REQUIRE(json_str.find("sessions") != std::string::npos);
        REQUIRE(json_str.find("latency") != std::string::npos);
    }
    
    SECTION("Key-value map export") {
        auto kv_map = metrics->to_key_value_map();
        REQUIRE_FALSE(kv_map.empty());
        REQUIRE(kv_map.count("connections.total") == 1);
        REQUIRE(kv_map.count("requests.total") == 1);
        REQUIRE(kv_map.count("bandwidth.bytes_sent") == 1);
        REQUIRE(kv_map.count("requests.get") == 1);
        
        REQUIRE(kv_map["connections.total"] == 1);
        REQUIRE(kv_map["requests.total"] == 1);
        REQUIRE(kv_map["bandwidth.bytes_sent"] == 256);
        REQUIRE(kv_map["requests.get"] == 1);
    }
}

TEST_CASE("NetworkMetrics - Reset Functionality", "[network][metrics]") {
    auto metrics = std::make_shared<NetworkMetrics>();
    
    // Populate with test data
    metrics->record_connection_start();
    metrics->record_request_start();
    metrics->record_request_end(std::chrono::microseconds(1000), true);
    metrics->record_bytes_sent(512);
    metrics->record_protocol_error();
    metrics->record_session_created();
    
    // Verify data exists
    REQUIRE(metrics->connection_metrics().total_connections.load() > 0);
    REQUIRE(metrics->request_metrics().total_requests.load() > 0);
    REQUIRE(metrics->bandwidth_metrics().bytes_sent.load() > 0);
    REQUIRE(metrics->error_metrics().protocol_errors.load() > 0);
    REQUIRE(metrics->session_metrics().active_sessions.load() > 0);
    
    // Reset all metrics
    metrics->reset_metrics();
    
    // Verify everything is reset
    REQUIRE(metrics->connection_metrics().total_connections.load() == 0);
    REQUIRE(metrics->connection_metrics().active_connections.load() == 0);
    REQUIRE(metrics->request_metrics().total_requests.load() == 0);
    REQUIRE(metrics->bandwidth_metrics().bytes_sent.load() == 0);
    REQUIRE(metrics->error_metrics().protocol_errors.load() == 0);
    REQUIRE(metrics->session_metrics().active_sessions.load() == 0);
    
    // Verify calculated values are also reset
    REQUIRE_THAT(metrics->get_average_response_time_ms(), WithinRel(0.0, 0.01));
    REQUIRE_THAT(metrics->get_error_rate(), WithinRel(0.0, 0.01));
}

TEST_CASE("MetricsMonitor - Basic Functionality", "[network][metrics]") {
    auto metrics = std::make_shared<NetworkMetrics>();
    MetricsMonitor::MonitorConfig config;
    config.report_interval = std::chrono::seconds(1); // Fast for testing
    config.enable_console_output = false; // Don't spam console during tests
    config.enable_file_output = false;    // Don't create files during tests
    
    MetricsMonitor monitor(metrics, config);
    
    SECTION("Start and stop") {
        REQUIRE_FALSE(monitor.is_running());
        
        monitor.start();
        REQUIRE(monitor.is_running());
        
        // Let it run briefly
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        monitor.stop();
        REQUIRE_FALSE(monitor.is_running());
    }
    
    SECTION("Configuration") {
        const auto& retrieved_config = monitor.config();
        REQUIRE(retrieved_config.report_interval == std::chrono::seconds(1));
        REQUIRE_FALSE(retrieved_config.enable_console_output);
        REQUIRE_FALSE(retrieved_config.enable_file_output);
    }
}

TEST_CASE("NetworkMetrics - Error Rate Calculation", "[network][metrics]") {
    auto metrics = std::make_shared<NetworkMetrics>();
    
    SECTION("Zero requests - no error rate") {
        REQUIRE_THAT(metrics->get_error_rate(), WithinRel(0.0, 0.01));
    }
    
    SECTION("Mixed success and failure") {
        // Record 10 successful requests
        for (int i = 0; i < 10; ++i) {
            metrics->record_request_start();
            metrics->record_request_end(std::chrono::microseconds(1000), true);
        }
        
        // Record 2 failed requests  
        for (int i = 0; i < 2; ++i) {
            metrics->record_request_start();
            metrics->record_request_end(std::chrono::microseconds(1000), false);
        }
        
        // Error rate should be 2/12 = 16.67%
        REQUIRE_THAT(metrics->get_error_rate(), WithinRel(16.67, 0.1));
    }
    
    SECTION("All failures") {
        for (int i = 0; i < 5; ++i) {
            metrics->record_request_start();
            metrics->record_request_end(std::chrono::microseconds(1000), false);
        }
        
        REQUIRE_THAT(metrics->get_error_rate(), WithinRel(100.0, 0.01));
    }
}

TEST_CASE("NetworkMetrics - Min/Max Tracking", "[network][metrics]") {
    auto metrics = std::make_shared<NetworkMetrics>();
    
    SECTION("Connection duration min/max") {
        metrics->record_connection_start();
        metrics->record_connection_end(std::chrono::microseconds(1000));
        
        metrics->record_connection_start();
        metrics->record_connection_end(std::chrono::microseconds(5000));
        
        metrics->record_connection_start();
        metrics->record_connection_end(std::chrono::microseconds(3000));
        
        REQUIRE(metrics->connection_metrics().min_connection_time_us.load() == 1000);
        REQUIRE(metrics->connection_metrics().max_connection_time_us.load() == 5000);
    }
    
    SECTION("Response time min/max") {
        metrics->record_request_start();
        metrics->record_request_end(std::chrono::microseconds(500), true);
        
        metrics->record_request_start();
        metrics->record_request_end(std::chrono::microseconds(2000), true);
        
        metrics->record_request_start();
        metrics->record_request_end(std::chrono::microseconds(1200), true);
        
        REQUIRE(metrics->request_metrics().min_response_time_us.load() == 500);
        REQUIRE(metrics->request_metrics().max_response_time_us.load() == 2000);
        
        // Average should be (500 + 2000 + 1200) / 3 = 1233.33 microseconds = 1.23 ms
        REQUIRE_THAT(metrics->get_average_response_time_ms(), WithinRel(1.23, 0.1));
    }
}