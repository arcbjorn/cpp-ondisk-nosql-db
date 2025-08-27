#pragma once

#include <atomic>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <string>
#include <memory>
#include <thread>

namespace ishikura::network {

/**
 * Network metrics collection and monitoring
 */

// High-resolution timestamp for metrics
using timestamp_t = std::chrono::steady_clock::time_point;
using duration_us_t = std::chrono::microseconds;

struct ConnectionMetrics {
    std::atomic<uint64_t> total_connections{0};
    std::atomic<uint64_t> active_connections{0};
    std::atomic<uint64_t> rejected_connections{0};
    std::atomic<uint64_t> failed_connections{0};
    std::atomic<uint64_t> connections_per_second{0};
    
    // Connection duration tracking
    std::atomic<uint64_t> total_connection_time_us{0};
    std::atomic<uint64_t> min_connection_time_us{UINT64_MAX};
    std::atomic<uint64_t> max_connection_time_us{0};
};

struct RequestMetrics {
    std::atomic<uint64_t> total_requests{0};
    std::atomic<uint64_t> requests_per_second{0};
    std::atomic<uint64_t> successful_requests{0};
    std::atomic<uint64_t> failed_requests{0};
    
    // Request type breakdown
    std::atomic<uint64_t> put_requests{0};
    std::atomic<uint64_t> get_requests{0};
    std::atomic<uint64_t> delete_requests{0};
    std::atomic<uint64_t> query_requests{0};
    std::atomic<uint64_t> batch_requests{0};
    std::atomic<uint64_t> ping_requests{0};
    
    // Response time tracking (in microseconds)
    std::atomic<uint64_t> total_response_time_us{0};
    std::atomic<uint64_t> min_response_time_us{UINT64_MAX};
    std::atomic<uint64_t> max_response_time_us{0};
};

struct BandwidthMetrics {
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> bytes_per_second_sent{0};
    std::atomic<uint64_t> bytes_per_second_received{0};
    
    // Message count
    std::atomic<uint64_t> messages_sent{0};
    std::atomic<uint64_t> messages_received{0};
    
    // Compression stats
    std::atomic<uint64_t> compressed_messages{0};
    std::atomic<uint64_t> compression_ratio_total{0}; // Sum of ratios for averaging
};

struct ErrorMetrics {
    std::atomic<uint64_t> protocol_errors{0};
    std::atomic<uint64_t> timeout_errors{0};
    std::atomic<uint64_t> network_errors{0};
    std::atomic<uint64_t> serialization_errors{0};
    std::atomic<uint64_t> rate_limit_violations{0};
    
    // Error rate per second
    std::atomic<uint64_t> errors_per_second{0};
};

struct SessionMetrics {
    std::atomic<uint64_t> active_sessions{0};
    std::atomic<uint64_t> expired_sessions{0};
    std::atomic<uint64_t> cleaned_sessions{0};
    std::atomic<uint64_t> session_renewals{0};
    
    // Session duration tracking
    std::atomic<uint64_t> total_session_duration_us{0};
    std::atomic<uint64_t> average_session_duration_us{0};
};

/**
 * Histogram for latency distribution tracking
 */
class LatencyHistogram {
public:
    // Latency buckets in microseconds: <1ms, <5ms, <10ms, <50ms, <100ms, <500ms, <1s, >=1s
    static constexpr size_t BUCKET_COUNT = 8;
    static constexpr uint64_t BUCKETS[BUCKET_COUNT] = {1000, 5000, 10000, 50000, 100000, 500000, 1000000, UINT64_MAX};
    
    LatencyHistogram();
    void record(duration_us_t latency);
    std::vector<uint64_t> get_buckets() const;
    void reset();

private:
    std::array<std::atomic<uint64_t>, BUCKET_COUNT> buckets_;
};

/**
 * Comprehensive network metrics manager
 */
class NetworkMetrics {
public:
    NetworkMetrics();
    ~NetworkMetrics();
    
    // Connection tracking
    void record_connection_start();
    void record_connection_end(duration_us_t connection_duration);
    void record_connection_rejected();
    void record_connection_failed();
    
    // Request tracking
    void record_request_start();
    void record_request_end(duration_us_t response_time, bool success = true);
    void record_request_by_type(const std::string& type);
    
    // Bandwidth tracking
    void record_bytes_sent(uint64_t bytes);
    void record_bytes_received(uint64_t bytes);
    void record_message_sent();
    void record_message_received();
    void record_compression(uint64_t original_size, uint64_t compressed_size);
    
    // Error tracking
    void record_protocol_error();
    void record_timeout_error();
    void record_network_error();
    void record_serialization_error();
    void record_rate_limit_violation();
    
    // Session tracking
    void record_session_created();
    void record_session_expired(duration_us_t session_duration);
    void record_session_renewed();
    
    // Getters for metrics
    const ConnectionMetrics& connection_metrics() const { return connection_metrics_; }
    const RequestMetrics& request_metrics() const { return request_metrics_; }
    const BandwidthMetrics& bandwidth_metrics() const { return bandwidth_metrics_; }
    const ErrorMetrics& error_metrics() const { return error_metrics_; }
    const SessionMetrics& session_metrics() const { return session_metrics_; }
    const LatencyHistogram& latency_histogram() const { return latency_histogram_; }
    
    // Metrics calculation
    double get_average_response_time_ms() const;
    double get_error_rate() const;
    double get_requests_per_second() const;
    double get_average_compression_ratio() const;
    
    // Reset all metrics
    void reset_metrics();
    
    // Export metrics in different formats
    std::string to_json() const;
    std::unordered_map<std::string, uint64_t> to_key_value_map() const;

private:
    ConnectionMetrics connection_metrics_;
    RequestMetrics request_metrics_;
    BandwidthMetrics bandwidth_metrics_;
    ErrorMetrics error_metrics_;
    SessionMetrics session_metrics_;
    LatencyHistogram latency_histogram_;
    
    // For rate calculation
    timestamp_t last_rate_calculation_;
    mutable std::mutex rate_mutex_;
    
    void update_rates();
    timestamp_t now() const { return std::chrono::steady_clock::now(); }
};

/**
 * Real-time metrics monitor with periodic reporting
 */
class MetricsMonitor {
public:
    struct MonitorConfig {
        std::chrono::seconds report_interval{30};
        bool enable_console_output = true;
        bool enable_file_output = false;
        std::string log_file_path = "metrics.log";
        bool enable_rate_calculation = true;
    };
    
    MetricsMonitor(std::shared_ptr<NetworkMetrics> metrics);
    MetricsMonitor(std::shared_ptr<NetworkMetrics> metrics, const MonitorConfig& config);
    ~MetricsMonitor();
    
    void start();
    void stop();
    bool is_running() const { return running_.load(); }
    
    // Manual trigger for metrics reporting
    void report_now();
    
    // Configuration
    const MonitorConfig& config() const { return config_; }
    void update_config(const MonitorConfig& config);

private:
    std::shared_ptr<NetworkMetrics> metrics_;
    MonitorConfig config_;
    
    std::atomic<bool> running_{false};
    std::atomic<bool> should_stop_{false};
    std::thread monitor_thread_;
    
    void monitor_loop();
    void write_metrics_report();
    void write_to_console(const std::string& report);
    void write_to_file(const std::string& report);
    std::string generate_report();
};

} // namespace ishikura::network