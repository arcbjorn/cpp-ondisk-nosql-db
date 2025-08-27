#include "network/metrics.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <nlohmann/json.hpp>

namespace ishikura::network {

// LatencyHistogram implementation
constexpr uint64_t LatencyHistogram::BUCKETS[BUCKET_COUNT];

LatencyHistogram::LatencyHistogram() {
    reset();
}

void LatencyHistogram::record(duration_us_t latency) {
    uint64_t latency_us = latency.count();
    
    for (size_t i = 0; i < BUCKET_COUNT; ++i) {
        if (latency_us < BUCKETS[i]) {
            buckets_[i].fetch_add(1);
            break;
        }
    }
}

std::vector<uint64_t> LatencyHistogram::get_buckets() const {
    std::vector<uint64_t> result;
    result.reserve(BUCKET_COUNT);
    
    for (const auto& bucket : buckets_) {
        result.push_back(bucket.load());
    }
    
    return result;
}

void LatencyHistogram::reset() {
    for (auto& bucket : buckets_) {
        bucket.store(0);
    }
}

// NetworkMetrics implementation
NetworkMetrics::NetworkMetrics() : last_rate_calculation_(now()) {
    spdlog::debug("NetworkMetrics initialized");
}

NetworkMetrics::~NetworkMetrics() = default;

void NetworkMetrics::record_connection_start() {
    connection_metrics_.total_connections.fetch_add(1);
    connection_metrics_.active_connections.fetch_add(1);
    update_rates();
}

void NetworkMetrics::record_connection_end(duration_us_t connection_duration) {
    connection_metrics_.active_connections.fetch_sub(1);
    
    uint64_t duration_us = connection_duration.count();
    connection_metrics_.total_connection_time_us.fetch_add(duration_us);
    
    // Update min/max connection times
    uint64_t current_min = connection_metrics_.min_connection_time_us.load();
    while (duration_us < current_min && 
           !connection_metrics_.min_connection_time_us.compare_exchange_weak(current_min, duration_us)) {
        // Retry if another thread updated it
    }
    
    uint64_t current_max = connection_metrics_.max_connection_time_us.load();
    while (duration_us > current_max && 
           !connection_metrics_.max_connection_time_us.compare_exchange_weak(current_max, duration_us)) {
        // Retry if another thread updated it
    }
}

void NetworkMetrics::record_connection_rejected() {
    connection_metrics_.rejected_connections.fetch_add(1);
}

void NetworkMetrics::record_connection_failed() {
    connection_metrics_.failed_connections.fetch_add(1);
}

void NetworkMetrics::record_request_start() {
    request_metrics_.total_requests.fetch_add(1);
    update_rates();
}

void NetworkMetrics::record_request_end(duration_us_t response_time, bool success) {
    if (success) {
        request_metrics_.successful_requests.fetch_add(1);
    } else {
        request_metrics_.failed_requests.fetch_add(1);
    }
    
    uint64_t response_us = response_time.count();
    request_metrics_.total_response_time_us.fetch_add(response_us);
    latency_histogram_.record(response_time);
    
    // Update min/max response times
    uint64_t current_min = request_metrics_.min_response_time_us.load();
    while (response_us < current_min && 
           !request_metrics_.min_response_time_us.compare_exchange_weak(current_min, response_us)) {
        // Retry if another thread updated it
    }
    
    uint64_t current_max = request_metrics_.max_response_time_us.load();
    while (response_us > current_max && 
           !request_metrics_.max_response_time_us.compare_exchange_weak(current_max, response_us)) {
        // Retry if another thread updated it
    }
}

void NetworkMetrics::record_request_by_type(const std::string& type) {
    if (type == "PUT") {
        request_metrics_.put_requests.fetch_add(1);
    } else if (type == "GET") {
        request_metrics_.get_requests.fetch_add(1);
    } else if (type == "DELETE") {
        request_metrics_.delete_requests.fetch_add(1);
    } else if (type == "QUERY") {
        request_metrics_.query_requests.fetch_add(1);
    } else if (type == "BATCH") {
        request_metrics_.batch_requests.fetch_add(1);
    } else if (type == "PING") {
        request_metrics_.ping_requests.fetch_add(1);
    }
}

void NetworkMetrics::record_bytes_sent(uint64_t bytes) {
    bandwidth_metrics_.bytes_sent.fetch_add(bytes);
}

void NetworkMetrics::record_bytes_received(uint64_t bytes) {
    bandwidth_metrics_.bytes_received.fetch_add(bytes);
}

void NetworkMetrics::record_message_sent() {
    bandwidth_metrics_.messages_sent.fetch_add(1);
}

void NetworkMetrics::record_message_received() {
    bandwidth_metrics_.messages_received.fetch_add(1);
}

void NetworkMetrics::record_compression(uint64_t original_size, uint64_t compressed_size) {
    bandwidth_metrics_.compressed_messages.fetch_add(1);
    if (original_size > 0) {
        uint64_t ratio = (compressed_size * 100) / original_size;
        bandwidth_metrics_.compression_ratio_total.fetch_add(ratio);
    }
}

void NetworkMetrics::record_protocol_error() {
    error_metrics_.protocol_errors.fetch_add(1);
}

void NetworkMetrics::record_timeout_error() {
    error_metrics_.timeout_errors.fetch_add(1);
}

void NetworkMetrics::record_network_error() {
    error_metrics_.network_errors.fetch_add(1);
}

void NetworkMetrics::record_serialization_error() {
    error_metrics_.serialization_errors.fetch_add(1);
}

void NetworkMetrics::record_rate_limit_violation() {
    error_metrics_.rate_limit_violations.fetch_add(1);
}

void NetworkMetrics::record_session_created() {
    session_metrics_.active_sessions.fetch_add(1);
}

void NetworkMetrics::record_session_expired(duration_us_t session_duration) {
    session_metrics_.active_sessions.fetch_sub(1);
    session_metrics_.expired_sessions.fetch_add(1);
    
    uint64_t duration_us = session_duration.count();
    session_metrics_.total_session_duration_us.fetch_add(duration_us);
    
    uint64_t expired_count = session_metrics_.expired_sessions.load();
    if (expired_count > 0) {
        session_metrics_.average_session_duration_us.store(
            session_metrics_.total_session_duration_us.load() / expired_count
        );
    }
}

void NetworkMetrics::record_session_renewed() {
    session_metrics_.session_renewals.fetch_add(1);
}

double NetworkMetrics::get_average_response_time_ms() const {
    uint64_t total_requests = request_metrics_.total_requests.load();
    if (total_requests == 0) return 0.0;
    
    uint64_t total_time_us = request_metrics_.total_response_time_us.load();
    return static_cast<double>(total_time_us) / total_requests / 1000.0; // Convert to milliseconds
}

double NetworkMetrics::get_error_rate() const {
    uint64_t total_requests = request_metrics_.total_requests.load();
    if (total_requests == 0) return 0.0;
    
    uint64_t failed_requests = request_metrics_.failed_requests.load();
    return static_cast<double>(failed_requests) / total_requests * 100.0; // Percentage
}

double NetworkMetrics::get_requests_per_second() const {
    return static_cast<double>(request_metrics_.requests_per_second.load());
}

double NetworkMetrics::get_average_compression_ratio() const {
    uint64_t compressed_count = bandwidth_metrics_.compressed_messages.load();
    if (compressed_count == 0) return 0.0;
    
    uint64_t total_ratio = bandwidth_metrics_.compression_ratio_total.load();
    return static_cast<double>(total_ratio) / compressed_count;
}

void NetworkMetrics::reset_metrics() {
    // Reset connection metrics
    connection_metrics_.total_connections.store(0);
    connection_metrics_.active_connections.store(0);
    connection_metrics_.rejected_connections.store(0);
    connection_metrics_.failed_connections.store(0);
    connection_metrics_.connections_per_second.store(0);
    connection_metrics_.total_connection_time_us.store(0);
    connection_metrics_.min_connection_time_us.store(UINT64_MAX);
    connection_metrics_.max_connection_time_us.store(0);
    
    // Reset request metrics
    request_metrics_.total_requests.store(0);
    request_metrics_.requests_per_second.store(0);
    request_metrics_.successful_requests.store(0);
    request_metrics_.failed_requests.store(0);
    request_metrics_.put_requests.store(0);
    request_metrics_.get_requests.store(0);
    request_metrics_.delete_requests.store(0);
    request_metrics_.query_requests.store(0);
    request_metrics_.batch_requests.store(0);
    request_metrics_.ping_requests.store(0);
    request_metrics_.total_response_time_us.store(0);
    request_metrics_.min_response_time_us.store(UINT64_MAX);
    request_metrics_.max_response_time_us.store(0);
    
    // Reset bandwidth metrics
    bandwidth_metrics_.bytes_sent.store(0);
    bandwidth_metrics_.bytes_received.store(0);
    bandwidth_metrics_.bytes_per_second_sent.store(0);
    bandwidth_metrics_.bytes_per_second_received.store(0);
    bandwidth_metrics_.messages_sent.store(0);
    bandwidth_metrics_.messages_received.store(0);
    bandwidth_metrics_.compressed_messages.store(0);
    bandwidth_metrics_.compression_ratio_total.store(0);
    
    // Reset error metrics
    error_metrics_.protocol_errors.store(0);
    error_metrics_.timeout_errors.store(0);
    error_metrics_.network_errors.store(0);
    error_metrics_.serialization_errors.store(0);
    error_metrics_.rate_limit_violations.store(0);
    error_metrics_.errors_per_second.store(0);
    
    // Reset session metrics
    session_metrics_.active_sessions.store(0);
    session_metrics_.expired_sessions.store(0);
    session_metrics_.cleaned_sessions.store(0);
    session_metrics_.session_renewals.store(0);
    session_metrics_.total_session_duration_us.store(0);
    session_metrics_.average_session_duration_us.store(0);
    
    // Reset histogram
    latency_histogram_.reset();
    
    last_rate_calculation_ = now();
    spdlog::debug("NetworkMetrics reset");
}

std::string NetworkMetrics::to_json() const {
    nlohmann::json j;
    
    // Connection metrics
    j["connections"]["total"] = connection_metrics_.total_connections.load();
    j["connections"]["active"] = connection_metrics_.active_connections.load();
    j["connections"]["rejected"] = connection_metrics_.rejected_connections.load();
    j["connections"]["failed"] = connection_metrics_.failed_connections.load();
    j["connections"]["per_second"] = connection_metrics_.connections_per_second.load();
    
    // Request metrics
    j["requests"]["total"] = request_metrics_.total_requests.load();
    j["requests"]["per_second"] = request_metrics_.requests_per_second.load();
    j["requests"]["successful"] = request_metrics_.successful_requests.load();
    j["requests"]["failed"] = request_metrics_.failed_requests.load();
    j["requests"]["average_response_time_ms"] = get_average_response_time_ms();
    j["requests"]["error_rate_percent"] = get_error_rate();
    
    // Request types
    j["requests"]["by_type"]["put"] = request_metrics_.put_requests.load();
    j["requests"]["by_type"]["get"] = request_metrics_.get_requests.load();
    j["requests"]["by_type"]["delete"] = request_metrics_.delete_requests.load();
    j["requests"]["by_type"]["query"] = request_metrics_.query_requests.load();
    j["requests"]["by_type"]["batch"] = request_metrics_.batch_requests.load();
    j["requests"]["by_type"]["ping"] = request_metrics_.ping_requests.load();
    
    // Bandwidth metrics
    j["bandwidth"]["bytes_sent"] = bandwidth_metrics_.bytes_sent.load();
    j["bandwidth"]["bytes_received"] = bandwidth_metrics_.bytes_received.load();
    j["bandwidth"]["messages_sent"] = bandwidth_metrics_.messages_sent.load();
    j["bandwidth"]["messages_received"] = bandwidth_metrics_.messages_received.load();
    j["bandwidth"]["compression_ratio"] = get_average_compression_ratio();
    
    // Error metrics
    j["errors"]["protocol"] = error_metrics_.protocol_errors.load();
    j["errors"]["timeout"] = error_metrics_.timeout_errors.load();
    j["errors"]["network"] = error_metrics_.network_errors.load();
    j["errors"]["serialization"] = error_metrics_.serialization_errors.load();
    j["errors"]["rate_limit"] = error_metrics_.rate_limit_violations.load();
    
    // Session metrics
    j["sessions"]["active"] = session_metrics_.active_sessions.load();
    j["sessions"]["expired"] = session_metrics_.expired_sessions.load();
    j["sessions"]["renewals"] = session_metrics_.session_renewals.load();
    j["sessions"]["average_duration_ms"] = session_metrics_.average_session_duration_us.load() / 1000.0;
    
    // Latency histogram
    auto buckets = latency_histogram_.get_buckets();
    j["latency"]["histogram"] = buckets;
    
    return j.dump(2);
}

std::unordered_map<std::string, uint64_t> NetworkMetrics::to_key_value_map() const {
    std::unordered_map<std::string, uint64_t> metrics;
    
    metrics["connections.total"] = connection_metrics_.total_connections.load();
    metrics["connections.active"] = connection_metrics_.active_connections.load();
    metrics["connections.rejected"] = connection_metrics_.rejected_connections.load();
    metrics["connections.failed"] = connection_metrics_.failed_connections.load();
    metrics["connections.per_second"] = connection_metrics_.connections_per_second.load();
    
    metrics["requests.total"] = request_metrics_.total_requests.load();
    metrics["requests.per_second"] = request_metrics_.requests_per_second.load();
    metrics["requests.successful"] = request_metrics_.successful_requests.load();
    metrics["requests.failed"] = request_metrics_.failed_requests.load();
    
    metrics["requests.put"] = request_metrics_.put_requests.load();
    metrics["requests.get"] = request_metrics_.get_requests.load();
    metrics["requests.delete"] = request_metrics_.delete_requests.load();
    metrics["requests.query"] = request_metrics_.query_requests.load();
    metrics["requests.batch"] = request_metrics_.batch_requests.load();
    metrics["requests.ping"] = request_metrics_.ping_requests.load();
    
    metrics["bandwidth.bytes_sent"] = bandwidth_metrics_.bytes_sent.load();
    metrics["bandwidth.bytes_received"] = bandwidth_metrics_.bytes_received.load();
    metrics["bandwidth.messages_sent"] = bandwidth_metrics_.messages_sent.load();
    metrics["bandwidth.messages_received"] = bandwidth_metrics_.messages_received.load();
    
    metrics["errors.protocol"] = error_metrics_.protocol_errors.load();
    metrics["errors.timeout"] = error_metrics_.timeout_errors.load();
    metrics["errors.network"] = error_metrics_.network_errors.load();
    metrics["errors.serialization"] = error_metrics_.serialization_errors.load();
    metrics["errors.rate_limit"] = error_metrics_.rate_limit_violations.load();
    
    metrics["sessions.active"] = session_metrics_.active_sessions.load();
    metrics["sessions.expired"] = session_metrics_.expired_sessions.load();
    metrics["sessions.renewals"] = session_metrics_.session_renewals.load();
    
    return metrics;
}

void NetworkMetrics::update_rates() {
    std::lock_guard<std::mutex> lock(rate_mutex_);
    
    auto current_time = now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(current_time - last_rate_calculation_);
    
    if (duration.count() >= 1) { // Update rates every second
        // Connection rate
        uint64_t current_connections = connection_metrics_.total_connections.load();
        static uint64_t last_connections = 0;
        uint64_t conn_delta = current_connections - last_connections;
        connection_metrics_.connections_per_second.store(conn_delta / duration.count());
        last_connections = current_connections;
        
        // Request rate
        uint64_t current_requests = request_metrics_.total_requests.load();
        static uint64_t last_requests = 0;
        uint64_t req_delta = current_requests - last_requests;
        request_metrics_.requests_per_second.store(req_delta / duration.count());
        last_requests = current_requests;
        
        // Error rate
        uint64_t current_errors = error_metrics_.protocol_errors.load() + 
                                error_metrics_.timeout_errors.load() +
                                error_metrics_.network_errors.load() +
                                error_metrics_.serialization_errors.load();
        static uint64_t last_errors = 0;
        uint64_t error_delta = current_errors - last_errors;
        error_metrics_.errors_per_second.store(error_delta / duration.count());
        last_errors = current_errors;
        
        // Bandwidth rate
        uint64_t current_sent = bandwidth_metrics_.bytes_sent.load();
        uint64_t current_received = bandwidth_metrics_.bytes_received.load();
        static uint64_t last_sent = 0;
        static uint64_t last_received = 0;
        
        bandwidth_metrics_.bytes_per_second_sent.store((current_sent - last_sent) / duration.count());
        bandwidth_metrics_.bytes_per_second_received.store((current_received - last_received) / duration.count());
        last_sent = current_sent;
        last_received = current_received;
        
        last_rate_calculation_ = current_time;
    }
}

// MetricsMonitor implementation
MetricsMonitor::MetricsMonitor(std::shared_ptr<NetworkMetrics> metrics)
    : MetricsMonitor(std::move(metrics), MonitorConfig{}) {
}

MetricsMonitor::MetricsMonitor(std::shared_ptr<NetworkMetrics> metrics, const MonitorConfig& config)
    : metrics_(std::move(metrics)), config_(config) {
    if (!metrics_) {
        throw std::invalid_argument("NetworkMetrics cannot be null");
    }
    spdlog::debug("MetricsMonitor initialized with {} second intervals", config_.report_interval.count());
}

MetricsMonitor::~MetricsMonitor() {
    stop();
}

void MetricsMonitor::start() {
    if (running_.load()) {
        spdlog::warn("MetricsMonitor already running");
        return;
    }
    
    running_.store(true);
    should_stop_.store(false);
    
    monitor_thread_ = std::thread(&MetricsMonitor::monitor_loop, this);
    spdlog::info("MetricsMonitor started");
}

void MetricsMonitor::stop() {
    if (!running_.load()) {
        return;
    }
    
    should_stop_.store(true);
    running_.store(false);
    
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    
    spdlog::info("MetricsMonitor stopped");
}

void MetricsMonitor::report_now() {
    write_metrics_report();
}

void MetricsMonitor::update_config(const MonitorConfig& config) {
    config_ = config;
    spdlog::debug("MetricsMonitor config updated");
}

void MetricsMonitor::monitor_loop() {
    while (!should_stop_.load()) {
        write_metrics_report();
        
        // Sleep for report interval
        auto sleep_duration = config_.report_interval;
        auto start_sleep = std::chrono::steady_clock::now();
        
        while (!should_stop_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            auto elapsed = std::chrono::steady_clock::now() - start_sleep;
            if (elapsed >= sleep_duration) {
                break;
            }
        }
    }
}

void MetricsMonitor::write_metrics_report() {
    auto report = generate_report();
    
    if (config_.enable_console_output) {
        write_to_console(report);
    }
    
    if (config_.enable_file_output) {
        write_to_file(report);
    }
}

void MetricsMonitor::write_to_console(const std::string& report) {
    spdlog::info("Network Metrics Report:\n{}", report);
}

void MetricsMonitor::write_to_file(const std::string& report) {
    try {
        std::ofstream file(config_.log_file_path, std::ios::app);
        if (file.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            
            file << "=== " << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << " ===\n";
            file << report << "\n\n";
            file.close();
        } else {
            spdlog::error("Failed to write metrics to file: {}", config_.log_file_path);
        }
    } catch (const std::exception& e) {
        spdlog::error("Error writing metrics to file: {}", e.what());
    }
}

std::string MetricsMonitor::generate_report() {
    std::ostringstream report;
    
    const auto& conn = metrics_->connection_metrics();
    const auto& req = metrics_->request_metrics();
    const auto& bw = metrics_->bandwidth_metrics();
    const auto& err = metrics_->error_metrics();
    const auto& sess = metrics_->session_metrics();
    
    report << "┌─────────────────────────────────────────┐\n";
    report << "│           Network Metrics               │\n";
    report << "├─────────────────────────────────────────┤\n";
    
    // Connection metrics
    report << std::setfill(' ');
    report << "│ Connections                             │\n";
    report << "│  Total: " << std::setw(10) << conn.total_connections.load() 
           << " Active: " << std::setw(8) << conn.active_connections.load() << " │\n";
    report << "│  Failed: " << std::setw(9) << conn.failed_connections.load() 
           << " Rejected: " << std::setw(6) << conn.rejected_connections.load() << " │\n";
    report << "│  Rate: " << std::setw(10) << conn.connections_per_second.load() << " conn/s           │\n";
    
    // Request metrics
    report << "├─────────────────────────────────────────┤\n";
    report << "│ Requests                                │\n";
    report << "│  Total: " << std::setw(10) << req.total_requests.load() 
           << " Success: " << std::setw(8) << req.successful_requests.load() << " │\n";
    report << "│  Failed: " << std::setw(9) << req.failed_requests.load() 
           << " Rate: " << std::setw(9) << req.requests_per_second.load() << " req/s │\n";
    report << "│  Avg Response: " << std::setw(6) << std::fixed << std::setprecision(2) 
           << metrics_->get_average_response_time_ms() << " ms          │\n";
    report << "│  Error Rate: " << std::setw(8) << std::fixed << std::setprecision(2) 
           << metrics_->get_error_rate() << " %             │\n";
    
    // Request types
    report << "│  PUT: " << std::setw(8) << req.put_requests.load() 
           << " GET: " << std::setw(8) << req.get_requests.load() 
           << " DEL: " << std::setw(5) << req.delete_requests.load() << " │\n";
    report << "│  QUERY: " << std::setw(6) << req.query_requests.load() 
           << " BATCH: " << std::setw(6) << req.batch_requests.load() 
           << " PING: " << std::setw(5) << req.ping_requests.load() << " │\n";
    
    // Bandwidth metrics
    report << "├─────────────────────────────────────────┤\n";
    report << "│ Bandwidth                               │\n";
    report << "│  Sent: " << std::setw(10) << bw.bytes_sent.load() 
           << " B  Rate: " << std::setw(6) << bw.bytes_per_second_sent.load() << " B/s │\n";
    report << "│  Recv: " << std::setw(10) << bw.bytes_received.load() 
           << " B  Rate: " << std::setw(6) << bw.bytes_per_second_received.load() << " B/s │\n";
    report << "│  Msgs Sent: " << std::setw(7) << bw.messages_sent.load() 
           << " Recv: " << std::setw(7) << bw.messages_received.load() << " │\n";
    
    if (bw.compressed_messages.load() > 0) {
        report << "│  Compression: " << std::setw(5) << std::fixed << std::setprecision(1)
               << metrics_->get_average_compression_ratio() << "%              │\n";
    }
    
    // Error summary
    uint64_t total_errors = err.protocol_errors.load() + err.timeout_errors.load() + 
                           err.network_errors.load() + err.serialization_errors.load() +
                           err.rate_limit_violations.load();
    
    if (total_errors > 0) {
        report << "├─────────────────────────────────────────┤\n";
        report << "│ Errors (Total: " << std::setw(8) << total_errors << ")           │\n";
        report << "│  Protocol: " << std::setw(6) << err.protocol_errors.load() 
               << " Timeout: " << std::setw(8) << err.timeout_errors.load() << " │\n";
        report << "│  Network: " << std::setw(7) << err.network_errors.load() 
               << " Serial: " << std::setw(9) << err.serialization_errors.load() << " │\n";
        report << "│  Rate Limit: " << std::setw(6) << err.rate_limit_violations.load() << "                  │\n";
    }
    
    // Session metrics
    if (sess.active_sessions.load() > 0 || sess.expired_sessions.load() > 0) {
        report << "├─────────────────────────────────────────┤\n";
        report << "│ Sessions                                │\n";
        report << "│  Active: " << std::setw(8) << sess.active_sessions.load() 
               << " Expired: " << std::setw(8) << sess.expired_sessions.load() << " │\n";
        report << "│  Renewals: " << std::setw(6) << sess.session_renewals.load() << "                  │\n";
        report << "│  Avg Duration: " << std::setw(6) << std::fixed << std::setprecision(2)
               << sess.average_session_duration_us.load() / 1000000.0 << " s          │\n";
    }
    
    report << "└─────────────────────────────────────────┘";
    
    return report.str();
}

} // namespace ishikura::network