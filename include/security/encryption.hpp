#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <chrono>
#include <unordered_map>
#include <mutex>

namespace nosql_db::security {

/**
 * Data encryption and key management for NoSQL database
 * Provides AES-256 encryption for data at rest and in transit
 */

// Forward declarations
class EncryptionKey;
class DataEncryptor;
class KeyManager;

/**
 * Represents an encryption key with metadata
 */
class EncryptionKey {
public:
    EncryptionKey(const std::string& key_id, const std::vector<uint8_t>& key_data);
    
    // Key information
    const std::string& key_id() const { return key_id_; }
    const std::vector<uint8_t>& key_data() const { return key_data_; }
    std::chrono::system_clock::time_point created_at() const { return created_at_; }
    std::chrono::system_clock::time_point expires_at() const { return expires_at_; }
    
    // Key status
    bool is_active() const { return active_; }
    bool is_expired() const;
    void set_active(bool active) { active_ = active; }
    void set_expiration(std::chrono::system_clock::time_point expiry) { expires_at_ = expiry; }
    
    // Key rotation
    void mark_for_rotation() { pending_rotation_ = true; }
    bool is_pending_rotation() const { return pending_rotation_; }
    
    // Serialization for secure storage
    std::vector<uint8_t> serialize() const;
    static std::optional<EncryptionKey> deserialize(const std::vector<uint8_t>& data);
    
private:
    std::string key_id_;
    std::vector<uint8_t> key_data_;
    std::chrono::system_clock::time_point created_at_;
    std::chrono::system_clock::time_point expires_at_;
    bool active_{true};
    bool pending_rotation_{false};
};

/**
 * High-level data encryption interface
 */
class DataEncryptor {
public:
    struct EncryptionOptions {
        std::string algorithm = "AES-256-GCM";
        bool compress_before_encrypt = true;
        bool include_metadata = true;
    };
    
    explicit DataEncryptor(std::shared_ptr<KeyManager> key_manager);
    
    // Encryption/Decryption
    std::optional<std::vector<uint8_t>> encrypt(const std::vector<uint8_t>& plaintext,
                                               const std::string& key_id = "",
                                               const EncryptionOptions& options = {});
    
    std::optional<std::vector<uint8_t>> decrypt(const std::vector<uint8_t>& ciphertext);
    
    // String convenience methods
    std::optional<std::string> encrypt_string(const std::string& plaintext,
                                             const std::string& key_id = "",
                                             const EncryptionOptions& options = {});
    
    std::optional<std::string> decrypt_string(const std::string& ciphertext_base64);
    
    // File encryption
    bool encrypt_file(const std::string& input_path, const std::string& output_path,
                     const std::string& key_id = "");
    bool decrypt_file(const std::string& input_path, const std::string& output_path);
    
    // Streaming encryption for large data
    class EncryptionStream {
    public:
        virtual ~EncryptionStream() = default;
        virtual bool update(const std::vector<uint8_t>& data) = 0;
        virtual std::optional<std::vector<uint8_t>> finalize() = 0;
    };
    
    std::unique_ptr<EncryptionStream> create_encryption_stream(const std::string& key_id = "");
    std::unique_ptr<EncryptionStream> create_decryption_stream();
    
private:
    std::shared_ptr<KeyManager> key_manager_;
    
    // Low-level encryption primitives
    std::optional<std::vector<uint8_t>> aes_encrypt(const std::vector<uint8_t>& plaintext,
                                                   const EncryptionKey& key,
                                                   std::vector<uint8_t>& iv);
    
    std::optional<std::vector<uint8_t>> aes_decrypt(const std::vector<uint8_t>& ciphertext,
                                                   const EncryptionKey& key,
                                                   const std::vector<uint8_t>& iv);
    
    std::vector<uint8_t> compress_data(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decompress_data(const std::vector<uint8_t>& compressed_data);
    
    // Metadata handling
    struct EncryptionMetadata {
        std::string key_id;
        std::string algorithm;
        std::vector<uint8_t> iv;
        bool compressed;
        uint64_t original_size;
        uint32_t checksum;
    };
    
    std::vector<uint8_t> serialize_metadata(const EncryptionMetadata& metadata);
    std::optional<EncryptionMetadata> parse_metadata(const std::vector<uint8_t>& data, size_t& offset);
};

/**
 * Encryption key management and rotation
 */
class KeyManager {
public:
    struct KeyConfig {
        std::chrono::hours key_rotation_interval{24 * 30}; // 30 days
        size_t key_history_size = 10; // Keep last 10 keys for decryption
        std::string key_derivation_algorithm = "PBKDF2";
        int key_derivation_iterations = 100000;
        bool auto_rotation_enabled = true;
    };
    
    explicit KeyManager(const KeyConfig& config = KeyConfig{});
    
    // Key creation and management
    std::string create_key(const std::string& key_id = "");
    std::optional<EncryptionKey> get_key(const std::string& key_id);
    std::optional<EncryptionKey> get_active_key();
    
    // Key rotation
    bool rotate_key(const std::string& key_id);
    void enable_auto_rotation();
    void disable_auto_rotation();
    std::vector<std::string> get_keys_pending_rotation();
    
    // Master key management
    bool set_master_password(const std::string& password);
    bool unlock_with_master_password(const std::string& password);
    bool is_unlocked() const { return unlocked_; }
    void lock() { unlocked_ = false; }
    
    // Key derivation from passwords
    std::string derive_key_from_password(const std::string& password, const std::string& salt = "");
    
    // Persistence
    bool save_keys_to_file(const std::string& filepath);
    bool load_keys_from_file(const std::string& filepath);
    
    // Statistics
    struct KeyStats {
        size_t total_keys{0};
        size_t active_keys{0};
        size_t expired_keys{0};
        size_t rotations_performed{0};
        std::chrono::system_clock::time_point last_rotation;
    };
    
    KeyStats get_stats() const;
    
    // Configuration
    const KeyConfig& config() const { return config_; }
    void update_config(const KeyConfig& config);
    
private:
    KeyConfig config_;
    std::unordered_map<std::string, EncryptionKey> keys_;
    std::string active_key_id_;
    std::string master_key_hash_;
    bool unlocked_{false};
    
    mutable std::mutex keys_mutex_;
    
    // Helper methods
    std::vector<uint8_t> generate_random_key(size_t key_size = 32); // 256 bits
    std::string generate_key_id();
    std::vector<uint8_t> derive_key_from_master(const std::string& key_id);
    bool verify_master_password(const std::string& password);
    
    // Auto-rotation management
    std::thread rotation_thread_;
    std::atomic<bool> auto_rotation_active_{false};
    void rotation_worker();
    void check_and_rotate_keys();
};

/**
 * Transparent encryption layer for storage engines
 */
class TransparentEncryption {
public:
    explicit TransparentEncryption(std::shared_ptr<DataEncryptor> encryptor);
    
    // Storage operations with automatic encryption
    bool put_encrypted(const std::string& key, const std::string& value);
    std::optional<std::string> get_decrypted(const std::string& key);
    bool delete_encrypted(const std::string& key);
    
    // Batch operations
    bool batch_put_encrypted(const std::vector<std::pair<std::string, std::string>>& pairs);
    std::vector<std::pair<std::string, std::optional<std::string>>> 
        batch_get_decrypted(const std::vector<std::string>& keys);
    
    // Key rotation for existing data
    bool rotate_data_encryption(const std::string& old_key_id, const std::string& new_key_id);
    size_t count_encrypted_records();
    
    // Statistics
    struct EncryptionStats {
        uint64_t encrypted_records{0};
        uint64_t decryption_operations{0};
        uint64_t encryption_operations{0};
        uint64_t key_rotations{0};
        double average_encryption_time_ms{0.0};
        double average_decryption_time_ms{0.0};
    };
    
    const EncryptionStats& stats() const { return stats_; }
    
private:
    std::shared_ptr<DataEncryptor> encryptor_;
    EncryptionStats stats_;
    
    std::string get_encrypted_key_prefix(const std::string& key);
    void update_timing_stats(std::chrono::steady_clock::time_point start, bool is_encryption);
};

/**
 * Security utilities and helpers
 */
namespace crypto_utils {
    // Random number generation
    std::vector<uint8_t> generate_random_bytes(size_t count);
    std::string generate_random_string(size_t length);
    
    // Hashing
    std::string sha256_hash(const std::string& input);
    std::string sha256_hash(const std::vector<uint8_t>& input);
    
    // Base64 encoding/decoding
    std::string base64_encode(const std::vector<uint8_t>& data);
    std::optional<std::vector<uint8_t>> base64_decode(const std::string& encoded);
    
    // Key derivation
    std::vector<uint8_t> pbkdf2(const std::string& password, const std::string& salt, 
                               int iterations, size_t key_length);
    
    // Secure memory operations
    void secure_zero_memory(void* ptr, size_t size);
    bool secure_memory_compare(const void* a, const void* b, size_t size);
    
    // Checksums and integrity
    uint32_t calculate_crc32(const std::vector<uint8_t>& data);
    bool verify_integrity(const std::vector<uint8_t>& data, uint32_t expected_crc);
}

} // namespace nosql_db::security