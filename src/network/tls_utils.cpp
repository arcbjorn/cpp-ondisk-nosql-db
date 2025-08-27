#include "network/tls_server.hpp"
#include <iostream>
#include <fstream>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <cstring>

namespace nosql_db {
namespace network {
namespace tls_utils {

bool generate_self_signed_certificate(const std::string& cert_file,
                                     const std::string& key_file) {
    return generate_self_signed_certificate(cert_file, key_file, CertificateInfo{});
}

bool generate_self_signed_certificate(const std::string& cert_file,
                                     const std::string& key_file,
                                     const CertificateInfo& info) {
    // Generate RSA key pair
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    
    if (BN_set_word(bn, RSA_F4) != 1) {
        std::cerr << "Failed to set RSA exponent" << std::endl;
        BN_free(bn);
        RSA_free(rsa);
        return false;
    }
    
    if (RSA_generate_key_ex(rsa, info.key_size, bn, nullptr) != 1) {
        std::cerr << "Failed to generate RSA key pair" << std::endl;
        BN_free(bn);
        RSA_free(rsa);
        return false;
    }
    
    BN_free(bn);
    
    // Create EVP_PKEY from RSA key
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        std::cerr << "Failed to assign RSA key to EVP_PKEY" << std::endl;
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    // Create X509 certificate
    X509* x509 = X509_new();
    if (!x509) {
        std::cerr << "Failed to create X509 certificate" << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }
    
    // Set certificate version
    X509_set_version(x509, 2); // Version 3
    
    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), info.validity_days * 24 * 60 * 60);
    
    // Set public key
    X509_set_pubkey(x509, pkey);
    
    // Set subject name
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, 
                               reinterpret_cast<const unsigned char*>(info.country.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, 
                               reinterpret_cast<const unsigned char*>(info.organization.c_str()), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
                               reinterpret_cast<const unsigned char*>(info.common_name.c_str()), -1, -1, 0);
    
    // Set issuer name (same as subject for self-signed)
    X509_set_issuer_name(x509, name);
    
    // Add Subject Alternative Name extension
    X509_EXTENSION* san_ext = nullptr;
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, x509, x509, nullptr, nullptr, 0);
    
    std::string san_value = "DNS:" + info.common_name;
    if (info.common_name != "localhost") {
        san_value += ",DNS:localhost";
    }
    san_value += ",IP:127.0.0.1";
    
    san_ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, san_value.c_str());
    if (san_ext) {
        X509_add_ext(x509, san_ext, -1);
        X509_EXTENSION_free(san_ext);
    }
    
    // Sign the certificate
    if (X509_sign(x509, pkey, EVP_sha256()) == 0) {
        std::cerr << "Failed to sign certificate" << std::endl;
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    // Write certificate to file
    FILE* cert_fp = fopen(cert_file.c_str(), "wb");
    if (!cert_fp) {
        std::cerr << "Failed to open certificate file for writing: " << cert_file << std::endl;
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    if (PEM_write_X509(cert_fp, x509) != 1) {
        std::cerr << "Failed to write certificate to file" << std::endl;
        fclose(cert_fp);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    fclose(cert_fp);
    
    // Write private key to file
    FILE* key_fp = fopen(key_file.c_str(), "wb");
    if (!key_fp) {
        std::cerr << "Failed to open key file for writing: " << key_file << std::endl;
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    if (PEM_write_PrivateKey(key_fp, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        std::cerr << "Failed to write private key to file" << std::endl;
        fclose(key_fp);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    fclose(key_fp);
    
    // Cleanup
    X509_free(x509);
    EVP_PKEY_free(pkey);
    
    std::cout << "Generated self-signed certificate:" << std::endl;
    std::cout << "  Certificate: " << cert_file << std::endl;
    std::cout << "  Private Key: " << key_file << std::endl;
    std::cout << "  Common Name: " << info.common_name << std::endl;
    std::cout << "  Valid for " << info.validity_days << " days" << std::endl;
    
    return true;
}

bool validate_certificate_file(const std::string& cert_file) {
    FILE* fp = fopen(cert_file.c_str(), "r");
    if (!fp) {
        return false;
    }
    
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    
    if (!cert) {
        return false;
    }
    
    // Check if certificate is not expired
    ASN1_TIME* not_after = X509_get_notAfter(cert);
    int result = X509_cmp_current_time(not_after);
    
    X509_free(cert);
    return result > 0; // Certificate is still valid
}

bool validate_private_key_file(const std::string& key_file) {
    FILE* fp = fopen(key_file.c_str(), "r");
    if (!fp) {
        return false;
    }
    
    EVP_PKEY* key = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    
    if (!key) {
        return false;
    }
    
    // Validate the key
    int result = 0;
    
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // OpenSSL 3.0+ API
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
    if (ctx) {
        result = EVP_PKEY_check(ctx);
        EVP_PKEY_CTX_free(ctx);
    }
#else
    // Legacy API
    if (EVP_PKEY_base_id(key) == EVP_PKEY_RSA) {
        RSA* rsa = EVP_PKEY_get1_RSA(key);
        if (rsa) {
            result = RSA_check_key(rsa);
            RSA_free(rsa);
        }
    } else {
        result = 1; // Assume valid for non-RSA keys
    }
#endif
    
    EVP_PKEY_free(key);
    return result == 1;
}

bool validate_certificate_key_pair(const std::string& cert_file, 
                                  const std::string& key_file) {
    // Load certificate
    FILE* cert_fp = fopen(cert_file.c_str(), "r");
    if (!cert_fp) {
        return false;
    }
    
    X509* cert = PEM_read_X509(cert_fp, nullptr, nullptr, nullptr);
    fclose(cert_fp);
    
    if (!cert) {
        return false;
    }
    
    // Load private key
    FILE* key_fp = fopen(key_file.c_str(), "r");
    if (!key_fp) {
        X509_free(cert);
        return false;
    }
    
    EVP_PKEY* key = PEM_read_PrivateKey(key_fp, nullptr, nullptr, nullptr);
    fclose(key_fp);
    
    if (!key) {
        X509_free(cert);
        return false;
    }
    
    // Get public key from certificate
    EVP_PKEY* cert_key = X509_get_pubkey(cert);
    if (!cert_key) {
        X509_free(cert);
        EVP_PKEY_free(key);
        return false;
    }
    
    // Compare public keys
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    int result = EVP_PKEY_eq(key, cert_key);
#else
    int result = EVP_PKEY_cmp(key, cert_key);
#endif
    
    EVP_PKEY_free(cert_key);
    EVP_PKEY_free(key);
    X509_free(cert);
    
    return result == 1;
}

std::chrono::system_clock::time_point get_certificate_expiry(const std::string& cert_file) {
    FILE* fp = fopen(cert_file.c_str(), "r");
    if (!fp) {
        return std::chrono::system_clock::time_point{};
    }
    
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    
    if (!cert) {
        return std::chrono::system_clock::time_point{};
    }
    
    ASN1_TIME* not_after = X509_get_notAfter(cert);
    struct tm tm_time;
    ASN1_TIME_to_tm(not_after, &tm_time);
    
    X509_free(cert);
    
    // Convert to system_clock::time_point
    std::time_t time = std::mktime(&tm_time);
    return std::chrono::system_clock::from_time_t(time);
}

std::string get_certificate_subject(const std::string& cert_file) {
    FILE* fp = fopen(cert_file.c_str(), "r");
    if (!fp) {
        return "";
    }
    
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    
    if (!cert) {
        return "";
    }
    
    char* subject = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
    std::string result;
    if (subject) {
        result = subject;
        OPENSSL_free(subject);
    }
    
    X509_free(cert);
    return result;
}

std::string get_certificate_issuer(const std::string& cert_file) {
    FILE* fp = fopen(cert_file.c_str(), "r");
    if (!fp) {
        return "";
    }
    
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    
    if (!cert) {
        return "";
    }
    
    char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
    std::string result;
    if (issuer) {
        result = issuer;
        OPENSSL_free(issuer);
    }
    
    X509_free(cert);
    return result;
}

std::vector<std::string> get_certificate_san_list(const std::string& cert_file) {
    std::vector<std::string> san_list;
    
    FILE* fp = fopen(cert_file.c_str(), "r");
    if (!fp) {
        return san_list;
    }
    
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    
    if (!cert) {
        return san_list;
    }
    
    STACK_OF(GENERAL_NAME)* san_names = static_cast<STACK_OF(GENERAL_NAME)*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    
    if (san_names) {
        int san_count = sk_GENERAL_NAME_num(san_names);
        for (int i = 0; i < san_count; ++i) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(san_names, i);
            if (name->type == GEN_DNS) {
                const unsigned char* dns_data = ASN1_STRING_get0_data(name->d.dNSName);
                char* dns_name = reinterpret_cast<char*>(const_cast<unsigned char*>(dns_data));
                if (dns_name) {
                    san_list.push_back(std::string(dns_name));
                }
            } else if (name->type == GEN_IPADD) {
                // Handle IP addresses
                const unsigned char* ip_data = ASN1_STRING_get0_data(name->d.iPAddress);
                int ip_len = ASN1_STRING_length(name->d.iPAddress);
                
                if (ip_len == 4) { // IPv4
                    char ip_str[INET_ADDRSTRLEN];
                    if (inet_ntop(AF_INET, ip_data, ip_str, INET_ADDRSTRLEN)) {
                        san_list.push_back(std::string(ip_str));
                    }
                } else if (ip_len == 16) { // IPv6
                    char ip_str[INET6_ADDRSTRLEN];
                    if (inet_ntop(AF_INET6, ip_data, ip_str, INET6_ADDRSTRLEN)) {
                        san_list.push_back(std::string(ip_str));
                    }
                }
            }
        }
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    }
    
    X509_free(cert);
    return san_list;
}

std::string tls_version_to_string(int version) {
    switch (version) {
        case TLS1_VERSION: return "TLSv1.0";
        case TLS1_1_VERSION: return "TLSv1.1";
        case TLS1_2_VERSION: return "TLSv1.2";
        case TLS1_3_VERSION: return "TLSv1.3";
        case SSL3_VERSION: return "SSLv3";
        default: return "Unknown";
    }
}

int string_to_tls_version(const std::string& version) {
    if (version == "TLSv1.0") return TLS1_VERSION;
    if (version == "TLSv1.1") return TLS1_1_VERSION;
    if (version == "TLSv1.2") return TLS1_2_VERSION;
    if (version == "TLSv1.3") return TLS1_3_VERSION;
    if (version == "SSLv3") return SSL3_VERSION;
    return -1; // Unknown
}

std::vector<std::string> get_supported_ciphers(SSL_CTX* ctx) {
    std::vector<std::string> ciphers;
    
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        return ciphers;
    }
    
    STACK_OF(SSL_CIPHER)* cipher_stack = SSL_get_ciphers(ssl);
    if (cipher_stack) {
        int cipher_count = sk_SSL_CIPHER_num(cipher_stack);
        for (int i = 0; i < cipher_count; ++i) {
            const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(cipher_stack, i);
            if (cipher) {
                const char* name = SSL_CIPHER_get_name(cipher);
                if (name) {
                    ciphers.push_back(std::string(name));
                }
            }
        }
    }
    
    SSL_free(ssl);
    return ciphers;
}

} // namespace tls_utils
} // namespace network
} // namespace nosql_db