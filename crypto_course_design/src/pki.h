#pragma once

#include "certificate.h"

#include <filesystem>
#include <map>
#include <ostream>
#include <string>
#include <vector>


// 按主体与用途管理证书，写入接口仅对 CA 开放。
class certificate_repository {
public:
    std::vector<certificate_data> query_path(const std::string& subject_id, key_usage_type key_usage) const;
    const certificate_data* find(const std::string& subject_id, key_usage_type key_usage) const;
    void save_all(const std::filesystem::path& directory) const;
    std::size_t size() const;

private:
    friend class certificate_authority;

    bool store_from_ca(const certificate_data& certificate, const std::string& ca_id);
    static std::string storage_key(const std::string& subject_id, key_usage_type key_usage);
    std::map<std::string, certificate_data> certificates_; // 以主体标识和用途为键的证书表
};

// 严格层次 PKI 中持有 RSA 密钥和证书的 CA。
class certificate_authority {
public:
    static certificate_authority create_root_rsa(
        const std::string& id,
        certificate_repository& repository,
        long rsa_prime_bits);

    static certificate_authority create_child_rsa(
        const std::string& id,
        const certificate_authority& issuer,
        certificate_repository& repository,
        long rsa_prime_bits);

    certificate_data issue_certificate(
        const std::string& subject_id,
        const public_key_data& subject_public_key,
        key_usage_type key_usage) const;

    const std::string& id() const;
    const rsa_key_pair& key_pair() const;
    const certificate_data& certificate() const;

private:
    certificate_authority(
        std::string id,
        rsa_key_pair key_pair,
        certificate_data certificate,
        certificate_repository& repository);

    std::string id_; // 对象的身份标识
    rsa_key_pair key_pair_; // CA 自身的 RSA 密钥对
    certificate_data certificate_; // CA 自身的证书
    certificate_repository* repository_; // 关联证书库的地址，不负责释放
};

// 严格层次 PKI 演示的验证结果及输出位置。
struct pki_demo_result {
    bool path_verified = false; // 证书链是否通过验证
    bool signature_verified = false; // 消息签名是否通过验证
    bool tampered_path_rejected = false; // 篡改证书链是否被拒绝
    std::string message; // 演示中签名的消息
    std::string alice_signature; // Alice 的消息签名文本
    std::vector<std::string> certificate_path_ids; // 从根到主体排列的身份标识
    std::filesystem::path certificate_directory; // 导出的证书所在目录
    std::size_t repository_size = 0; // 证书库记录数
};

bool verify_certificate_path(
    const std::vector<certificate_data>& path,
    const public_key_data& trusted_root_public_key,
    std::string* error_message);

pki_demo_result run_strict_hierarchy_pki_demo(
    long rsa_prime_bits,
    const std::filesystem::path& output_directory,
    std::ostream& log);
