#pragma once

#include "elgamal.h"
#include "rsa.h"

#include <filesystem>
#include <string>


// 主体公钥的算法种类。
enum class public_key_algorithm {
    RSA,
    ELGAMAL
};

// 证书 Flag1 的含义：0 为 RSA，1 为 ElGamal。
enum class signature_algorithm_type {
    RSA = 0,
    ELGAMAL = 1
};

// 证书 Flag2 的含义：0 为加密，1 为签名。
enum class key_usage_type {
    ENCRYPTION = 0,
    SIGNATURE = 1
};

// 带算法标记的公钥数据，仅使用标记指定的那组参数。
struct public_key_data {
    public_key_algorithm algorithm = public_key_algorithm::RSA; // 决定当前有效数据分支的算法标记
    rsa_public_key rsa; // RSA 参数或签名值
    elgamal_public_key elgamal; // ElGamal 参数或签名值

    static public_key_data from_rsa(const rsa_public_key& public_key);
    static public_key_data from_elgamal(const elgamal_public_key& public_key);
};

// 带算法标记的签名值。
struct signature_value {
    signature_algorithm_type algorithm = signature_algorithm_type::RSA; // 决定当前有效数据分支的算法标记
    big_integer rsa; // RSA 参数或签名值
    elgamal_signature elgamal; // ElGamal 参数或签名值
};

// 课程任务书要求的简单 TXT 证书，签名载荷由 payload 构造。
struct certificate_data {
    std::string subject_id; // 证书主体标识
    public_key_data subject_public_key; // 证书主体的公钥
    std::string issuer_id; // 签发者标识
    signature_algorithm_type flag1 = signature_algorithm_type::RSA; // 签名算法标记，对应 TXT 的 Flag1
    key_usage_type flag2 = key_usage_type::SIGNATURE; // 公钥用途标记，对应 TXT 的 Flag2
    signature_value signature; // 签发者对证书载荷的签名

    std::string payload() const;
    std::string to_text() const;
    void save_to_file(const std::filesystem::path& path) const;

    static certificate_data from_text(const std::string& text);
    static certificate_data load_from_file(const std::filesystem::path& path);
};

std::string public_key_algorithm_name(public_key_algorithm algorithm);
std::string signature_algorithm_name(signature_algorithm_type algorithm);
std::string key_usage_name(key_usage_type usage);
std::string canonical_public_key(const public_key_data& public_key);

certificate_data issue_certificate_rsa(
    const std::string& subject_id,
    const public_key_data& subject_public_key,
    const std::string& issuer_id,
    key_usage_type key_usage,
    const rsa_key_pair& issuer_key_pair);

certificate_data issue_certificate_elgamal(
    const std::string& subject_id,
    const public_key_data& subject_public_key,
    const std::string& issuer_id,
    key_usage_type key_usage,
    const elgamal_key_pair& issuer_key_pair);

bool verify_certificate(const certificate_data& certificate, const public_key_data& issuer_public_key);
