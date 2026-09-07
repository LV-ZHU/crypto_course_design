#pragma once

#include "certificate.h"

#include <string>
#include <vector>


class certificate_authority;

// 加密和签名使用独立密钥对的 PKI 用户。
class pki_user {
public:
    pki_user(std::string id, long rsa_prime_bits);

    void request_certificates(const certificate_authority& authority);

    const std::string& id() const;
    const rsa_public_key& encryption_public_key() const;
    const rsa_public_key& signature_public_key() const;
    const certificate_data& certificate(key_usage_type key_usage) const;

    big_integer sign_message(const std::string& message) const;
    std::string decrypt_text(const std::vector<big_integer>& cipher_blocks) const;

private:
    std::string id_; // 对象的身份标识
    rsa_key_pair encryption_key_pair_; // 用于接收密文的加密密钥对
    rsa_key_pair signature_key_pair_; // 用于消息签名的密钥对
    certificate_data encryption_certificate_; // 加密公钥证书
    certificate_data signature_certificate_; // 签名公钥证书
    bool has_encryption_certificate_ = false; // 是否已申请加密证书
    bool has_signature_certificate_ = false; // 是否已申请签名证书
};
