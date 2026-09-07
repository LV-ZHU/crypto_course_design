#pragma once

#include "certificate.h"

#include <string>


// 可使用 RSA 或 ElGamal 签发简单证书的可信机构。
class trusted_authority {
public:
    static trusted_authority create_rsa(const std::string& id, long rsa_prime_bits);
    static trusted_authority create_elgamal(const std::string& id, long elgamal_prime_bits);
    static trusted_authority from_elgamal_key_pair(const std::string& id, const elgamal_key_pair& key_pair);

    certificate_data issue_certificate(
        const std::string& subject_id,
        const public_key_data& subject_public_key,
        key_usage_type key_usage) const;

    const std::string& id() const;
    public_key_data get_public_key() const;
    signature_algorithm_type get_signature_algorithm() const;

private:
    trusted_authority();

    std::string id_; // 对象的身份标识
    signature_algorithm_type signature_algorithm_ = signature_algorithm_type::RSA; // 机构使用的签名算法
    rsa_key_pair rsa_key_pair_; // RSA 签发密钥
    elgamal_key_pair elgamal_key_pair_; // ElGamal 签发密钥
};
