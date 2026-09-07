#pragma once

#include "common.h"

#include <string>
#include <vector>


// RSA 公钥，供加密和签名验证使用。
struct rsa_public_key {
    big_integer n; // RSA 模数 n=p*q
    big_integer b; // RSA 公钥指数
};

// RSA 私钥，保存两个素数及私钥指数。
struct rsa_private_key {
    big_integer p; // RSA 私钥中的素数 p；ElGamal 中为公共安全素数模数
    big_integer q; // RSA 私钥中的素数 q；ElGamal 中满足 p=2q+1
    big_integer a; // RSA 私钥指数
};

// 一套配对的 RSA 公钥和私钥。
struct rsa_key_pair {
    rsa_public_key public_key; // 配对公钥
    rsa_private_key private_key; // 配对私钥
};

rsa_key_pair generate_rsa_key_pair(long prime_bits = 1024, long primality_error = 80);

big_integer rsa_encrypt_integer(const big_integer& message, const rsa_public_key& public_key);
big_integer rsa_decrypt_integer(const big_integer& cipher, const rsa_key_pair& key_pair);

std::vector<big_integer> rsa_encrypt_text(const std::string& plaintext, const rsa_public_key& public_key);
std::string rsa_decrypt_text(const std::vector<big_integer>& cipher_blocks, const rsa_key_pair& key_pair);

big_integer rsa_sign_message(const std::string& message, const rsa_key_pair& key_pair);
bool rsa_verify_message(const std::string& message, const big_integer& signature, const rsa_public_key& public_key);

std::string serialize_rsa_public_key(const rsa_public_key& public_key);
