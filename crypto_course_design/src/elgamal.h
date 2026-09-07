#pragma once

#include "common.h"

#include <string>
#include <vector>


// ElGamal 公钥及公共群参数。
struct elgamal_public_key {
    big_integer p; // RSA 私钥中的素数 p；ElGamal 中为公共安全素数模数
    big_integer g; // 模 p 的原根
    big_integer y; // 公钥分量 y=g^x mod p
};

// ElGamal 私钥指数。
struct elgamal_private_key {
    big_integer x; // 私钥指数
};

// ElGamal 密钥对及安全素数的辅助参数。
struct elgamal_key_pair {
    elgamal_public_key public_key; // 配对公钥
    elgamal_private_key private_key; // 配对私钥
    big_integer q; // RSA 私钥中的素数 q；ElGamal 中满足 p=2q+1
};

// 一个 ElGamal 密文块的两个分量。
struct elgamal_cipher_block {
    big_integer c1; // 密文第一分量 g^k mod p
    big_integer c2; // 密文第二分量 message*y^k mod p
};

// ElGamal 数字签名的两个分量。
struct elgamal_signature {
    big_integer r; // 签名第一分量
    big_integer s; // 签名第二分量
};

elgamal_key_pair generate_elgamal_key_pair(long prime_bits = 2048, long primality_error = 80);

elgamal_cipher_block elgamal_encrypt_integer(const big_integer& message, const elgamal_public_key& public_key);
big_integer elgamal_decrypt_integer(const elgamal_cipher_block& cipher, const elgamal_key_pair& key_pair);

std::vector<elgamal_cipher_block> elgamal_encrypt_text(const std::string& plaintext, const elgamal_public_key& public_key);
std::string elgamal_decrypt_text(const std::vector<elgamal_cipher_block>& cipher_blocks, const elgamal_key_pair& key_pair);

elgamal_signature elgamal_sign_message(const std::string& message, const elgamal_key_pair& key_pair);
bool elgamal_verify_message(const std::string& message, const elgamal_signature& signature, const elgamal_public_key& public_key);

std::string serialize_elgamal_public_key(const elgamal_public_key& public_key);
