#include "elgamal.h"

#include "hash.h"

#include <stdexcept>


/***************************************************************************
  函数名称：find_primitive_root_for_safe_prime
  功    能：寻找安全素数模数对应的原根
  输入参数：const big_integer& p：安全素数模数
  const big_integer& q：满足 p=2q+1 的辅助素数
  返 回 值：模 p 的原根 g
  说    明：要求 p=2q+1 且 p、q 为素数；排除阶为 1、2、q 的候选值。
***************************************************************************/
static big_integer find_primitive_root_for_safe_prime(const big_integer& p, const big_integer& q)
{
    while (true) {
        const big_integer g = random_between(NTL::conv<big_integer>(2), p - 2);
        if (NTL::PowerMod(g, 2, p) != 1 && NTL::PowerMod(g, q, p) != 1) {
            return g;
        }
    }
}


/***************************************************************************
  函数名称：generate_elgamal_key_pair
  功    能：生成 ElGamal 公钥和私钥
  输入参数：long prime_bits：所生成素数的二进制位数
  long primality_error：传递给 NTL 素数生成函数的错误界参数
  返 回 值：包含 p、g、y、x 和辅助素数 q 的密钥对
  说    明：先生成 q 和安全素数 p=2q+1，再选择原根及私钥；prime_bits 不小于 128。
***************************************************************************/
elgamal_key_pair generate_elgamal_key_pair(long prime_bits, long primality_error)
{
    if (prime_bits < 128) {
        throw std::invalid_argument("ElGamal primeBits should be at least 128 for this demo");
    }

    const big_integer q = NTL::GenGermainPrime_ZZ(prime_bits - 1, primality_error);
    const big_integer p = 2 * q + 1;
    const big_integer g = find_primitive_root_for_safe_prime(p, q);
    const big_integer x = random_between(NTL::conv<big_integer>(2), p - 2);
    const big_integer y = NTL::PowerMod(g, x, p);
    elgamal_key_pair result;
    result.public_key.p = p;
    result.public_key.g = g;
    result.public_key.y = y;
    result.private_key.x = x;
    result.q = q;
    return result;
}

/***************************************************************************
  函数名称：elgamal_encrypt_integer
  功    能：使用 ElGamal 加密单个整数
  输入参数：const big_integer& message：待加密、签名或验证的消息；指针参数用于输出正文
  const elgamal_public_key& public_key：算法对应的公钥
  返 回 值：包含 c1、c2 的密文块
  说    明：每次重新选择随机 k，计算 c1=g^k、c2=message*y^k，结果均模 p。
***************************************************************************/
elgamal_cipher_block elgamal_encrypt_integer(const big_integer& message, const elgamal_public_key& public_key)
{
    if (message < 0 || message >= public_key.p) {
        throw std::invalid_argument("ElGamal message representative is outside [0,p)");
    }
    const big_integer k = random_between(NTL::conv<big_integer>(2), public_key.p - 2);
    const big_integer c1 = NTL::PowerMod(public_key.g, k, public_key.p);
    const big_integer shared = NTL::PowerMod(public_key.y, k, public_key.p);
    const big_integer c2 = (message * shared) % public_key.p;
    elgamal_cipher_block result;
    result.c1 = c1;
    result.c2 = c2;
    return result;
}

/***************************************************************************
  函数名称：elgamal_decrypt_integer
  功    能：使用 ElGamal 私钥解密整数
  输入参数：const elgamal_cipher_block& cipher：单个密文整数或密文块
  const elgamal_key_pair& key_pair：包含公钥和私钥的密钥对
  返 回 值：恢复的消息整数
  说    明：检查密文范围，再用 c1^x 的模逆消去共享因子。
***************************************************************************/
big_integer elgamal_decrypt_integer(const elgamal_cipher_block& cipher, const elgamal_key_pair& key_pair)
{
    const big_integer& p = key_pair.public_key.p;
    if (cipher.c1 <= 0 || cipher.c1 >= p || cipher.c2 < 0 || cipher.c2 >= p) {
        throw std::invalid_argument("ElGamal ciphertext representative is outside modulus range");
    }
    const big_integer shared = NTL::PowerMod(cipher.c1, key_pair.private_key.x, p);
    return (cipher.c2 * NTL::InvMod(shared, p)) % p;
}

/***************************************************************************
  函数名称：elgamal_encrypt_text
  功    能：对文本分块后执行 ElGamal 加密
  输入参数：const std::string& plaintext：待加密的原始文本
  const elgamal_public_key& public_key：算法对应的公钥
  返 回 值：ElGamal 密文块数组
  说    明：各块独立选择随机数，保持与统一分块编码格式兼容。
***************************************************************************/
std::vector<elgamal_cipher_block> elgamal_encrypt_text(const std::string& plaintext, const elgamal_public_key& public_key)
{
    const std::vector<big_integer> blocks = text_to_blocks(plaintext, public_key.p);
    std::vector<elgamal_cipher_block> encrypted;
    encrypted.reserve(blocks.size());
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const big_integer& block = blocks[i];
        encrypted.push_back(elgamal_encrypt_integer(block, public_key));
    }
    return encrypted;
}

/***************************************************************************
  函数名称：elgamal_decrypt_text
  功    能：解密 ElGamal 密文并恢复文本
  输入参数：const std::vector<elgamal_cipher_block>& cipher_blocks：按顺序排列的密文块
  const elgamal_key_pair& key_pair：包含公钥和私钥的密钥对
  返 回 值：恢复的原始字符串
  说    明：逐块还原整数，再按长度前缀重组字节。
***************************************************************************/
std::string elgamal_decrypt_text(const std::vector<elgamal_cipher_block>& cipher_blocks, const elgamal_key_pair& key_pair)
{
    std::vector<big_integer> blocks;
    blocks.reserve(cipher_blocks.size());
    for (std::size_t i = 0; i < cipher_blocks.size(); ++i) {
        const elgamal_cipher_block& cipher = cipher_blocks[i];
        blocks.push_back(elgamal_decrypt_integer(cipher, key_pair));
    }
    return blocks_to_text(blocks, key_pair.public_key.p);
}

/***************************************************************************
  函数名称：elgamal_sign_message
  功    能：生成消息的 ElGamal 签名
  输入参数：const std::string& message：待加密、签名或验证的消息；指针参数用于输出正文
  const elgamal_key_pair& key_pair：包含公钥和私钥的密钥对
  返 回 值：由 r 和 s 组成的签名
  说    明：随机 k 必须与 p-1 互素；计算 r=g^k，s=(摘要-x*r)/k 模 p-1。
***************************************************************************/
elgamal_signature elgamal_sign_message(const std::string& message, const elgamal_key_pair& key_pair)
{
    const big_integer& p = key_pair.public_key.p;
    const big_integer modulus = p - 1;
    const big_integer digest = hash_to_zz(message) % modulus;

    big_integer k;
    do {
        k = random_between(NTL::conv<big_integer>(2), p - 2);
    } while (NTL::GCD(k, modulus) != 1);

    const big_integer r = NTL::PowerMod(key_pair.public_key.g, k, p);
    const big_integer inverse = NTL::InvMod(k, modulus);
    const big_integer s = mod_positive((digest - key_pair.private_key.x * r) * inverse, modulus);
    elgamal_signature result;
    result.r = r;
    result.s = s;
    return result;
}

/***************************************************************************
  函数名称：elgamal_verify_message
  功    能：验证消息的 ElGamal 签名
  输入参数：const std::string& message：待加密、签名或验证的消息；指针参数用于输出正文
  const elgamal_signature& signature：签名值；指针参数用于输出解析结果
  const elgamal_public_key& public_key：算法对应的公钥
  返 回 值：true 为通过，false 为签名无效
  说    明：检查 r、s 范围，并比较 y^r*r^s 与 g^摘要 模 p 的结果。
***************************************************************************/
bool elgamal_verify_message(const std::string& message, const elgamal_signature& signature, const elgamal_public_key& public_key)
{
    const big_integer& p = public_key.p;
    if (signature.r <= 0 || signature.r >= p || signature.s < 0 || signature.s >= p - 1) {
        return false;
    }
    const big_integer digest = hash_to_zz(message) % (p - 1);
    const big_integer left = (NTL::PowerMod(public_key.y, signature.r, p) * NTL::PowerMod(signature.r, signature.s, p)) % p;
    const big_integer right = NTL::PowerMod(public_key.g, digest, p);
    return left == right;
}

/***************************************************************************
  函数名称：serialize_elgamal_public_key
  功    能：生成 ElGamal 公钥的规范文本
  输入参数：const elgamal_public_key& public_key：算法对应的公钥
  返 回 值：包含 p、g、y 的字符串
  说    明：字段顺序固定，用于证书载荷及公钥比较。
***************************************************************************/
std::string serialize_elgamal_public_key(const elgamal_public_key& public_key)
{
    return "ELGAMAL|p=" + zz_to_string(public_key.p) + "|g=" + zz_to_string(public_key.g) + "|y=" + zz_to_string(public_key.y);
}
