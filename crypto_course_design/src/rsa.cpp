#include "rsa.h"

#include "hash.h"

#include <stdexcept>


/***************************************************************************
  函数名称：generate_rsa_key_pair
  功    能：生成 RSA 公钥和私钥
  输入参数：long prime_bits：所生成素数的二进制位数
  long primality_error：传递给 NTL 素数生成函数的错误界参数
  返 回 值：包含公钥与私钥的密钥对
  说    明：生成不同的 p、q，优先选 b=65537，并求 a=b 的模 phi 逆元；prime_bits 不小于 128。
***************************************************************************/
rsa_key_pair generate_rsa_key_pair(long prime_bits, long primality_error)
{
    // 基本参数检查：RSA 素数位数太小没有实际意义
    if (prime_bits < 128) {
        throw std::invalid_argument("RSA primeBits should be at least 128 for this demo");
    }

    // 生成第一个素数 p
    big_integer p = NTL::GenPrime_ZZ(prime_bits, primality_error);

    // 继续生成第二个素数 q，直到 q 与 p 不相等
    big_integer q;
    do {
        q = NTL::GenPrime_ZZ(prime_bits, primality_error);
    } while (q == p);

    // 计算 RSA 模数 n = p * q
    const big_integer n = p * q;

    // 计算欧拉函数 phi = (p - 1) * (q - 1)
    const big_integer phi = (p - 1) * (q - 1);

    // 选择公钥指数 b，优先使用 65537
    // 65537 是 RSA 中非常常用的公钥指数，通常效率和安全性都较好
    big_integer b = NTL::conv<big_integer>(65537);

    // 如果 gcd(b, phi) != 1，说明 b 与 phi 不互素，不能求逆元
    // 此时重新随机找一个满足条件的 b
    if (NTL::GCD(b, phi) != 1) {
        do {
            // 在 [3, phi-1] 范围内随机选取一个整数
            b = random_between(NTL::conv<big_integer>(3), phi - 1);

            // RSA 公钥指数一般取奇数，这里若为偶数则加 1
            if (b % 2 == 0) {
                ++b;
            }
        } while (b >= phi || NTL::GCD(b, phi) != 1);
    }

    // 计算私钥指数 a，使得 a * b ≡ 1 (mod phi)
    // 也就是 b 在模 phi 意义下的乘法逆元
    const big_integer a = NTL::InvMod(b, phi);

    // 构造并返回 RSA 密钥对
    rsa_key_pair result;
    result.public_key.n = n;
    result.public_key.b = b;
    result.private_key.p = p;
    result.private_key.q = q;
    result.private_key.a = a;
    return result;
}

/***************************************************************************
  函数名称：rsa_encrypt_integer
  功    能：对单个整数执行 RSA 加密
  输入参数：const big_integer& message：待加密、签名或验证的消息；指针参数用于输出正文
  const rsa_public_key& public_key：算法对应的公钥
  返 回 值：密文整数
  说    明：要求 0<=message<n，计算 message 的 b 次幂模 n；越界时抛出异常。
***************************************************************************/
big_integer rsa_encrypt_integer(const big_integer& message, const rsa_public_key& public_key)
{
    if (message < 0 || message >= public_key.n) {
        throw std::invalid_argument("RSA message representative is outside [0,n)");
    }
    return NTL::PowerMod(message, public_key.b, public_key.n);
}

/***************************************************************************
  函数名称：rsa_decrypt_integer
  功    能：对单个整数执行 RSA 解密
  输入参数：const big_integer& cipher：单个密文整数或密文块
  const rsa_key_pair& key_pair：包含公钥和私钥的密钥对
  返 回 值：解密得到的整数
  说    明：要求 0<=cipher<n，计算 cipher 的 a 次幂模 n。
***************************************************************************/
big_integer rsa_decrypt_integer(const big_integer& cipher, const rsa_key_pair& key_pair)
{
    if (cipher < 0 || cipher >= key_pair.public_key.n) {
        throw std::invalid_argument("RSA ciphertext representative is outside [0,n)");
    }
    return NTL::PowerMod(cipher, key_pair.private_key.a, key_pair.public_key.n);
}

/***************************************************************************
  函数名称：rsa_encrypt_text
  功    能：对文本分块后执行 RSA 加密
  输入参数：const std::string& plaintext：待加密的原始文本
  const rsa_public_key& public_key：算法对应的公钥
  返 回 值：按原文顺序排列的密文块
  说    明：沿用课程项目的可逆分块格式，各块分别调用整数加密函数。
***************************************************************************/
std::vector<big_integer> rsa_encrypt_text(const std::string& plaintext, const rsa_public_key& public_key)
{
    const std::vector<big_integer> blocks = text_to_blocks(plaintext, public_key.n);
    std::vector<big_integer> encrypted;
    encrypted.reserve(blocks.size());
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const big_integer& block = blocks[i];
        encrypted.push_back(rsa_encrypt_integer(block, public_key));
    }
    return encrypted;
}

/***************************************************************************
  函数名称：rsa_decrypt_text
  功    能：对 RSA 密文块解密并还原文本
  输入参数：const std::vector<big_integer>& cipher_blocks：按顺序排列的密文块
  const rsa_key_pair& key_pair：包含公钥和私钥的密钥对
  返 回 值：还原的原始文本
  说    明：逐块解密后使用相同的分块格式去除长度前缀和填充。
***************************************************************************/
std::string rsa_decrypt_text(const std::vector<big_integer>& cipher_blocks, const rsa_key_pair& key_pair)
{
    std::vector<big_integer> blocks;
    blocks.reserve(cipher_blocks.size());
    for (std::size_t i = 0; i < cipher_blocks.size(); ++i) {
        const big_integer& cipher = cipher_blocks[i];
        blocks.push_back(rsa_decrypt_integer(cipher, key_pair));
    }
    return blocks_to_text(blocks, key_pair.public_key.n);
}

/***************************************************************************
  函数名称：rsa_sign_message
  功    能：使用 RSA 私钥对消息摘要签名
  输入参数：const std::string& message：待加密、签名或验证的消息；指针参数用于输出正文
  const rsa_key_pair& key_pair：包含公钥和私钥的密钥对
  返 回 值：RSA 签名整数
  说    明：计算 SHA-256 摘要模 n，再用私钥指数 a 做模幂运算。
***************************************************************************/
big_integer rsa_sign_message(const std::string& message, const rsa_key_pair& key_pair)
{
    const big_integer digest = hash_to_zz(message) % key_pair.public_key.n;
    return NTL::PowerMod(digest, key_pair.private_key.a, key_pair.public_key.n);
}

/***************************************************************************
  函数名称：rsa_verify_message
  功    能：验证消息的 RSA 签名
  输入参数：const std::string& message：待加密、签名或验证的消息；指针参数用于输出正文
  const big_integer& signature：签名值；指针参数用于输出解析结果
  const rsa_public_key& public_key：算法对应的公钥
  返 回 值：true 为通过，false 为签名无效
  说    明：先检查签名范围，再比较公钥模幂结果与消息摘要。
***************************************************************************/
bool rsa_verify_message(const std::string& message, const big_integer& signature, const rsa_public_key& public_key)
{
    if (signature < 0 || signature >= public_key.n) {
        return false;
    }
    const big_integer digest = hash_to_zz(message) % public_key.n;
    return NTL::PowerMod(signature, public_key.b, public_key.n) == digest;
}

/***************************************************************************
  函数名称：serialize_rsa_public_key
  功    能：生成 RSA 公钥的规范文本
  输入参数：const rsa_public_key& public_key：算法对应的公钥
  返 回 值：包含 n 和 b 的公钥字符串
  说    明：字段顺序固定，供证书签名载荷与信任锚比较使用。
***************************************************************************/
std::string serialize_rsa_public_key(const rsa_public_key& public_key)
{
    return "RSA|n=" + zz_to_string(public_key.n) + "|b=" + zz_to_string(public_key.b);
}
