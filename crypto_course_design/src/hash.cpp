#include "hash.h"

#include "common.h"

#include <iomanip>
#include <sstream>


const std::uint32_t k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U};

/***************************************************************************
  函数名称：rotr
  功    能：对 32 位无符号整数循环右移
  输入参数：std::uint32_t x：待移位的 32 位无符号整数
  std::uint32_t n：循环右移的位数
  返 回 值：循环移位后的数值
  说    明：本模块传入的移位量均在 1 到 31 之间。
***************************************************************************/
static std::uint32_t rotr(std::uint32_t x, std::uint32_t n)
{
    return (x >> n) | (x << (32U - n));
}

/***************************************************************************
  函数名称：read_big_endian32
  功    能：从字节数组读取一个大端 32 位整数
  输入参数：const std::vector<unsigned char>& data：输入字节数组
  std::size_t offset：读写起始字节下标
  返 回 值：合并后的 32 位整数
  说    明：调用方保证 offset 开始至少还有四个字节。
***************************************************************************/
static std::uint32_t read_big_endian32(const std::vector<unsigned char>& data, std::size_t offset)
{
    return (static_cast<std::uint32_t>(data[offset]) << 24U) |
           (static_cast<std::uint32_t>(data[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(data[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(data[offset + 3]);
}

/***************************************************************************
  函数名称：write_big_endian32
  功    能：将 32 位整数按大端顺序写入摘要数组
  输入参数：std::array<unsigned char, 32>& out：用于写入结果的摘要数组
  std::size_t offset：读写起始字节下标
  std::uint32_t value：待转换、计算或写入的数值；解析标记函数中为输入文本
  返 回 值：无
  说    明：调用方保证 offset 开始的四个位置均在数组范围内。
***************************************************************************/
static void write_big_endian32(std::array<unsigned char, 32>& out, std::size_t offset, std::uint32_t value)
{
    out[offset] = static_cast<unsigned char>((value >> 24U) & 0xffU);
    out[offset + 1] = static_cast<unsigned char>((value >> 16U) & 0xffU);
    out[offset + 2] = static_cast<unsigned char>((value >> 8U) & 0xffU);
    out[offset + 3] = static_cast<unsigned char>(value & 0xffU);
}


/***************************************************************************
  函数名称：sha256
  功    能：计算输入数据的 SHA-256 摘要
  输入参数：const std::vector<unsigned char>& bytes：输入字节数组
  返 回 值：长度固定为 32 字节的摘要
  说    明：字符串重载先转为字节；字节重载完成填充、消息扩展和 64 轮压缩。
***************************************************************************/
std::array<unsigned char, 32> sha256(const std::vector<unsigned char>& bytes)
{
    std::vector<unsigned char> data = bytes;
    const std::uint64_t bit_length = static_cast<std::uint64_t>(data.size()) * 8ULL;
    // 追加一个 1 位，再补零，使长度字段前的数据占 56 mod 64 字节。
    data.push_back(0x80U);
    while ((data.size() % 64U) != 56U) {
        data.push_back(0);
    }
    for (int shift = 56; shift >= 0; shift -= 8) {
        data.push_back(static_cast<unsigned char>((bit_length >> shift) & 0xffULL));
    }

    std::uint32_t h[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};

    for (std::size_t offset = 0; offset < data.size(); offset += 64) {
        std::uint32_t w[64]{};
        for (int i = 0; i < 16; ++i) {
            w[i] = read_big_endian32(data, offset + static_cast<std::size_t>(i) * 4U);
        }
        // 将当前 512 位分组扩展为 64 个用于压缩运算的字。
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3U);
            const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10U);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = h[0];
        std::uint32_t b = h[1];
        std::uint32_t c = h[2];
        std::uint32_t d = h[3];
        std::uint32_t e = h[4];
        std::uint32_t f = h[5];
        std::uint32_t g = h[6];
        std::uint32_t hh = h[7];

        // 每轮更新八个工作寄存器，最后累加回摘要状态。
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t ch = (e & f) ^ ((~e) & g);
            const std::uint32_t temp1 = hh + s1 + ch + k[i] + w[i];
            const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = s0 + maj;

            hh = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    std::array<unsigned char, 32> digest{};
    for (std::size_t i = 0; i < 8; ++i) {
        write_big_endian32(digest, i * 4U, h[i]);
    }
    return digest;
}

/***************************************************************************
  函数名称：sha256
  功    能：计算输入数据的 SHA-256 摘要
  输入参数：const std::string& text：待处理的文本
  返 回 值：长度固定为 32 字节的摘要
  说    明：字符串重载先转为字节；字节重载完成填充、消息扩展和 64 轮压缩。
***************************************************************************/
std::array<unsigned char, 32> sha256(const std::string& text)
{
    return sha256(string_to_bytes(text));
}

/***************************************************************************
  函数名称：sha256_hex
  功    能：生成消息摘要的十六进制表示
  输入参数：const std::string& text：待处理的文本
  返 回 值：64 个小写十六进制字符
  说    明：每个摘要字节固定输出两位，不足时补零。
***************************************************************************/
std::string sha256_hex(const std::string& text)
{
    const std::array<unsigned char, 32> digest = sha256(text);
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < digest.size(); ++i) {
        const unsigned char byte = digest[i];
        out << std::setw(2) << static_cast<int>(byte);
    }
    return out.str();
}

/***************************************************************************
  函数名称：hash_to_zz
  功    能：把 SHA-256 摘要转换为大整数
  输入参数：const std::string& text：待处理的文本
  返 回 值：摘要对应的非负整数
  说    明：按大端顺序累积 32 个字节，供 RSA 和 ElGamal 签名使用。
***************************************************************************/
big_integer hash_to_zz(const std::string& text)
{
    const std::array<unsigned char, 32> digest = sha256(text);
    big_integer value(0);
    const big_integer base = NTL::conv<big_integer>(256);
    for (std::size_t i = 0; i < digest.size(); ++i) {
        const unsigned char byte = digest[i];
        value *= base;
        value += static_cast<long>(byte);
    }
    return value;
}
