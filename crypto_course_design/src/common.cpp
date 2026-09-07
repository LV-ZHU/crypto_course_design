#include "common.h"

#include <chrono>
#include <random>
#include <sstream>
#include <stdexcept>


/***************************************************************************
  函数名称：initialize_random
  功    能：初始化 NTL 使用的随机数种子
  输入参数：无
  返 回 值：无
  说    明：把随机设备输出与当前时钟值混合为 32 字节种子。
***************************************************************************/
void initialize_random()
{
    std::random_device rd;
    unsigned char seed[32]{};
    const unsigned long long now = static_cast<unsigned long long>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    for (std::size_t i = 0; i < sizeof(seed); ++i) {
        unsigned int r = rd();
        seed[i] = static_cast<unsigned char>((r >> ((i % 4) * 8)) & 0xffU);
    }
    for (std::size_t i = 0; i < sizeof(now); ++i) {
        seed[i] ^= static_cast<unsigned char>((now >> (i * 8)) & 0xffU);
    }
    NTL::SetSeed(seed, static_cast<long>(sizeof(seed)));
}

/***************************************************************************
  函数名称：zz_to_string
  功    能：把大整数转换为十进制字符串
  输入参数：const big_integer& value：待转换、计算或写入的数值；解析标记函数中为输入文本
  返 回 值：大整数的十进制文本
  说    明：通过输出字符串流完成转换，不截断整数精度。
***************************************************************************/
std::string zz_to_string(const big_integer& value)
{
    std::ostringstream out;
    out << value;
    return out.str();
}

/***************************************************************************
  函数名称：zz_from_string
  功    能：解析十进制大整数
  输入参数：const std::string& text：待处理的文本
  返 回 值：解析得到的大整数
  说    明：拒绝非数字输入及数字后的多余内容，格式错误时抛出异常。
***************************************************************************/
big_integer zz_from_string(const std::string& text)
{
    std::istringstream in(text);
    big_integer value;
    if (!(in >> value)) {
        throw std::runtime_error("invalid integer: " + text);
    }
    in >> std::ws;
    if (!in.eof()) {
        throw std::runtime_error("invalid integer: " + text);
    }
    return value;
}

/***************************************************************************
  函数名称：mod_positive
  功    能：求非负模余数
  输入参数：const big_integer& value：待转换、计算或写入的数值；解析标记函数中为输入文本
  const big_integer& modulus：用于模运算或分块编码的正模数
  返 回 值：位于 [0, modulus) 的余数
  说    明：调用时 modulus 必须为正；负余数加上模数后返回。
***************************************************************************/
big_integer mod_positive(const big_integer& value, const big_integer& modulus)
{
    big_integer result = value % modulus;
    if (result < 0) {
        result += modulus;
    }
    return result;
}

/***************************************************************************
  函数名称：random_between
  功    能：在闭区间内产生随机大整数
  输入参数：const big_integer& low：随机区间下界
  const big_integer& high_inclusive：随机区间上界，包含该值
  返 回 值：位于 [low, high_inclusive] 的随机数
  说    明：上界小于下界时抛出异常；两端点均可被取到。
***************************************************************************/
big_integer random_between(const big_integer& low, const big_integer& high_inclusive)
{
    if (high_inclusive < low) {
        throw std::invalid_argument("randomBetween: invalid range");
    }
    return low + NTL::RandomBnd(high_inclusive - low + 1);
}

/***************************************************************************
  函数名称：string_to_bytes
  功    能：将字符串按原始字节转换为数组
  输入参数：const std::string& text：待处理的文本
  返 回 值：字节数组
  说    明：不转换字符编码，也保留字符串中的零字节。
***************************************************************************/
std::vector<unsigned char> string_to_bytes(const std::string& text)
{
    return std::vector<unsigned char>(text.begin(), text.end());
}

/***************************************************************************
  函数名称：bytes_to_string
  功    能：把字节数组还原为字符串
  输入参数：const std::vector<unsigned char>& bytes：输入字节数组
  返 回 值：包含原始字节的字符串
  说    明：按照数组长度构造字符串，不以零字节作为结束标志。
***************************************************************************/
std::string bytes_to_string(const std::vector<unsigned char>& bytes)
{
    return std::string(bytes.begin(), bytes.end());
}

/***************************************************************************
  函数名称：fixed_block_size_for_modulus
  功    能：计算小于模数的固定编码块长度
  输入参数：const big_integer& modulus：用于模运算或分块编码的正模数
  返 回 值：每块的字节数
  说    明：按 (模数位数-1)/8 取整，保证编码整数小于模数；模数过小时抛出异常。
***************************************************************************/
std::size_t fixed_block_size_for_modulus(const big_integer& modulus)
{
    const long bits = NTL::NumBits(modulus);
    if (bits < 32) {
        throw std::invalid_argument("modulus is too small for reversible block encoding");
    }
    return static_cast<std::size_t>((bits - 1) / 8);
}

/***************************************************************************
  函数名称：payload_size_for_modulus
  功    能：计算每个编码块可容纳的数据长度
  输入参数：const big_integer& modulus：用于模运算或分块编码的正模数
  返 回 值：有效载荷字节数
  说    明：固定块的前两个字节保存长度，其余位置存放数据。
***************************************************************************/
std::size_t payload_size_for_modulus(const big_integer& modulus)
{
    const std::size_t block_size = fixed_block_size_for_modulus(modulus);
    if (block_size <= 2) {
        throw std::invalid_argument("modulus is too small for length-prefixed blocks");
    }
    return block_size - 2;
}

/***************************************************************************
  函数名称：fixed_bytes_to_zz
  功    能：按大端顺序把字节块转换为大整数
  输入参数：const std::vector<unsigned char>& block：固定长度字节块
  返 回 值：编码后的非负整数
  说    明：每读入一个字节，将已有数值乘 256 后累加。
***************************************************************************/
static big_integer fixed_bytes_to_zz(const std::vector<unsigned char>& block)
{
    big_integer value(0);
    const big_integer base = NTL::conv<big_integer>(256);
    for (std::size_t i = 0; i < block.size(); ++i) {
        const unsigned char byte = block[i];
        value *= base;
        value += static_cast<long>(byte);
    }
    return value;
}

/***************************************************************************
  函数名称：zz_to_fixed_bytes
  功    能：将大整数拆成固定长度的大端字节块
  输入参数：big_integer value：待转换、计算或写入的数值；解析标记函数中为输入文本
  std::size_t size：目标字节数
  返 回 值：固定长度的字节数组
  说    明：不足部分在高位补零；负数或超出指定长度时抛出异常。
***************************************************************************/
static std::vector<unsigned char> zz_to_fixed_bytes(big_integer value, std::size_t size)
{
    if (value < 0) {
        throw std::invalid_argument("negative block value");
    }
    std::vector<unsigned char> bytes(size, 0);
    const big_integer base = NTL::conv<big_integer>(256);
    for (std::size_t pos = size; pos > 0; --pos) {
        const big_integer byte_value = value % base;
        bytes[pos - 1] = static_cast<unsigned char>(NTL::conv<long>(byte_value));
        value /= base;
    }
    if (value != 0) {
        throw std::runtime_error("integer does not fit the fixed block size");
    }
    return bytes;
}

/***************************************************************************
  函数名称：bytes_to_blocks
  功    能：把任意长度字节数组编码为整数块
  输入参数：const std::vector<unsigned char>& bytes：输入字节数组
  const big_integer& modulus：用于模运算或分块编码的正模数
  返 回 值：可用于公钥加密的整数块数组
  说    明：每块使用两字节长度前缀和零填充；空输入仍生成一个空载荷块。
***************************************************************************/
std::vector<big_integer> bytes_to_blocks(const std::vector<unsigned char>& bytes, const big_integer& modulus)
{
    const std::size_t block_size = fixed_block_size_for_modulus(modulus);
    const std::size_t payload_size = payload_size_for_modulus(modulus);
    std::vector<big_integer> blocks;

    for (std::size_t offset = 0; offset < bytes.size() || (bytes.empty() && offset == 0); offset += payload_size) {
        const std::size_t remaining = offset < bytes.size() ? bytes.size() - offset : 0;
        const std::size_t count = remaining < payload_size ? remaining : payload_size;
        std::vector<unsigned char> block(block_size, 0);
        // 前两字节按大端顺序记录实际载荷长度，末块的补零不计入正文。
        block[0] = static_cast<unsigned char>((count >> 8) & 0xffU);
        block[1] = static_cast<unsigned char>(count & 0xffU);
        for (std::size_t i = 0; i < count; ++i) {
            block[i + 2] = bytes[offset + i];
        }
        big_integer value = fixed_bytes_to_zz(block);
        if (value >= modulus) {
            throw std::runtime_error("encoded block is not smaller than modulus");
        }
        blocks.push_back(value);
        if (bytes.empty()) {
            break;
        }
    }
    return blocks;
}

/***************************************************************************
  函数名称：blocks_to_bytes
  功    能：把整数块解码为原始字节数组
  输入参数：const std::vector<big_integer>& blocks：按顺序排列的整数块
  const big_integer& modulus：用于模运算或分块编码的正模数
  返 回 值：按块顺序拼接的字节数据
  说    明：检查整数范围及长度前缀，跳过每块的长度前缀和填充部分。
***************************************************************************/
std::vector<unsigned char> blocks_to_bytes(const std::vector<big_integer>& blocks, const big_integer& modulus)
{
    const std::size_t block_size = fixed_block_size_for_modulus(modulus);
    const std::size_t payload_size = payload_size_for_modulus(modulus);
    std::vector<unsigned char> bytes;

    for (std::size_t i = 0; i < blocks.size(); ++i) {
        const big_integer& value = blocks[i];
        if (value < 0 || value >= modulus) {
            throw std::runtime_error("decoded block is outside modulus range");
        }
        const std::vector<unsigned char> block = zz_to_fixed_bytes(value, block_size);
        const std::size_t count = (static_cast<std::size_t>(block[0]) << 8) | block[1];
        if (count > payload_size) {
            throw std::runtime_error("decoded block length is invalid");
        }
        bytes.insert(bytes.end(), block.begin() + 2, block.begin() + 2 + static_cast<long>(count));
    }
    return bytes;
}

/***************************************************************************
  函数名称：text_to_blocks
  功    能：把文本编码为整数块
  输入参数：const std::string& text：待处理的文本
  const big_integer& modulus：用于模运算或分块编码的正模数
  返 回 值：文本对应的整数块数组
  说    明：先转为字节，再调用统一的分块编码函数。
***************************************************************************/
std::vector<big_integer> text_to_blocks(const std::string& text, const big_integer& modulus)
{
    return bytes_to_blocks(string_to_bytes(text), modulus);
}

/***************************************************************************
  函数名称：blocks_to_text
  功    能：把整数块还原为文本
  输入参数：const std::vector<big_integer>& blocks：按顺序排列的整数块
  const big_integer& modulus：用于模运算或分块编码的正模数
  返 回 值：恢复的原始字符串
  说    明：先解码字节块，再按实际长度构造字符串。
***************************************************************************/
std::string blocks_to_text(const std::vector<big_integer>& blocks, const big_integer& modulus)
{
    return bytes_to_string(blocks_to_bytes(blocks, modulus));
}

/***************************************************************************
  函数名称：shorten
  功    能：截短用于显示的文本
  输入参数：const std::string& text：待处理的文本
  std::size_t max_chars：最多保留的字节数
  返 回 值：截短后或原样返回的字符串
  说    明：按字节数截短；长度允许时用三个点表示省略，不用于保存原始数据。
***************************************************************************/
std::string shorten(const std::string& text, std::size_t max_chars)
{
    if (text.size() <= max_chars) {
        return text;
    }
    if (max_chars <= 3) {
        return text.substr(0, max_chars);
    }
    return text.substr(0, max_chars - 3) + "...";
}
