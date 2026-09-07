#pragma once

#include <NTL/ZZ.h>

#include <cstddef>
#include <string>
#include <vector>


// NTL 大整数的项目内名称，保留第三方库接口本身的命名。
typedef NTL::ZZ big_integer;

void initialize_random();

std::string zz_to_string(const big_integer& value);
big_integer zz_from_string(const std::string& text);
big_integer mod_positive(const big_integer& value, const big_integer& modulus);
big_integer random_between(const big_integer& low, const big_integer& high_inclusive);

std::vector<unsigned char> string_to_bytes(const std::string& text);
std::string bytes_to_string(const std::vector<unsigned char>& bytes);

std::size_t fixed_block_size_for_modulus(const big_integer& modulus);
std::size_t payload_size_for_modulus(const big_integer& modulus);

std::vector<big_integer> bytes_to_blocks(const std::vector<unsigned char>& bytes, const big_integer& modulus);
std::vector<unsigned char> blocks_to_bytes(const std::vector<big_integer>& blocks, const big_integer& modulus);

std::vector<big_integer> text_to_blocks(const std::string& text, const big_integer& modulus);
std::string blocks_to_text(const std::vector<big_integer>& blocks, const big_integer& modulus);

std::string shorten(const std::string& text, std::size_t max_chars);
