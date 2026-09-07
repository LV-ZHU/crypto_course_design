#pragma once

#include "common.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>


std::array<unsigned char, 32> sha256(const std::vector<unsigned char>& bytes);
std::array<unsigned char, 32> sha256(const std::string& text);
std::string sha256_hex(const std::string& text);
big_integer hash_to_zz(const std::string& text);
