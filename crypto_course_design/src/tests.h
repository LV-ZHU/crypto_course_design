#pragma once

#include <filesystem>
#include <ostream>


// 各测试模块使用的位数参数和输出位置。
struct test_options {
    long rsa_prime_bits = 256; // RSA 每个素数 p、q 的位数
    long elgamal_prime_bits = 256; // ElGamal 模数 p 的位数
    std::filesystem::path output_directory = "generated/test"; // 测试生成数据的输出目录
};

bool run_rsa_tests(long rsa_prime_bits, std::ostream& log);
bool run_elgamal_tests(long elgamal_prime_bits, std::ostream& log);
bool run_certificate_tests(
    long rsa_prime_bits,
    long elgamal_prime_bits,
    const std::filesystem::path& output_directory,
    std::ostream& log);
bool run_pki_tests(
    long rsa_prime_bits,
    const std::filesystem::path& output_directory,
    std::ostream& log);
bool run_secure_mail_tests(
    long rsa_prime_bits,
    const std::filesystem::path& output_directory,
    std::ostream& log);
bool run_all_tests(const test_options& options, std::ostream& log);
