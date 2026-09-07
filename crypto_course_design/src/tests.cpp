#include "tests.h"

#include "certificate.h"
#include "elgamal.h"
#include "hash.h"
#include "pki.h"
#include "rsa.h"
#include "secure_mail.h"
#include "ta.h"

#include <stdexcept>
#include <string>


/***************************************************************************
  函数名称：require
  功    能：检查测试断言
  输入参数：bool condition：需要成立的测试条件
  const std::string& message：待加密、签名或验证的消息；指针参数用于输出正文
  返 回 值：无
  说    明：条件为 false 时抛出带说明的异常，由外层测试函数记录失败。
***************************************************************************/
static void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}


/***************************************************************************
  函数名称：clear_text_files
  功    能：清理测试输出目录内的 TXT 文件
  输入参数：const std::filesystem::path& directory：用于证书导出的目录
  返 回 值：无
  说    明：目录不存在时创建，只删除该目录中的普通 TXT 文件。
***************************************************************************/
static void clear_text_files(const std::filesystem::path& directory)
{
    std::filesystem::create_directories(directory);
    for (std::filesystem::directory_iterator it(directory); it != std::filesystem::directory_iterator(); ++it) {
        const std::filesystem::directory_entry& entry = *it;
        if (entry.is_regular_file() && entry.path().extension() == ".txt") {
            std::filesystem::remove(entry.path());
        }
    }
}


/***************************************************************************
  函数名称：run_rsa_tests
  功    能：运行 RSA 与 SHA-256 独立测试
  输入参数：long rsa_prime_bits：RSA 每个素数 p、q 的位数
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：true 为全部断言通过，false 为存在失败
  说    明：覆盖摘要向量、素数位数、加解密、空文本和消息篡改。
***************************************************************************/
bool run_rsa_tests(long rsa_prime_bits, std::ostream& log)
{
    const std::string test_name = "RSA 加密、解密、签名与验证（p/q=" + std::to_string(rsa_prime_bits) + " bit）";
    try {
        log << "[TEST] " << test_name << "\n";
        require(
            sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "SHA-256 empty-message test vector failed");
        require(
            sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256 abc test vector failed");

        const rsa_key_pair key_pair = generate_rsa_key_pair(rsa_prime_bits);
        require(NTL::NumBits(key_pair.private_key.p) == rsa_prime_bits, "RSA p bit length mismatch");
        require(NTL::NumBits(key_pair.private_key.q) == rsa_prime_bits, "RSA q bit length mismatch");
        require(key_pair.private_key.p != key_pair.private_key.q, "RSA p and q must differ");
        require(NTL::ProbPrime(key_pair.private_key.p, 40) != 0, "RSA p failed primality check");
        require(NTL::ProbPrime(key_pair.private_key.q, 40) != 0, "RSA q failed primality check");

        const std::string message =
            "RSA test message: 同济大学现代密码学课程设计。"
            "This text is intentionally long enough to exercise reversible block encoding.";
        const std::vector<big_integer> cipher = rsa_encrypt_text(message, key_pair.public_key);
        require(rsa_decrypt_text(cipher, key_pair) == message, "RSA decrypt result differs from plaintext");
        require(rsa_decrypt_text(rsa_encrypt_text("", key_pair.public_key), key_pair).empty(), "RSA empty text failed");

        const big_integer signature = rsa_sign_message(message, key_pair);
        require(rsa_verify_message(message, signature, key_pair.public_key), "RSA signature verify failed");
        require(!rsa_verify_message(message + "!", signature, key_pair.public_key), "RSA tamper test failed");
        log << "[PASS] " << test_name << "\n";
        return true;
    } catch (const std::exception& ex) {
        log << "[FAIL] " << test_name << ": " << ex.what() << "\n";
        return false;
    }
}

/***************************************************************************
  函数名称：run_elgamal_tests_and_return_key
  功    能：运行 ElGamal 测试并可选返回密钥
  输入参数：long elgamal_prime_bits：ElGamal 模数 p 的位数
  elgamal_key_pair* generated_key_pair：接收测试密钥的指针，可为 nullptr
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：true 为测试通过，false 为失败
  说    明：检查素数和原根性质、加解密及签名；通过后可复用生成的密钥。
***************************************************************************/
static bool run_elgamal_tests_and_return_key(
    long elgamal_prime_bits,
    elgamal_key_pair* generated_key_pair,
    std::ostream& log)
{
    const std::string test_name = "ElGamal 加密、解密、签名与验证（p=" + std::to_string(elgamal_prime_bits) + " bit）";
    try {
        log << "[TEST] " << test_name << "\n";
        const elgamal_key_pair key_pair = generate_elgamal_key_pair(elgamal_prime_bits);
        require(NTL::NumBits(key_pair.public_key.p) == elgamal_prime_bits, "ElGamal p bit length mismatch");
        require(NTL::ProbPrime(key_pair.q, 40) != 0, "ElGamal q failed primality check");
        require(NTL::ProbPrime(key_pair.public_key.p, 40) != 0, "ElGamal p failed primality check");
        require(
            NTL::PowerMod(key_pair.public_key.g, 2, key_pair.public_key.p) != 1,
            "ElGamal generator has order 2");
        require(
            NTL::PowerMod(key_pair.public_key.g, key_pair.q, key_pair.public_key.p) != 1,
            "ElGamal generator is not primitive");

        const std::string message = "ElGamal test: 加密、解密和数字签名。";
        const std::vector<elgamal_cipher_block> cipher = elgamal_encrypt_text(message, key_pair.public_key);
        require(elgamal_decrypt_text(cipher, key_pair) == message, "ElGamal decrypt result differs from plaintext");

        const elgamal_signature signature = elgamal_sign_message(message, key_pair);
        require(elgamal_verify_message(message, signature, key_pair.public_key), "ElGamal signature verify failed");
        require(
            !elgamal_verify_message(message + "!", signature, key_pair.public_key),
            "ElGamal signature tamper test failed");
        if (generated_key_pair != nullptr) {
            *generated_key_pair = key_pair;
        }
        log << "[PASS] " << test_name << "\n";
        return true;
    } catch (const std::exception& ex) {
        log << "[FAIL] " << test_name << ": " << ex.what() << "\n";
        return false;
    }
}

/***************************************************************************
  函数名称：run_elgamal_tests
  功    能：运行独立 ElGamal 测试
  输入参数：long elgamal_prime_bits：ElGamal 模数 p 的位数
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：true 为测试通过，false 为失败
  说    明：不向调用者输出测试生成的密钥。
***************************************************************************/
bool run_elgamal_tests(long elgamal_prime_bits, std::ostream& log)
{
    return run_elgamal_tests_and_return_key(elgamal_prime_bits, nullptr, log);
}

/***************************************************************************
  函数名称：run_certificate_tests_with_elgamal_key
  功    能：测试 TXT 证书的签发、存取和异常拒绝
  输入参数：long rsa_prime_bits：RSA 每个素数 p、q 的位数
  long elgamal_prime_bits：ElGamal 模数 p 的位数
  const elgamal_key_pair* reusable_elgamal_key_pair：可复用的 ElGamal 密钥指针，为 nullptr 时重新生成
  const std::filesystem::path& output_directory：生成证书等测试数据的输出目录
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：true 为测试通过，false 为失败
  说    明：可复用 ElGamal 密钥；覆盖双用途、CRLF、篡改、重复字段与非法整数。
***************************************************************************/
static bool run_certificate_tests_with_elgamal_key(
    long rsa_prime_bits,
    long elgamal_prime_bits,
    const elgamal_key_pair* reusable_elgamal_key_pair,
    const std::filesystem::path& output_directory,
    std::ostream& log)
{
    const std::string test_name = "TXT 简单证书（Flag1/Flag2、RSA/ElGamal 签发与验证）";
    try {
        log << "[TEST] " << test_name << "\n";
        const trusted_authority rsa_ta = trusted_authority::create_rsa("TA_RSA", rsa_prime_bits);
        const rsa_key_pair alice_encryption_key = generate_rsa_key_pair(rsa_prime_bits);
        const rsa_key_pair alice_signature_key = generate_rsa_key_pair(rsa_prime_bits);
        const certificate_data encryption_certificate = rsa_ta.issue_certificate(
            "Alice",
            public_key_data::from_rsa(alice_encryption_key.public_key),
            key_usage_type::ENCRYPTION);
        const certificate_data signature_certificate = rsa_ta.issue_certificate(
            "Alice",
            public_key_data::from_rsa(alice_signature_key.public_key),
            key_usage_type::SIGNATURE);

        require(encryption_certificate.flag1 == signature_algorithm_type::RSA, "RSA certificate Flag1 mismatch");
        require(encryption_certificate.flag2 == key_usage_type::ENCRYPTION, "encryption certificate Flag2 mismatch");
        require(signature_certificate.flag2 == key_usage_type::SIGNATURE, "signature certificate Flag2 mismatch");
        require(verify_certificate(encryption_certificate, rsa_ta.get_public_key()), "RSA certificate verify failed");
        require(verify_certificate(signature_certificate, rsa_ta.get_public_key()), "RSA signature certificate failed");
        require(encryption_certificate.to_text().find("Flag1=0") != std::string::npos, "Flag1 missing from TXT");
        require(encryption_certificate.to_text().find("Flag2=0") != std::string::npos, "Flag2 missing from TXT");

        const trusted_authority elgamal_ta = reusable_elgamal_key_pair == nullptr
            ? trusted_authority::create_elgamal("TA_ELGAMAL", elgamal_prime_bits)
            : trusted_authority::from_elgamal_key_pair("TA_ELGAMAL", *reusable_elgamal_key_pair);
        const rsa_key_pair eve_signature_key = generate_rsa_key_pair(rsa_prime_bits);
        const certificate_data elgamal_signed_certificate = elgamal_ta.issue_certificate(
            "Eve",
            public_key_data::from_rsa(eve_signature_key.public_key),
            key_usage_type::SIGNATURE);
        require(
            elgamal_signed_certificate.flag1 == signature_algorithm_type::ELGAMAL,
            "ElGamal certificate Flag1 mismatch");
        require(
            verify_certificate(elgamal_signed_certificate, elgamal_ta.get_public_key()),
            "ElGamal-signed certificate verify failed");

        const std::filesystem::path cert_directory = output_directory / "cert_examples";
        clear_text_files(cert_directory);
        encryption_certificate.save_to_file(cert_directory / "Alice_encryption_RSA_signed.txt");
        signature_certificate.save_to_file(cert_directory / "Alice_signature_RSA_signed.txt");
        elgamal_signed_certificate.save_to_file(cert_directory / "Eve_signature_ElGamal_signed.txt");
        const certificate_data loaded = certificate_data::load_from_file(
            cert_directory / "Alice_encryption_RSA_signed.txt");
        require(loaded.flag2 == key_usage_type::ENCRYPTION, "loaded certificate Flag2 mismatch");
        require(verify_certificate(loaded, rsa_ta.get_public_key()), "loaded certificate verify failed");

        std::string crlf_text;
        const std::string certificate_text = encryption_certificate.to_text();
        for (std::size_t i = 0; i < certificate_text.size(); ++i) {
            const char ch = certificate_text[i];
            if (ch == '\n') {
                crlf_text += "\r\n";
            } else {
                crlf_text += ch;
            }
        }
        const certificate_data crlf_certificate = certificate_data::from_text(crlf_text);
        require(
            verify_certificate(crlf_certificate, rsa_ta.get_public_key()),
            "certificate with Windows CRLF line endings failed verification");

        certificate_data tampered = loaded;
        tampered.subject_id = "Mallory";
        require(!verify_certificate(tampered, rsa_ta.get_public_key()), "tampered certificate was accepted");
        tampered = loaded;
        tampered.signature.algorithm = signature_algorithm_type::ELGAMAL;
        require(!verify_certificate(tampered, rsa_ta.get_public_key()), "signature algorithm mismatch was accepted");

        bool malformed_rejected = false;
        try {
            (void)certificate_data::from_text("SubjectID=Alice\nCERTIFICATE_END\n");
        } catch (const std::exception&) {
            malformed_rejected = true;
        }
        require(malformed_rejected, "certificate without begin marker was accepted");

        bool duplicate_rejected = false;
        try {
            std::string duplicate_text = encryption_certificate.to_text();
            duplicate_text.insert(
                duplicate_text.find("CERTIFICATE_END"),
                "SubjectID=Mallory\n");
            (void)certificate_data::from_text(duplicate_text);
        } catch (const std::exception&) {
            duplicate_rejected = true;
        }
        require(duplicate_rejected, "certificate with duplicate fields was accepted");

        bool malformed_integer_rejected = false;
        try {
            std::string malformed_integer_text = encryption_certificate.to_text();
            const std::size_t signature_start = malformed_integer_text.find("SignatureRSA=");
            const std::size_t signature_end = malformed_integer_text.find('\n', signature_start);
            malformed_integer_text.insert(signature_end, "not-a-number");
            (void)certificate_data::from_text(malformed_integer_text);
        } catch (const std::exception&) {
            malformed_integer_rejected = true;
        }
        require(malformed_integer_rejected, "certificate with a malformed signature integer was accepted");
        log << "[PASS] " << test_name << "\n";
        return true;
    } catch (const std::exception& ex) {
        log << "[FAIL] " << test_name << ": " << ex.what() << "\n";
        return false;
    }
}

/***************************************************************************
  函数名称：run_certificate_tests
  功    能：独立运行证书模块测试
  输入参数：long rsa_prime_bits：RSA 每个素数 p、q 的位数
  long elgamal_prime_bits：ElGamal 模数 p 的位数
  const std::filesystem::path& output_directory：生成证书等测试数据的输出目录
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：true 为测试通过，false 为失败
  说    明：未提供复用密钥，由内部测试生成 ElGamal 参数。
***************************************************************************/
bool run_certificate_tests(
    long rsa_prime_bits,
    long elgamal_prime_bits,
    const std::filesystem::path& output_directory,
    std::ostream& log)
{
    return run_certificate_tests_with_elgamal_key(
        rsa_prime_bits,
        elgamal_prime_bits,
        nullptr,
        output_directory,
        log);
}

/***************************************************************************
  函数名称：run_pki_tests
  功    能：运行严格层次 PKI 测试
  输入参数：long rsa_prime_bits：RSA 每个素数 p、q 的位数
  const std::filesystem::path& output_directory：生成证书等测试数据的输出目录
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：true 为测试通过，false 为失败
  说    明：检查三层路径、消息签名、篡改拒绝和九张证书记录。
***************************************************************************/
bool run_pki_tests(
    long rsa_prime_bits,
    const std::filesystem::path& output_directory,
    std::ostream& log)
{
    const std::string test_name = "严格层次 PKI、公开证书库与证书链验证";
    try {
        log << "[TEST] " << test_name << "\n";
        const pki_demo_result result = run_strict_hierarchy_pki_demo(rsa_prime_bits, output_directory / "pki", log);
        require(result.path_verified, "PKI path verification failed");
        require(result.signature_verified, "PKI message signature verification failed");
        require(result.tampered_path_rejected, "tampered certificate path was accepted");
        require(result.certificate_path_ids.size() == 3, "PKI path should contain root, CA and user");
        require(result.repository_size == 9, "repository should contain 3 CA and 6 user certificates");
        log << "[PASS] " << test_name << "\n";
        return true;
    } catch (const std::exception& ex) {
        log << "[FAIL] " << test_name << ": " << ex.what() << "\n";
        return false;
    }
}

/***************************************************************************
  函数名称：run_secure_mail_tests
  功    能：运行安全邮件收发和攻击拒绝测试
  输入参数：long rsa_prime_bits：RSA 每个素数 p、q 的位数
  const std::filesystem::path& output_directory：生成证书等测试数据的输出目录
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：true 为测试通过，false 为失败
  说    明：检查收发双方证书链、消息验签、错误接收者和伪造发送者。
***************************************************************************/
bool run_secure_mail_tests(
    long rsa_prime_bits,
    const std::filesystem::path& output_directory,
    std::ostream& log)
{
    const std::string test_name = "简易安全邮件发送、接收与攻击拒绝";
    try {
        log << "[TEST] " << test_name << "\n";
        const secure_mail_demo_result result = run_secure_mail_demo(
            rsa_prime_bits,
            output_directory / "secure_mail",
            log);
        require(result.recipient_path_verified, "recipient encryption certificate path failed");
        require(result.sender_path_verified, "sender signature certificate path failed");
        require(result.signature_verified, "secure mail signature verification failed");
        require(result.wrong_recipient_rejected, "wrong recipient was not rejected");
        require(result.forged_sender_rejected, "forged sender was not rejected");
        require(!result.recovered_message.empty(), "secure mail plaintext is empty");
        require(result.cipher_block_count > 0, "secure mail ciphertext is empty");
        log << "[PASS] " << test_name << "\n";
        return true;
    } catch (const std::exception& ex) {
        log << "[FAIL] " << test_name << ": " << ex.what() << "\n";
        return false;
    }
}

/***************************************************************************
  函数名称：run_all_tests
  功    能：按模块执行全部独立测试
  输入参数：const test_options& options：测试参数或邮件证书查询策略
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：true 为所有测试通过，false 为存在失败或跳过
  说    明：ElGamal 成功后复用其密钥进行证书测试；后续模块仍继续执行。
***************************************************************************/
bool run_all_tests(const test_options& options, std::ostream& log)
{
    std::filesystem::create_directories(options.output_directory);
    log << "========== 课程设计独立测试开始 ==========\n";
    bool all_passed = true;
    all_passed = run_rsa_tests(options.rsa_prime_bits, log) && all_passed;
    elgamal_key_pair elgamal_key_pair;
    const bool elgamal_passed = run_elgamal_tests_and_return_key(
        options.elgamal_prime_bits,
        &elgamal_key_pair,
        log);
    all_passed = elgamal_passed && all_passed;
    if (elgamal_passed) {
        all_passed = run_certificate_tests_with_elgamal_key(
            options.rsa_prime_bits,
            options.elgamal_prime_bits,
            &elgamal_key_pair,
            options.output_directory,
            log) && all_passed;
    } else {
        log << "[SKIP] 证书测试需要有效的 ElGamal 密钥，因前置测试失败而跳过\n";
        all_passed = false;
    }
    all_passed = run_pki_tests(options.rsa_prime_bits, options.output_directory, log) && all_passed;
    all_passed = run_secure_mail_tests(options.rsa_prime_bits, options.output_directory, log) && all_passed;
    log << (all_passed ? "========== 全部测试通过 ==========\n" : "========== 存在测试失败 ==========\n");
    return all_passed;
}
