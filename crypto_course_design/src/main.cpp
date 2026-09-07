#include "common.h"
#include "elgamal.h"
#include "pki.h"
#include "rsa.h"
#include "secure_mail.h"
#include "tests.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif


const long quick_bits = 256;
const long demo_rsa_bits = 512;
const long required_rsa_prime_bits = 1024;
const long required_elgamal_prime_bits = 2048;

/***************************************************************************
  函数名称：configure_console
  功    能：设置 Windows 控制台的 UTF-8 输入输出
  输入参数：无
  返 回 值：无
  说    明：仅 Windows 平台调用系统编码设置接口。
***************************************************************************/
static void configure_console()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}

/***************************************************************************
  函数名称：print_help
  功    能：显示命令行参数说明
  输入参数：无
  返 回 值：无
  说    明：列出快速测试、任务书参数测试及协议演示入口。
***************************************************************************/
static void print_help()
{
    std::cout
        << "现代密码学课程设计（2026 新版任务书）\n"
        << "\n快速独立测试：\n"
        << "  crypto_course_design.exe --test\n"
        << "  crypto_course_design.exe --test-rsa\n"
        << "  crypto_course_design.exe --test-elgamal\n"
        << "  crypto_course_design.exe --test-certificate\n"
        << "  crypto_course_design.exe --test-pki\n"
        << "  crypto_course_design.exe --test-mail\n"
        << "\n任务书参数测试：\n"
        << "  crypto_course_design.exe --full-test              RSA p/q=1024 bit，ElGamal p=2048 bit\n"
        << "  crypto_course_design.exe --full-test-rsa\n"
        << "  crypto_course_design.exe --full-test-elgamal\n"
        << "  crypto_course_design.exe --full-test-certificate\n"
        << "  crypto_course_design.exe --full-test-pki\n"
        << "  crypto_course_design.exe --full-test-mail\n"
        << "\n协议演示：\n"
        << "  crypto_course_design.exe --demo                   快速 PKI 演示\n"
        << "  crypto_course_design.exe --full-demo              1024-bit RSA PKI 演示\n"
        << "  crypto_course_design.exe --mail-demo              快速安全邮件演示\n"
        << "  crypto_course_design.exe --full-mail-demo         1024-bit RSA 安全邮件演示\n"
        << "  crypto_course_design.exe --mail-file <UTF-8文件>  读取文件并完成安全邮件收发\n"
        << "\n无参数运行进入交互菜单。--help 显示本帮助。\n";
}

/***************************************************************************
  函数名称：read_utf8_file
  功    能：读取供安全邮件使用的 UTF-8 文本
  输入参数：const std::filesystem::path& path：文件路径；证书路径验证函数中为按根到主体排列的证书数组
  返 回 值：去除可选 BOM 后的文件内容
  说    明：二进制读取；打开失败或正文为空时抛出异常，不执行字符编码转换。
***************************************************************************/
static std::string read_utf8_file(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("无法读取输入文件: " + path.string());
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    std::string text = buffer.str();
    if (text.size() >= 3 &&
        static_cast<unsigned char>(text[0]) == 0xefU &&
        static_cast<unsigned char>(text[1]) == 0xbbU &&
        static_cast<unsigned char>(text[2]) == 0xbfU) {
        text.erase(0, 3);
    }
    if (text.empty()) {
        throw std::runtime_error("输入文件不能为空");
    }
    return text;
}

/***************************************************************************
  函数名称：run_all
  功    能：选择参数并运行全部测试
  输入参数：bool full：是否使用任务书规定的完整位数参数
  返 回 值：0 为通过，1 为失败
  说    明：full 为 true 时使用任务书参数，否则使用快速测试参数。
***************************************************************************/
static int run_all(bool full)
{
    test_options options;
    options.rsa_prime_bits = full ? required_rsa_prime_bits : quick_bits;
    options.elgamal_prime_bits = full ? required_elgamal_prime_bits : quick_bits;
    options.output_directory = full ? "generated/full_test" : "generated/test";
    return run_all_tests(options, std::cout) ? 0 : 1;
}

/***************************************************************************
  函数名称：run_component
  功    能：运行指定模块的独立测试
  输入参数：const std::string& component：测试模块名称
  bool full：是否使用任务书规定的完整位数参数
  返 回 值：0 为通过，1 为失败
  说    明：根据 component 选择 RSA、ElGamal、证书、PKI 或邮件，未知名称抛出异常。
***************************************************************************/
static int run_component(const std::string& component, bool full)
{
    const long rsa_bits = full ? required_rsa_prime_bits : quick_bits;
    const long elgamal_bits = full ? required_elgamal_prime_bits : quick_bits;
    const std::filesystem::path output = full ? "generated/full_test" : "generated/components";

    bool passed = false;
    if (component == "rsa") {
        passed = run_rsa_tests(rsa_bits, std::cout);
    } else if (component == "elgamal") {
        passed = run_elgamal_tests(elgamal_bits, std::cout);
    } else if (component == "certificate") {
        passed = run_certificate_tests(rsa_bits, elgamal_bits, output, std::cout);
    } else if (component == "pki") {
        passed = run_pki_tests(rsa_bits, output, std::cout);
    } else if (component == "mail") {
        passed = run_secure_mail_tests(rsa_bits, output, std::cout);
    } else {
        throw std::invalid_argument("unknown test component: " + component);
    }
    return passed ? 0 : 1;
}

/***************************************************************************
  函数名称：run_rsa_interactive
  功    能：交互演示 RSA 文本加解密与签名
  输入参数：无
  返 回 值：无
  说    明：读取一行正文，使用任务书要求的 p、q 位数生成密钥并显示验证结果。
***************************************************************************/
static void run_rsa_interactive()
{
    std::cout << "请输入要用 RSA 加密和签名的消息：\n> ";
    std::string message;
    std::getline(std::cin, message);
    std::cout << "[RSA] 正在生成 p、q 均为 1024 bit 的密钥...\n";
    const rsa_key_pair key_pair = generate_rsa_key_pair(required_rsa_prime_bits);
    const std::vector<big_integer> cipher = rsa_encrypt_text(message, key_pair.public_key);
    const std::string recovered = rsa_decrypt_text(cipher, key_pair);
    const big_integer signature = rsa_sign_message(message, key_pair);

    std::cout << "[RSA] p bit = " << NTL::NumBits(key_pair.private_key.p)
              << ", q bit = " << NTL::NumBits(key_pair.private_key.q) << "\n";
    std::cout << "[RSA] 密文块数 = " << cipher.size() << "\n";
    std::cout << "[RSA] 解密结果 = " << recovered << "\n";
    std::cout << "[RSA] 签名验证 = "
              << (rsa_verify_message(message, signature, key_pair.public_key) ? "通过" : "失败") << "\n";
}

/***************************************************************************
  函数名称：run_elgamal_interactive
  功    能：交互演示 ElGamal 加解密与签名
  输入参数：无
  返 回 值：无
  说    明：读取一行正文，使用 2048 位安全素数参数，生成参数可能较耗时。
***************************************************************************/
static void run_elgamal_interactive()
{
    std::cout << "请输入要用 ElGamal 加密和签名的消息：\n> ";
    std::string message;
    std::getline(std::cin, message);
    std::cout << "[ElGamal] 正在生成 2048-bit 安全素数参数，耗时会明显长于快速测试...\n";
    const elgamal_key_pair key_pair = generate_elgamal_key_pair(required_elgamal_prime_bits);
    const std::vector<elgamal_cipher_block> cipher = elgamal_encrypt_text(message, key_pair.public_key);
    const std::string recovered = elgamal_decrypt_text(cipher, key_pair);
    const elgamal_signature signature = elgamal_sign_message(message, key_pair);

    std::cout << "[ElGamal] p bit = " << NTL::NumBits(key_pair.public_key.p) << "\n";
    std::cout << "[ElGamal] 密文块数 = " << cipher.size() << "\n";
    std::cout << "[ElGamal] 解密结果 = " << recovered << "\n";
    std::cout << "[ElGamal] 签名验证 = "
              << (elgamal_verify_message(message, signature, key_pair.public_key) ? "通过" : "失败") << "\n";
}

/***************************************************************************
  函数名称：run_mail_from_file
  功    能：读取文件并完成安全邮件演示
  输入参数：const std::filesystem::path& path：文件路径；证书路径验证函数中为按根到主体排列的证书数组
  返 回 值：无
  说    明：使用任务书 RSA 参数，检查验签结果以及恢复正文与输入一致。
***************************************************************************/
static void run_mail_from_file(const std::filesystem::path& path)
{
    const std::string message = read_utf8_file(path);
    const secure_mail_demo_result result = run_secure_mail_demo_with_message(
        required_rsa_prime_bits,
        "generated/mail_file",
        message,
        std::cout);
    if (!result.signature_verified || result.recovered_message != message) {
        throw std::runtime_error("文件安全邮件收发验证失败");
    }
}

/***************************************************************************
  函数名称：run_menu
  功    能：显示并处理控制台交互菜单
  输入参数：无
  返 回 值：0 为正常退出，1 为输入或测试失败
  说    明：每次读取选择后丢弃行末换行，再执行相应模块。
***************************************************************************/
static int run_menu()
{
    while (true) {
        std::cout
            << "\n===== 现代密码学课程设计菜单 =====\n"
            << "1. 运行全部快速独立测试\n"
            << "2. 运行严格层次 PKI 示例（512-bit 演示参数）\n"
            << "3. RSA 自定义加密/解密/签名（p/q=1024 bit）\n"
            << "4. ElGamal 自定义加密/解密/签名（p=2048 bit）\n"
            << "5. 运行简易安全邮件示例（512-bit 演示参数）\n"
            << "6. 从 UTF-8 文件读取邮件并按 1024-bit RSA 完成收发\n"
            << "0. 退出\n"
            << "请选择：";

        int choice = -1;
        if (!(std::cin >> choice)) {
            return 1;
        }
        std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

        if (choice == 0) {
            return 0;
        }
        if (choice == 1) {
            if (run_all(false) != 0) {
                return 1;
            }
        } else if (choice == 2) {
            run_strict_hierarchy_pki_demo(demo_rsa_bits, "generated/demo", std::cout);
        } else if (choice == 3) {
            run_rsa_interactive();
        } else if (choice == 4) {
            run_elgamal_interactive();
        } else if (choice == 5) {
            run_secure_mail_demo(demo_rsa_bits, "generated/mail_demo", std::cout);
        } else if (choice == 6) {
            std::cout << "请输入 UTF-8 邮件文件路径：\n> ";
            std::string path;
            std::getline(std::cin, path);
            run_mail_from_file(path);
        } else {
            std::cout << "无效选项。\n";
        }
    }
}


/***************************************************************************
  函数名称：main
  功    能：初始化程序并分派菜单或命令行任务
  输入参数：int argc：命令行参数数量
  char* argv[]：命令行参数字符串数组
  返 回 值：0 为成功，1 为参数错误或执行失败
  说    明：无参数进入菜单；捕获标准异常并输出错误说明。
***************************************************************************/
int main(int argc, char* argv[])
{
    configure_console();
    initialize_random();

    try {
        if (argc <= 1) {
            return run_menu();
        }

        const std::string arg = argv[1];
        if (arg == "--help" || arg == "-h") {
            print_help();
            return 0;
        }
        if (arg == "--test") {
            return run_all(false);
        }
        if (arg == "--full-test") {
            return run_all(true);
        }
        if (arg.rfind("--test-", 0) == 0) {
            return run_component(arg.substr(7), false);
        }
        if (arg.rfind("--full-test-", 0) == 0) {
            return run_component(arg.substr(12), true);
        }
        if (arg == "--demo") {
            run_strict_hierarchy_pki_demo(demo_rsa_bits, "generated/demo", std::cout);
            return 0;
        }
        if (arg == "--full-demo") {
            run_strict_hierarchy_pki_demo(required_rsa_prime_bits, "generated/full_demo", std::cout);
            return 0;
        }
        if (arg == "--mail-demo") {
            run_secure_mail_demo(demo_rsa_bits, "generated/mail_demo", std::cout);
            return 0;
        }
        if (arg == "--full-mail-demo") {
            run_secure_mail_demo(required_rsa_prime_bits, "generated/full_mail_demo", std::cout);
            return 0;
        }
        if (arg == "--mail-file") {
            if (argc < 3) {
                throw std::invalid_argument("--mail-file 后必须提供 UTF-8 文件路径");
            }
            run_mail_from_file(argv[2]);
            return 0;
        }

        print_help();
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "[ERROR] " << ex.what() << "\n";
        return 1;
    }
}
