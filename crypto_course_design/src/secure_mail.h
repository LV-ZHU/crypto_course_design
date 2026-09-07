#pragma once

#include "pki.h"
#include "user.h"

#include <filesystem>
#include <ostream>
#include <string>
#include <vector>


// 证书路径查询失败后的处理方式。
enum class path_failure_action_type {
    ABORT,
    RETRY
};

// 安全邮件的证书查询策略。
struct secure_mail_options {
    path_failure_action_type path_failure_action = path_failure_action_type::ABORT; // 查询失败后终止或重试
    int max_query_attempts = 1; // 最多查询次数，非正数按一次处理
};

// 在发送端与接收端之间传递的邮件数据。
struct secure_mail {
    std::string sender_id; // 发送者身份标识
    std::string recipient_id; // 接收者身份标识
    std::vector<big_integer> cipher_blocks; // 正文与签名一起加密后的密文块
};

// 邮件解密及发送者验证的结果。
struct secure_mail_receive_result {
    std::string plaintext; // 解密得到的正文
    bool sender_path_verified = false; // 发送者签名证书链是否有效
    bool signature_verified = false; // 消息签名是否通过验证
    std::vector<std::string> sender_path_ids; // 发送者证书链中的身份标识
};

// 安全邮件演示及攻击拒绝检查的汇总结果。
struct secure_mail_demo_result {
    bool recipient_path_verified = false; // 接收者加密证书链是否有效
    bool sender_path_verified = false; // 发送者签名证书链是否有效
    bool signature_verified = false; // 消息签名是否通过验证
    bool wrong_recipient_rejected = false; // 错误接收者是否被拒绝
    bool forged_sender_rejected = false; // 伪造发送者是否被拒绝
    std::string recovered_message; // 接收端恢复的正文
    std::size_t cipher_block_count = 0; // 邮件密文块数量
    std::filesystem::path certificate_directory; // 导出的证书所在目录
};

secure_mail send_secure_mail(
    const pki_user& sender,
    const std::string& recipient_id,
    const std::string& message,
    const certificate_repository& repository,
    const public_key_data& trusted_root_public_key,
    const secure_mail_options& options,
    std::ostream& log,
    bool* recipient_path_verified);

secure_mail_receive_result receive_secure_mail(
    const pki_user& recipient,
    const secure_mail& mail,
    const certificate_repository& repository,
    const public_key_data& trusted_root_public_key,
    const secure_mail_options& options,
    std::ostream& log);

secure_mail_demo_result run_secure_mail_demo(
    long rsa_prime_bits,
    const std::filesystem::path& output_directory,
    std::ostream& log);

secure_mail_demo_result run_secure_mail_demo_with_message(
    long rsa_prime_bits,
    const std::filesystem::path& output_directory,
    const std::string& message,
    std::ostream& log);
