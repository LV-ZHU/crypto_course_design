#include "secure_mail.h"

#include <stdexcept>


/***************************************************************************
  函数名称：query_verified_path
  功    能：查询并验证指定主体和用途的证书路径
  输入参数：const certificate_repository& repository：保存证书并提供查询的证书库
  const std::string& subject_id：证书主体的身份标识
  key_usage_type key_usage：申请或查询的公钥用途
  const public_key_data& trusted_root_public_key：调用方预先信任的根 CA 公钥
  const secure_mail_options& options：测试参数或邮件证书查询策略
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：验证通过的证书路径
  说    明：按 options 控制失败后终止或重试，最终失败时抛出异常。
***************************************************************************/
static std::vector<certificate_data> query_verified_path(
    const certificate_repository& repository,
    const std::string& subject_id,
    key_usage_type key_usage,
    const public_key_data& trusted_root_public_key,
    const secure_mail_options& options,
    std::ostream& log)
{
    const int attempts = options.max_query_attempts > 0 ? options.max_query_attempts : 1;
    std::string last_error;
    for (int attempt = 1; attempt <= attempts; ++attempt) {
        try {
            std::vector<certificate_data> path = repository.query_path(subject_id, key_usage);
            if (verify_certificate_path(path, trusted_root_public_key, &last_error) &&
                path.back().subject_id == subject_id && path.back().flag2 == key_usage) {
                return path;
            }
            if (last_error.empty()) {
                last_error = "certificate path returned the wrong subject or key usage";
            }
        } catch (const std::exception& ex) {
            last_error = ex.what();
        }

        const bool can_retry = options.path_failure_action == path_failure_action_type::RETRY && attempt < attempts;
        if (!can_retry) {
            throw std::runtime_error(
                "certificate path verification failed for " + subject_id + ": " + last_error);
        }
        log << "[MAIL] 第 " << attempt << " 次证书链申请失败，按用户选择重新申请\n";
    }
    throw std::runtime_error("unreachable certificate query state");
}

/***************************************************************************
  函数名称：serialize_signed_content
  功    能：组合邮件明文与签名
  输入参数：const std::string& message：待加密、签名或验证的消息；指针参数用于输出正文
  const big_integer& signature：签名值；指针参数用于输出解析结果
  返 回 值：带长度前缀的待加密字符串
  说    明：长度按字节计算，使正文中的换行符不会与签名分隔符混淆。
***************************************************************************/
static std::string serialize_signed_content(const std::string& message, const big_integer& signature)
{
    return std::to_string(message.size()) + "\n" + message + "\n" + zz_to_string(signature);
}

/***************************************************************************
  函数名称：parse_signed_content
  功    能：从解密内容中提取正文与签名
  输入参数：const std::string& content：解密后带长度前缀的正文与签名
  std::string* message：待加密、签名或验证的消息；指针参数用于输出正文
  big_integer* signature：签名值；指针参数用于输出解析结果
  返 回 值：无，通过指针输出 message 和 signature
  说    明：输出指针必须有效；检查长度、截断和分隔符，格式错误时抛出异常。
***************************************************************************/
static void parse_signed_content(const std::string& content, std::string* message, big_integer* signature)
{
    const std::size_t first_newline = content.find('\n');
    if (first_newline == std::string::npos) {
        throw std::runtime_error("secure mail content is missing the message length");
    }

    std::size_t parsed_characters = 0;
    const unsigned long long message_length = std::stoull(content.substr(0, first_newline), &parsed_characters);
    if (parsed_characters != first_newline) {
        throw std::runtime_error("secure mail message length is invalid");
    }
    const std::size_t message_start = first_newline + 1;
    if (message_length > content.size() - message_start) {
        throw std::runtime_error("secure mail message is truncated");
    }
    const std::size_t signature_separator = message_start + static_cast<std::size_t>(message_length);
    if (signature_separator >= content.size() || content[signature_separator] != '\n') {
        throw std::runtime_error("secure mail signature separator is missing");
    }
    *message = content.substr(message_start, static_cast<std::size_t>(message_length));
    *signature = zz_from_string(content.substr(signature_separator + 1));
}

/***************************************************************************
  函数名称：path_ids
  功    能：提取证书路径中的主体身份
  输入参数：const std::vector<certificate_data>& path：文件路径；证书路径验证函数中为按根到主体排列的证书数组
  返 回 值：按证书路径顺序排列的身份数组
  说    明：用于显示及记录验证路径。
***************************************************************************/
static std::vector<std::string> path_ids(const std::vector<certificate_data>& path)
{
    std::vector<std::string> ids;
    for (std::size_t i = 0; i < path.size(); ++i) {
        const certificate_data& certificate = path[i];
        ids.push_back(certificate.subject_id);
    }
    return ids;
}


/***************************************************************************
  函数名称：send_secure_mail
  功    能：验证接收者证书并发送签名加密邮件
  输入参数：const pki_user& sender：持有签名私钥的发送者
  const std::string& recipient_id：接收者身份标识
  const std::string& message：待加密、签名或验证的消息；指针参数用于输出正文
  const certificate_repository& repository：保存证书并提供查询的证书库
  const public_key_data& trusted_root_public_key：调用方预先信任的根 CA 公钥
  const secure_mail_options& options：测试参数或邮件证书查询策略
  std::ostream& log：用于输出执行过程和结果的日志流
  bool* recipient_path_verified：接收接收者证书链验证状态的指针，可为 nullptr
  返 回 值：包含双方标识与密文块的邮件
  说    明：先签名，再使用接收者加密公钥加密正文与签名；不发送网络请求。
***************************************************************************/
secure_mail send_secure_mail(
    const pki_user& sender,
    const std::string& recipient_id,
    const std::string& message,
    const certificate_repository& repository,
    const public_key_data& trusted_root_public_key,
    const secure_mail_options& options,
    std::ostream& log,
    bool* recipient_path_verified)
{
    if (recipient_path_verified != nullptr) {
        *recipient_path_verified = false;
    }
    if (message.empty()) {
        throw std::invalid_argument("secure mail message cannot be empty");
    }
    log << "[MAIL-SEND] 查询并验证 " << recipient_id << " 的加密证书链\n";
    const std::vector<certificate_data> recipient_path = query_verified_path(
        repository,
        recipient_id,
        key_usage_type::ENCRYPTION,
        trusted_root_public_key,
        options,
        log);
    if (recipient_path_verified != nullptr) {
        *recipient_path_verified = true;
    }
    const certificate_data& recipient_certificate = recipient_path.back();
    if (recipient_certificate.subject_public_key.algorithm != public_key_algorithm::RSA) {
        throw std::runtime_error("secure mail demo requires an RSA encryption public key");
    }

    log << "[MAIL-SEND] 用 " << sender.id() << " 的签名私钥对 SHA-256(message) 签名\n";
    // 先用发送者签名私钥签名，再将正文和签名整体交给接收者公钥加密。
    const big_integer signature = sender.sign_message(message);
    const std::string signed_content = serialize_signed_content(message, signature);
    const std::vector<big_integer> cipher_blocks = rsa_encrypt_text(signed_content, recipient_certificate.subject_public_key.rsa);
    log << "[MAIL-SEND] 用接收端加密公钥加密 message||signature，密文块数="
        << cipher_blocks.size() << "\n";

    secure_mail mail;
    mail.sender_id = sender.id();
    mail.recipient_id = recipient_id;
    mail.cipher_blocks = cipher_blocks;
    return mail;
}

/***************************************************************************
  函数名称：receive_secure_mail
  功    能：解密邮件并验证发送者身份及消息签名
  输入参数：const pki_user& recipient：持有解密私钥的接收者
  const secure_mail& mail：接收到的邮件数据
  const certificate_repository& repository：保存证书并提供查询的证书库
  const public_key_data& trusted_root_public_key：调用方预先信任的根 CA 公钥
  const secure_mail_options& options：测试参数或邮件证书查询策略
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：明文、证书路径与签名验证结果
  说    明：接收者不匹配或路径无效时抛出异常；消息验签失败通过结果中的布尔值表示。
***************************************************************************/
secure_mail_receive_result receive_secure_mail(
    const pki_user& recipient,
    const secure_mail& mail,
    const certificate_repository& repository,
    const public_key_data& trusted_root_public_key,
    const secure_mail_options& options,
    std::ostream& log)
{
    if (mail.recipient_id != recipient.id()) {
        throw std::runtime_error("secure mail recipient ID does not match the current user");
    }

    log << "[MAIL-RECV] " << recipient.id() << " 用加密私钥解密密文\n";
    const std::string signed_content = recipient.decrypt_text(mail.cipher_blocks);
    std::string message;
    big_integer signature;
    parse_signed_content(signed_content, &message, &signature);

    log << "[MAIL-RECV] 查询并验证 " << mail.sender_id << " 的签名证书链\n";
    const std::vector<certificate_data> sender_path = query_verified_path(
        repository,
        mail.sender_id,
        key_usage_type::SIGNATURE,
        trusted_root_public_key,
        options,
        log);
    const certificate_data& sender_certificate = sender_path.back();
    if (sender_certificate.subject_public_key.algorithm != public_key_algorithm::RSA) {
        throw std::runtime_error("secure mail demo requires an RSA signature public key");
    }

    const bool signature_verified = rsa_verify_message(
        message,
        signature,
        sender_certificate.subject_public_key.rsa);
    log << "[MAIL-RECV] 邮件签名验证：" << (signature_verified ? "通过" : "失败") << "\n";

    secure_mail_receive_result result;
    result.plaintext = message;
    result.sender_path_verified = true;
    result.signature_verified = signature_verified;
    result.sender_path_ids = path_ids(sender_path);
    return result;
}

/***************************************************************************
  函数名称：run_secure_mail_demo
  功    能：使用预设中文正文演示安全邮件
  输入参数：long rsa_prime_bits：RSA 每个素数 p、q 的位数
  const std::filesystem::path& output_directory：生成证书等测试数据的输出目录
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：收发及攻击拒绝的演示结果
  说    明：转交给支持指定正文的演示函数。
***************************************************************************/
secure_mail_demo_result run_secure_mail_demo(
    long rsa_prime_bits,
    const std::filesystem::path& output_directory,
    std::ostream& log)
{
    return run_secure_mail_demo_with_message(
        rsa_prime_bits,
        output_directory,
        "课程设计安全邮件：Alice 向 Bob 发送经过签名和加密的 UTF-8 消息。",
        log);
}

/***************************************************************************
  函数名称：run_secure_mail_demo_with_message
  功    能：使用指定正文演示安全邮件完整流程
  输入参数：long rsa_prime_bits：RSA 每个素数 p、q 的位数
  const std::filesystem::path& output_directory：生成证书等测试数据的输出目录
  const std::string& message：待加密、签名或验证的消息；指针参数用于输出正文
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：收发、证书路径和攻击拒绝结果
  说    明：建立演示 PKI，检查错误接收者及冒充发送者两种情况，并导出证书。
***************************************************************************/
secure_mail_demo_result run_secure_mail_demo_with_message(
    long rsa_prime_bits,
    const std::filesystem::path& output_directory,
    const std::string& message,
    std::ostream& log)
{
    log << "[MAIL] 初始化严格层次 PKI 与双用途证书，RSA 素数位数=" << rsa_prime_bits << "\n";
    certificate_repository repository;
    certificate_authority root = certificate_authority::create_root_rsa("CAroot", repository, rsa_prime_bits);
    certificate_authority ca1 = certificate_authority::create_child_rsa("CA1", root, repository, rsa_prime_bits);
    certificate_authority ca2 = certificate_authority::create_child_rsa("CA2", root, repository, rsa_prime_bits);

    pki_user alice("Alice", rsa_prime_bits);
    pki_user bob("Bob", rsa_prime_bits);
    pki_user eve("Eve", rsa_prime_bits);
    alice.request_certificates(ca1);
    bob.request_certificates(ca2);
    eve.request_certificates(ca1);

    const public_key_data trusted_root_public_key = public_key_data::from_rsa(root.key_pair().public_key);
    secure_mail_options options;
    options.path_failure_action = path_failure_action_type::RETRY;
    options.max_query_attempts = 2;

    bool recipient_path_verified = false;
    const secure_mail mail = send_secure_mail(
        alice,
        bob.id(),
        message,
        repository,
        trusted_root_public_key,
        options,
        log,
        &recipient_path_verified);
    const secure_mail_receive_result received = receive_secure_mail(
        bob,
        mail,
        repository,
        trusted_root_public_key,
        options,
        log);

    bool wrong_recipient_rejected = false;
    try {
        (void)receive_secure_mail(eve, mail, repository, trusted_root_public_key, options, log);
    } catch (const std::exception&) {
        wrong_recipient_rejected = true;
    }

    bool ignored_path_result = false;
    secure_mail forged_mail = send_secure_mail(
        eve,
        bob.id(),
        "forged sender test",
        repository,
        trusted_root_public_key,
        options,
        log,
        &ignored_path_result);
    forged_mail.sender_id = alice.id();
    const secure_mail_receive_result forged_result = receive_secure_mail(
        bob,
        forged_mail,
        repository,
        trusted_root_public_key,
        options,
        log);
    const bool forged_sender_rejected = !forged_result.signature_verified;

    const std::filesystem::path certificate_directory = output_directory / "certs";
    repository.save_all(certificate_directory);
    log << "[MAIL] Bob 恢复明文：" << received.plaintext << "\n";
    log << "[MAIL] 错误接收者拒绝测试：" << (wrong_recipient_rejected ? "通过" : "失败") << "\n";
    log << "[MAIL] 冒充发送者拒绝测试：" << (forged_sender_rejected ? "通过" : "失败") << "\n";

    secure_mail_demo_result result;
    result.recipient_path_verified = recipient_path_verified;
    result.sender_path_verified = received.sender_path_verified;
    result.signature_verified = received.signature_verified;
    result.wrong_recipient_rejected = wrong_recipient_rejected;
    result.forged_sender_rejected = forged_sender_rejected;
    result.recovered_message = received.plaintext;
    result.cipher_block_count = mail.cipher_blocks.size();
    result.certificate_directory = certificate_directory;
    return result;
}
