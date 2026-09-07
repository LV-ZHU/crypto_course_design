#include "pki.h"

#include "user.h"

#include <set>
#include <stdexcept>
#include <utility>


/***************************************************************************
  函数名称：storage_key
  功    能：构造证书库的索引键
  输入参数：const std::string& subject_id：证书主体的身份标识
  key_usage_type key_usage：申请或查询的公钥用途
  返 回 值：由主体标识和用途组成的键
  说    明：同一个主体的加密证书与签名证书使用不同键。
***************************************************************************/
std::string certificate_repository::storage_key(const std::string& subject_id, key_usage_type key_usage)
{
    return subject_id + "|" + std::to_string(static_cast<int>(key_usage));
}

/***************************************************************************
  函数名称：store_from_ca
  功    能：将 CA 签发的证书存入证书库
  输入参数：const certificate_data& certificate：待处理的证书
  const std::string& ca_id：提交证书的 CA 标识
  返 回 值：true 为存入成功，false 为标识检查失败
  说    明：仅向友元 CA 开放；相同主体和用途的新证书覆盖旧记录。
***************************************************************************/
bool certificate_repository::store_from_ca(const certificate_data& certificate, const std::string& ca_id)
{
    if (certificate.issuer_id != ca_id || ca_id.empty() || certificate.subject_id.empty()) {
        return false;
    }
    certificates_[storage_key(certificate.subject_id, certificate.flag2)] = certificate;
    return true;
}

/***************************************************************************
  函数名称：find
  功    能：根据主体与用途查找证书
  输入参数：const std::string& subject_id：证书主体的身份标识
  key_usage_type key_usage：申请或查询的公钥用途
  返 回 值：证书指针，未找到时为 nullptr
  说    明：返回证书库内部对象地址，调用方不得释放该地址。
***************************************************************************/
const certificate_data* certificate_repository::find(const std::string& subject_id, key_usage_type key_usage) const
{
    const std::map<std::string, certificate_data>::const_iterator it = certificates_.find(storage_key(subject_id, key_usage));
    return it == certificates_.end() ? nullptr : &it->second;
}

/***************************************************************************
  函数名称：query_path
  功    能：从目标主体向上查找完整证书路径
  输入参数：const std::string& subject_id：证书主体的身份标识
  key_usage_type key_usage：申请或查询的公钥用途
  返 回 值：按根 CA 到主体顺序排列的证书数组
  说    明：检测缺失证书和循环关系；上级 CA 使用签名用途证书。
***************************************************************************/
std::vector<certificate_data> certificate_repository::query_path(
    const std::string& subject_id,
    key_usage_type key_usage) const
{
    std::vector<certificate_data> reversed;
    std::set<std::string> visited;
    std::string current_id = subject_id;
    key_usage_type current_usage = key_usage;

    while (true) {
        const std::string key = storage_key(current_id, current_usage);
        if (!visited.insert(key).second) {
            throw std::runtime_error("cycle detected in certificate path at ID: " + current_id);
        }
        const certificate_data* cert = find(current_id, current_usage);
        if (cert == nullptr) {
            throw std::runtime_error(
                "certificate not found for ID=" + current_id + ", usage=" + key_usage_name(current_usage));
        }
        reversed.push_back(*cert);
        if (cert->issuer_id == cert->subject_id) {
            break;
        }
        current_id = cert->issuer_id;
        current_usage = key_usage_type::SIGNATURE;
    }
    return std::vector<certificate_data>(reversed.rbegin(), reversed.rend());
}

/***************************************************************************
  函数名称：save_all
  功    能：将证书库导出到目录
  输入参数：const std::filesystem::path& directory：用于证书导出的目录
  返 回 值：无
  说    明：沿用原行为，先清理目录中的普通 TXT 文件，再按主体与用途保存。
***************************************************************************/
void certificate_repository::save_all(const std::filesystem::path& directory) const
{
    std::filesystem::create_directories(directory);
    for (std::filesystem::directory_iterator it(directory); it != std::filesystem::directory_iterator(); ++it) {
        const std::filesystem::directory_entry& entry = *it;
        if (entry.is_regular_file() && entry.path().extension() == ".txt") {
            std::filesystem::remove(entry.path());
        }
    }
    for (std::map<std::string, certificate_data>::const_iterator it = certificates_.begin(); it != certificates_.end(); ++it) {
        const certificate_data& cert = it->second;
        const std::string suffix = cert.flag2 == key_usage_type::ENCRYPTION ? "_encryption.txt" : "_signature.txt";
        cert.save_to_file(directory / (cert.subject_id + suffix));
    }
}

/***************************************************************************
  函数名称：size
  功    能：取得证书库内记录数量
  输入参数：无
  返 回 值：已存储的证书数量
  说    明：同一主体的两种用途分别计数。
***************************************************************************/
std::size_t certificate_repository::size() const
{
    return certificates_.size();
}

/***************************************************************************
  函数名称：certificate_authority
  功    能：构造持有密钥与证书的 CA 对象
  输入参数：std::string id：当前机构或用户的身份标识
  rsa_key_pair key_pair：包含公钥和私钥的密钥对
  certificate_data certificate：待处理的证书
  certificate_repository& repository：保存证书并提供查询的证书库
  返 回 值：无，构造函数
  说    明：保存证书库地址，证书库的生存期必须长于 CA。
***************************************************************************/
certificate_authority::certificate_authority(
    std::string id,
    rsa_key_pair key_pair,
    certificate_data certificate,
    certificate_repository& repository)
    : id_(id),
      key_pair_(key_pair),
      certificate_(certificate),
      repository_(&repository)
{}

/***************************************************************************
  函数名称：create_root_rsa
  功    能：创建 RSA 根 CA 及其自签名证书
  输入参数：const std::string& id：当前机构或用户的身份标识
  certificate_repository& repository：保存证书并提供查询的证书库
  long rsa_prime_bits：RSA 每个素数 p、q 的位数
  返 回 值：根 CA 对象
  说    明：生成密钥后签发自身证书并存入指定证书库。
***************************************************************************/
certificate_authority certificate_authority::create_root_rsa(
    const std::string& id,
    certificate_repository& repository,
    long rsa_prime_bits)
{
    rsa_key_pair key_pair = generate_rsa_key_pair(rsa_prime_bits);
    certificate_data certificate = issue_certificate_rsa(
        id,
        public_key_data::from_rsa(key_pair.public_key),
        id,
        key_usage_type::SIGNATURE,
        key_pair);
    if (!repository.store_from_ca(certificate, id)) {
        throw std::runtime_error("failed to store root certificate");
    }
    return certificate_authority(id, key_pair, certificate, repository);
}

/***************************************************************************
  函数名称：create_child_rsa
  功    能：创建由上级 CA 签发证书的子 CA
  输入参数：const std::string& id：当前机构或用户的身份标识
  const certificate_authority& issuer：负责签发当前 CA 证书的上级 CA
  certificate_repository& repository：保存证书并提供查询的证书库
  long rsa_prime_bits：RSA 每个素数 p、q 的位数
  返 回 值：子 CA 对象
  说    明：上下级必须使用同一个证书库，子 CA 的证书用于签名验证。
***************************************************************************/
certificate_authority certificate_authority::create_child_rsa(
    const std::string& id,
    const certificate_authority& issuer,
    certificate_repository& repository,
    long rsa_prime_bits)
{
    if (issuer.repository_ != &repository) {
        throw std::invalid_argument("child CA must use the issuer's certificate repository");
    }
    rsa_key_pair key_pair = generate_rsa_key_pair(rsa_prime_bits);
    certificate_data certificate = issue_certificate_rsa(
        id,
        public_key_data::from_rsa(key_pair.public_key),
        issuer.id_,
        key_usage_type::SIGNATURE,
        issuer.key_pair_);
    if (!repository.store_from_ca(certificate, issuer.id_)) {
        throw std::runtime_error("failed to store child CA certificate");
    }
    return certificate_authority(id, key_pair, certificate, repository);
}

/***************************************************************************
  函数名称：issue_certificate
  功    能：为指定主体签发指定用途的证书
  输入参数：const std::string& subject_id：证书主体的身份标识
  const public_key_data& subject_public_key：证书主体的公钥
  key_usage_type key_usage：申请或查询的公钥用途
  返 回 值：签发完成的证书
  说    明：CA 类还将证书存入关联证书库；TA 类按自身算法选择签名方式。
***************************************************************************/
certificate_data certificate_authority::issue_certificate(
    const std::string& subject_id,
    const public_key_data& subject_public_key,
    key_usage_type key_usage) const
{
    certificate_data certificate = issue_certificate_rsa(
        subject_id,
        subject_public_key,
        id_,
        key_usage,
        key_pair_);
    if (!repository_->store_from_ca(certificate, id_)) {
        throw std::runtime_error("failed to store certificate issued by " + id_);
    }
    return certificate;
}

/***************************************************************************
  函数名称：id
  功    能：取得当前对象的身份标识
  输入参数：无
  返 回 值：身份字符串的只读引用
  说    明：引用的有效期与当前对象一致。
***************************************************************************/
const std::string& certificate_authority::id() const
{
    return id_;
}

/***************************************************************************
  函数名称：key_pair
  功    能：取得 CA 的 RSA 密钥对
  输入参数：无
  返 回 值：密钥对的只读引用
  说    明：供课程演示建立信任锚使用，引用有效期与 CA 一致。
***************************************************************************/
const rsa_key_pair& certificate_authority::key_pair() const
{
    return key_pair_;
}

/***************************************************************************
  函数名称：certificate
  功    能：取得对象持有的证书
  输入参数：无
  返 回 值：证书的只读引用
  说    明：用户对象按用途选择证书，尚未申请对应证书时抛出异常。
***************************************************************************/
const certificate_data& certificate_authority::certificate() const
{
    return certificate_;
}

/***************************************************************************
  函数名称：certificate_path_failure
  功    能：保存证书路径验证失败的原因
  输入参数：const std::string& message：待加密、签名或验证的消息；指针参数用于输出正文
  std::string* error_message：接收失败原因的字符串指针，可为 nullptr
  返 回 值：固定返回 false
  说    明：error_message 可以为空指针，为空时只返回失败状态。
***************************************************************************/
static bool certificate_path_failure(const std::string& message, std::string* error_message)
{
    if (error_message != nullptr) {
        *error_message = message;
    }
    return false;
}

/***************************************************************************
  函数名称：verify_certificate_path
  功    能：从可信根公钥开始逐级验证证书路径
  输入参数：const std::vector<certificate_data>& path：文件路径；证书路径验证函数中为按根到主体排列的证书数组
  const public_key_data& trusted_root_public_key：调用方预先信任的根 CA 公钥
  std::string* error_message：接收失败原因的字符串指针，可为 nullptr
  返 回 值：true 为整条路径通过，false 为验证失败
  说    明：检查根自签名、信任锚、公钥用途、签发者关系及逐级签名。
***************************************************************************/
bool verify_certificate_path(
    const std::vector<certificate_data>& path,
    const public_key_data& trusted_root_public_key,
    std::string* error_message)
{

    if (path.empty()) {
        return certificate_path_failure("empty certificate path", error_message);
    }
    if (path.front().subject_id != path.front().issuer_id) {
        return certificate_path_failure("first certificate is not a self-signed root", error_message);
    }
    if (path.front().flag2 != key_usage_type::SIGNATURE) {
        return certificate_path_failure("root certificate is not marked for signature verification", error_message);
    }
    if (canonical_public_key(path.front().subject_public_key) != canonical_public_key(trusted_root_public_key)) {
        return certificate_path_failure("root certificate public key differs from trusted anchor", error_message);
    }
    if (!verify_certificate(path.front(), trusted_root_public_key)) {
        return certificate_path_failure("root certificate signature is invalid", error_message);
    }

    // 已验证的上一层公钥作为下一张证书的验签公钥，逐层传递信任。
    public_key_data issuer_key = path.front().subject_public_key;
    std::string issuer_id = path.front().subject_id;
    for (std::size_t i = 1; i < path.size(); ++i) {
        if (path[i].issuer_id != issuer_id) {
            return certificate_path_failure("issuer mismatch at certificate " + path[i].subject_id, error_message);
        }
        if (i + 1 < path.size() && path[i].flag2 != key_usage_type::SIGNATURE) {
            return certificate_path_failure("intermediate CA certificate is not marked for signature verification", error_message);
        }
        if (!verify_certificate(path[i], issuer_key)) {
            return certificate_path_failure("signature invalid at certificate " + path[i].subject_id, error_message);
        }
        issuer_key = path[i].subject_public_key;
        issuer_id = path[i].subject_id;
    }
    if (error_message != nullptr) {
        error_message->clear();
    }
    return true;
}

/***************************************************************************
  函数名称：run_strict_hierarchy_pki_demo
  功    能：演示严格层次 PKI 的签发、查询和验证
  输入参数：long rsa_prime_bits：RSA 每个素数 p、q 的位数
  const std::filesystem::path& output_directory：生成证书等测试数据的输出目录
  std::ostream& log：用于输出执行过程和结果的日志流
  返 回 值：证书链与消息签名的验证结果
  说    明：建立三个 CA 和三个双密钥用户，并检查篡改后的证书链被拒绝。
***************************************************************************/
pki_demo_result run_strict_hierarchy_pki_demo(
    long rsa_prime_bits,
    const std::filesystem::path& output_directory,
    std::ostream& log)
{
    log << "[PKI] 生成 CA 与用户双用途 RSA 密钥，RSA 素数位数=" << rsa_prime_bits << "\n";
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

    const std::filesystem::path cert_dir = output_directory / "certs";
    repository.save_all(cert_dir);
    log << "[PKI] 证书库共存储 " << repository.size()
        << " 张证书（CA 3 张、用户双用途证书 6 张）\n";

    const std::string message = "Alice sends Bob a signed message for the strict hierarchical PKI demo.";
    const big_integer alice_signature = alice.sign_message(message);
    std::vector<certificate_data> path = repository.query_path("Alice", key_usage_type::SIGNATURE);

    std::string error;
    const bool path_ok = verify_certificate_path(path, public_key_data::from_rsa(root.key_pair().public_key), &error);
    const bool sig_ok = path_ok && path.back().flag2 == key_usage_type::SIGNATURE &&
                       path.back().subject_public_key.algorithm == public_key_algorithm::RSA &&
                       rsa_verify_message(message, alice_signature, path.back().subject_public_key.rsa);
    std::vector<certificate_data> tampered_path = path;
    tampered_path.back().signature.rsa += 1;
    std::string tampered_error;
    const bool tampered_path_rejected = !verify_certificate_path(
        tampered_path,
        public_key_data::from_rsa(root.key_pair().public_key),
        &tampered_error);

    log << "[PKI] Bob 查询 Alice 的签名证书路径：";
    std::vector<std::string> ids;
    for (std::size_t i = 0; i < path.size(); ++i) {
        const certificate_data& cert = path[i];
        ids.push_back(cert.subject_id);
        log << " <" << cert.subject_id << ">";
    }
    log << "\n";
    log << "[PKI] 证书路径验证：" << (path_ok ? "通过" : ("失败: " + error)) << "\n";
    log << "[PKI] Alice 消息签名验证：" << (sig_ok ? "通过" : "失败") << "\n";
    log << "[PKI] 篡改证书链拒绝测试：" << (tampered_path_rejected ? "通过" : "失败") << "\n";

    pki_demo_result result;
    result.path_verified = path_ok;
    result.signature_verified = sig_ok;
    result.tampered_path_rejected = tampered_path_rejected;
    result.message = message;
    result.alice_signature = zz_to_string(alice_signature);
    result.certificate_path_ids = ids;
    result.certificate_directory = cert_dir;
    result.repository_size = repository.size();
    return result;
}
