#include "certificate.h"

#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>


/***************************************************************************
  函数名称：strip_trailing_carriage_return
  功    能：去除文本行末的回车符
  输入参数：std::string* line：待去除行末回车的字符串指针
  返 回 值：无
  说    明：line 指针必须有效；兼容 Windows 的 CRLF 换行。
***************************************************************************/
static void strip_trailing_carriage_return(std::string* line)
{
    if (!line->empty() && line->back() == '\r') {
        line->pop_back();
    }
}

/***************************************************************************
  函数名称：value_or_throw
  功    能：从证书字段表中读取指定字段
  输入参数：const std::map<std::string, std::string>& values：证书字段名到字段值的映射
  const std::string& key：要查找的字段名称
  返 回 值：对应字段的文本值
  说    明：字段不存在时抛出异常，不生成默认值。
***************************************************************************/
static std::string value_or_throw(const std::map<std::string, std::string>& values, const std::string& key)
{
    const std::map<std::string, std::string>::const_iterator it = values.find(key);
    if (it == values.end()) {
        throw std::runtime_error("certificate field missing: " + key);
    }
    return it->second;
}

/***************************************************************************
  函数名称：parse_key_values
  功    能：解析证书文本的键值字段
  输入参数：const std::string& text：待处理的文本
  返 回 值：证书字段映射表
  说    明：检查起止标记、字段分隔符、重复字段和结束标记后的多余内容。
***************************************************************************/
static std::map<std::string, std::string> parse_key_values(const std::string& text)
{
    std::map<std::string, std::string> values;
    std::istringstream in(text);
    std::string line;
    if (!std::getline(in, line)) {
        throw std::runtime_error("certificate must start with CERTIFICATE_BEGIN");
    }
    strip_trailing_carriage_return(&line);
    if (line != "CERTIFICATE_BEGIN") {
        throw std::runtime_error("certificate must start with CERTIFICATE_BEGIN");
    }
    bool reached_end = false;
    while (std::getline(in, line)) {
        strip_trailing_carriage_return(&line);
        if (line == "CERTIFICATE_END") {
            reached_end = true;
            break;
        }
        if (line.empty()) {
            continue;
        }
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) {
            throw std::runtime_error("malformed certificate line: " + line);
        }
        const std::string key = line.substr(0, eq);
        if (key.empty()) {
            throw std::runtime_error("certificate field name cannot be empty");
        }
        if (values.find(key) != values.end()) {
            throw std::runtime_error("duplicate certificate field: " + key);
        }
        values[key] = line.substr(eq + 1);
    }
    if (!reached_end) {
        throw std::runtime_error("certificate must end with CERTIFICATE_END");
    }
    while (std::getline(in, line)) {
        strip_trailing_carriage_return(&line);
        if (!line.empty()) {
            throw std::runtime_error("unexpected content after CERTIFICATE_END");
        }
    }
    return values;
}

/***************************************************************************
  函数名称：parse_subject_public_key
  功    能：从证书字段中恢复主体公钥
  输入参数：const std::map<std::string, std::string>& values：证书字段名到字段值的映射
  返 回 值：包含算法标记的主体公钥
  说    明：根据算法标记读取 RSA 或 ElGamal 参数，未知算法抛出异常。
***************************************************************************/
static public_key_data parse_subject_public_key(const std::map<std::string, std::string>& values)
{
    const std::string type = value_or_throw(values, "SubjectPublicKeyAlgorithm");
    if (type == "RSA") {
        return public_key_data::from_rsa(rsa_public_key{
            zz_from_string(value_or_throw(values, "SubjectRSA_n")),
            zz_from_string(value_or_throw(values, "SubjectRSA_b"))});
    }
    if (type == "ELGAMAL") {
        return public_key_data::from_elgamal(elgamal_public_key{
            zz_from_string(value_or_throw(values, "SubjectElGamal_p")),
            zz_from_string(value_or_throw(values, "SubjectElGamal_g")),
            zz_from_string(value_or_throw(values, "SubjectElGamal_y"))});
    }
    throw std::runtime_error("unknown subject public key algorithm: " + type);
}

/***************************************************************************
  函数名称：parse_signature_algorithm
  功    能：解析证书的签名算法标记
  输入参数：const std::string& value：待转换、计算或写入的数值；解析标记函数中为输入文本
  返 回 值：签名算法枚举值
  说    明：兼容数字标记 0、1 和算法名称，其他输入抛出异常。
***************************************************************************/
static signature_algorithm_type parse_signature_algorithm(const std::string& value)
{
    if (value == "0" || value == "RSA") {
        return signature_algorithm_type::RSA;
    }
    if (value == "1" || value == "ELGAMAL") {
        return signature_algorithm_type::ELGAMAL;
    }
    throw std::runtime_error("unknown signature algorithm flag: " + value);
}

/***************************************************************************
  函数名称：parse_key_usage
  功    能：解析证书公钥用途标记
  输入参数：const std::string& value：待转换、计算或写入的数值；解析标记函数中为输入文本
  返 回 值：加密或签名用途枚举值
  说    明：兼容数字标记及用途名称，未知用途抛出异常。
***************************************************************************/
static key_usage_type parse_key_usage(const std::string& value)
{
    if (value == "0" || value == "ENCRYPTION") {
        return key_usage_type::ENCRYPTION;
    }
    if (value == "1" || value == "SIGNATURE") {
        return key_usage_type::SIGNATURE;
    }
    throw std::runtime_error("unknown public key usage flag: " + value);
}


/***************************************************************************
  函数名称：from_rsa
  功    能：将 RSA 公钥包装为通用公钥数据
  输入参数：const rsa_public_key& public_key：算法对应的公钥
  返 回 值：标记为 RSA 的公钥数据
  说    明：只复制公钥参数，不包含私钥。
***************************************************************************/
public_key_data public_key_data::from_rsa(const rsa_public_key& public_key)
{
    public_key_data key;
    key.algorithm = public_key_algorithm::RSA;
    key.rsa = public_key;
    return key;
}

/***************************************************************************
  函数名称：from_elgamal
  功    能：将 ElGamal 公钥包装为通用公钥数据
  输入参数：const elgamal_public_key& public_key：算法对应的公钥
  返 回 值：标记为 ElGamal 的公钥数据
  说    明：只复制公钥参数，不包含私钥。
***************************************************************************/
public_key_data public_key_data::from_elgamal(const elgamal_public_key& public_key)
{
    public_key_data key;
    key.algorithm = public_key_algorithm::ELGAMAL;
    key.elgamal = public_key;
    return key;
}

/***************************************************************************
  函数名称：public_key_algorithm_name
  功    能：取得公钥算法的文本名称
  输入参数：public_key_algorithm algorithm：需要转换为文本的算法标记
  返 回 值：RSA 或 ELGAMAL
  说    明：用于证书文本的算法字段。
***************************************************************************/
std::string public_key_algorithm_name(public_key_algorithm algorithm)
{
    return algorithm == public_key_algorithm::RSA ? "RSA" : "ELGAMAL";
}

/***************************************************************************
  函数名称：signature_algorithm_name
  功    能：取得签名算法的文本名称
  输入参数：signature_algorithm_type algorithm：需要转换为文本的算法标记
  返 回 值：RSA 或 ELGAMAL
  说    明：用于证书中 Flag1 的说明字段。
***************************************************************************/
std::string signature_algorithm_name(signature_algorithm_type algorithm)
{
    return algorithm == signature_algorithm_type::RSA ? "RSA" : "ELGAMAL";
}

/***************************************************************************
  函数名称：key_usage_name
  功    能：取得公钥用途的文本名称
  输入参数：key_usage_type usage：证书公钥用途
  返 回 值：ENCRYPTION 或 SIGNATURE
  说    明：用于证书用途说明和查询错误信息。
***************************************************************************/
std::string key_usage_name(key_usage_type usage)
{
    return usage == key_usage_type::ENCRYPTION ? "ENCRYPTION" : "SIGNATURE";
}

/***************************************************************************
  函数名称：canonical_public_key
  功    能：按算法生成规范公钥字符串
  输入参数：const public_key_data& public_key：算法对应的公钥
  返 回 值：顺序固定的公钥文本
  说    明：选择对应算法的序列化函数，供载荷拼接和公钥比较使用。
***************************************************************************/
std::string canonical_public_key(const public_key_data& public_key)
{
    if (public_key.algorithm == public_key_algorithm::RSA) {
        return serialize_rsa_public_key(public_key.rsa);
    }
    return serialize_elgamal_public_key(public_key.elgamal);
}

/***************************************************************************
  函数名称：payload
  功    能：构造证书签名所覆盖的载荷
  输入参数：无
  返 回 值：主体标识与规范公钥拼接的字符串
  说    明：沿用原格式：主体标识、双竖线和规范公钥；issuer_id、flag1、flag2 不在签名载荷内。
***************************************************************************/
std::string certificate_data::payload() const
{
    return subject_id + "||" + canonical_public_key(subject_public_key);
}

/***************************************************************************
  函数名称：to_text
  功    能：将证书序列化为 TXT 格式
  输入参数：无
  返 回 值：完整证书文本
  说    明：保留原有字段名称、顺序、数字标志及起止标记。
***************************************************************************/
std::string certificate_data::to_text() const
{
    std::ostringstream out;
    out << "CERTIFICATE_BEGIN\n";
    out << "SubjectID=" << subject_id << "\n";
    out << "SubjectPublicKeyAlgorithm=" << public_key_algorithm_name(subject_public_key.algorithm) << "\n";
    if (subject_public_key.algorithm == public_key_algorithm::RSA) {
        out << "SubjectRSA_n=" << subject_public_key.rsa.n << "\n";
        out << "SubjectRSA_b=" << subject_public_key.rsa.b << "\n";
    } else {
        out << "SubjectElGamal_p=" << subject_public_key.elgamal.p << "\n";
        out << "SubjectElGamal_g=" << subject_public_key.elgamal.g << "\n";
        out << "SubjectElGamal_y=" << subject_public_key.elgamal.y << "\n";
    }
    out << "IssuerID=" << issuer_id << "\n";
    out << "Flag1=" << static_cast<int>(flag1) << "\n";
    out << "Flag1Meaning=" << signature_algorithm_name(flag1) << "\n";
    out << "Flag2=" << static_cast<int>(flag2) << "\n";
    out << "Flag2Meaning=" << key_usage_name(flag2) << "\n";
    if (flag1 == signature_algorithm_type::RSA) {
        out << "SignatureRSA=" << signature.rsa << "\n";
    } else {
        out << "SignatureElGamal_r=" << signature.elgamal.r << "\n";
        out << "SignatureElGamal_s=" << signature.elgamal.s << "\n";
    }
    out << "CERTIFICATE_END\n";
    return out.str();
}

/***************************************************************************
  函数名称：save_to_file
  功    能：把证书文本写入文件
  输入参数：const std::filesystem::path& path：文件路径；证书路径验证函数中为按根到主体排列的证书数组
  返 回 值：无
  说    明：先创建父目录，再按二进制方式写入文本；打开失败时抛出异常。
***************************************************************************/
void certificate_data::save_to_file(const std::filesystem::path& path) const
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("cannot write certificate: " + path.string());
    }
    out << to_text();
}

/***************************************************************************
  函数名称：from_text
  功    能：从 TXT 文本恢复证书
  输入参数：const std::string& text：待处理的文本
  返 回 值：解析完成的证书数据
  说    明：按 Flag1 选择签名参数结构；本函数只解析，验证需另行调用。
***************************************************************************/
certificate_data certificate_data::from_text(const std::string& text)
{
    const std::map<std::string, std::string> values = parse_key_values(text);
    certificate_data cert;
    cert.subject_id = value_or_throw(values, "SubjectID");
    cert.subject_public_key = parse_subject_public_key(values);
    cert.issuer_id = value_or_throw(values, "IssuerID");
    cert.flag1 = parse_signature_algorithm(value_or_throw(values, "Flag1"));
    cert.flag2 = parse_key_usage(value_or_throw(values, "Flag2"));
    cert.signature.algorithm = cert.flag1;
    if (cert.flag1 == signature_algorithm_type::RSA) {
        cert.signature.rsa = zz_from_string(value_or_throw(values, "SignatureRSA"));
    } else {
        cert.signature.elgamal = elgamal_signature{
            zz_from_string(value_or_throw(values, "SignatureElGamal_r")),
            zz_from_string(value_or_throw(values, "SignatureElGamal_s"))};
    }
    return cert;
}

/***************************************************************************
  函数名称：load_from_file
  功    能：从文件读取并解析证书
  输入参数：const std::filesystem::path& path：文件路径；证书路径验证函数中为按根到主体排列的证书数组
  返 回 值：文件中保存的证书数据
  说    明：读取失败抛出异常，解析规则与 from_text 相同。
***************************************************************************/
certificate_data certificate_data::load_from_file(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot read certificate: " + path.string());
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return from_text(buffer.str());
}

/***************************************************************************
  函数名称：issue_certificate_rsa
  功    能：使用签发者的 RSA 私钥签发证书
  输入参数：const std::string& subject_id：证书主体的身份标识
  const public_key_data& subject_public_key：证书主体的公钥
  const std::string& issuer_id：证书签发者的身份标识
  key_usage_type key_usage：申请或查询的公钥用途
  const rsa_key_pair& issuer_key_pair：签发者的密钥对
  返 回 值：带 RSA 签名的新证书
  说    明：填写主体、公钥、签发者和用途后，对既定载荷签名。
***************************************************************************/
certificate_data issue_certificate_rsa(
    const std::string& subject_id,
    const public_key_data& subject_public_key,
    const std::string& issuer_id,
    key_usage_type key_usage,
    const rsa_key_pair& issuer_key_pair)
{
    certificate_data cert;
    cert.subject_id = subject_id;
    cert.subject_public_key = subject_public_key;
    cert.issuer_id = issuer_id;
    cert.flag1 = signature_algorithm_type::RSA;
    cert.flag2 = key_usage;
    cert.signature.algorithm = signature_algorithm_type::RSA;
    cert.signature.rsa = rsa_sign_message(cert.payload(), issuer_key_pair);
    return cert;
}

/***************************************************************************
  函数名称：issue_certificate_elgamal
  功    能：使用签发者的 ElGamal 私钥签发证书
  输入参数：const std::string& subject_id：证书主体的身份标识
  const public_key_data& subject_public_key：证书主体的公钥
  const std::string& issuer_id：证书签发者的身份标识
  key_usage_type key_usage：申请或查询的公钥用途
  const elgamal_key_pair& issuer_key_pair：签发者的密钥对
  返 回 值：带 ElGamal 签名的新证书
  说    明：填写证书字段后，对既定载荷生成 ElGamal 签名。
***************************************************************************/
certificate_data issue_certificate_elgamal(
    const std::string& subject_id,
    const public_key_data& subject_public_key,
    const std::string& issuer_id,
    key_usage_type key_usage,
    const elgamal_key_pair& issuer_key_pair)
{
    certificate_data cert;
    cert.subject_id = subject_id;
    cert.subject_public_key = subject_public_key;
    cert.issuer_id = issuer_id;
    cert.flag1 = signature_algorithm_type::ELGAMAL;
    cert.flag2 = key_usage;
    cert.signature.algorithm = signature_algorithm_type::ELGAMAL;
    cert.signature.elgamal = elgamal_sign_message(cert.payload(), issuer_key_pair);
    return cert;
}

/***************************************************************************
  函数名称：verify_certificate
  功    能：使用签发者公钥验证证书签名
  输入参数：const certificate_data& certificate：待处理的证书
  const public_key_data& issuer_public_key：用于验签的签发者公钥
  返 回 值：true 为签名通过，false 为不匹配
  说    明：检查签名结构与 Flag1 一致，再按对应算法验证载荷。
***************************************************************************/
bool verify_certificate(const certificate_data& certificate, const public_key_data& issuer_public_key)
{
    if (certificate.signature.algorithm != certificate.flag1) {
        return false;
    }
    if (certificate.flag1 == signature_algorithm_type::RSA) {
        if (issuer_public_key.algorithm != public_key_algorithm::RSA) {
            return false;
        }
        return rsa_verify_message(certificate.payload(), certificate.signature.rsa, issuer_public_key.rsa);
    }
    if (issuer_public_key.algorithm != public_key_algorithm::ELGAMAL) {
        return false;
    }
    return elgamal_verify_message(certificate.payload(), certificate.signature.elgamal, issuer_public_key.elgamal);
}
