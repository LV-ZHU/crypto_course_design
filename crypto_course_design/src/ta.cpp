#include "ta.h"

#include <stdexcept>


/***************************************************************************
  函数名称：create_rsa
  功    能：创建使用 RSA 签名的可信机构
  输入参数：const std::string& id：当前机构或用户的身份标识
  long rsa_prime_bits：RSA 每个素数 p、q 的位数
  返 回 值：RSA 可信机构对象
  说    明：身份不能为空；根据指定素数位数生成机构密钥。
***************************************************************************/
trusted_authority trusted_authority::create_rsa(const std::string& id, long rsa_prime_bits)
{
    if (id.empty()) {
        throw std::invalid_argument("TA ID cannot be empty");
    }
    trusted_authority authority;
    authority.id_ = id;
    authority.signature_algorithm_ = signature_algorithm_type::RSA;
    authority.rsa_key_pair_ = generate_rsa_key_pair(rsa_prime_bits);
    return authority;
}

/***************************************************************************
  函数名称：create_elgamal
  功    能：创建使用 ElGamal 签名的可信机构
  输入参数：const std::string& id：当前机构或用户的身份标识
  long elgamal_prime_bits：ElGamal 模数 p 的位数
  返 回 值：ElGamal 可信机构对象
  说    明：身份不能为空；生成安全素数及机构密钥。
***************************************************************************/
trusted_authority trusted_authority::create_elgamal(const std::string& id, long elgamal_prime_bits)
{
    if (id.empty()) {
        throw std::invalid_argument("TA ID cannot be empty");
    }
    trusted_authority authority;
    authority.id_ = id;
    authority.signature_algorithm_ = signature_algorithm_type::ELGAMAL;
    authority.elgamal_key_pair_ = generate_elgamal_key_pair(elgamal_prime_bits);
    return authority;
}

/***************************************************************************
  函数名称：from_elgamal_key_pair
  功    能：用已有 ElGamal 密钥创建可信机构
  输入参数：const std::string& id：当前机构或用户的身份标识
  const elgamal_key_pair& key_pair：包含公钥和私钥的密钥对
  返 回 值：复用指定密钥的机构对象
  说    明：供测试复用生成耗时较长的安全素数参数。
***************************************************************************/
trusted_authority trusted_authority::from_elgamal_key_pair(
    const std::string& id,
    const elgamal_key_pair& key_pair)
{
    if (id.empty()) {
        throw std::invalid_argument("TA ID cannot be empty");
    }
    trusted_authority authority;
    authority.id_ = id;
    authority.signature_algorithm_ = signature_algorithm_type::ELGAMAL;
    authority.elgamal_key_pair_ = key_pair;
    return authority;
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
certificate_data trusted_authority::issue_certificate(
    const std::string& subject_id,
    const public_key_data& subject_public_key,
    key_usage_type key_usage) const
{
    if (signature_algorithm_ == signature_algorithm_type::RSA) {
        return issue_certificate_rsa(subject_id, subject_public_key, id_, key_usage, rsa_key_pair_);
    }
    return issue_certificate_elgamal(subject_id, subject_public_key, id_, key_usage, elgamal_key_pair_);
}

/***************************************************************************
  函数名称：id
  功    能：取得当前对象的身份标识
  输入参数：无
  返 回 值：身份字符串的只读引用
  说    明：引用的有效期与当前对象一致。
***************************************************************************/
const std::string& trusted_authority::id() const
{
    return id_;
}

/***************************************************************************
  函数名称：get_public_key
  功    能：取得可信机构用于验证签名的公钥
  输入参数：无
  返 回 值：包含算法标记的通用公钥
  说    明：根据机构的签名算法返回对应公钥。
***************************************************************************/
public_key_data trusted_authority::get_public_key() const
{
    if (signature_algorithm_ == signature_algorithm_type::RSA) {
        return public_key_data::from_rsa(rsa_key_pair_.public_key);
    }
    return public_key_data::from_elgamal(elgamal_key_pair_.public_key);
}

/***************************************************************************
  函数名称：get_signature_algorithm
  功    能：取得可信机构使用的签名算法
  输入参数：无
  返 回 值：签名算法枚举值
  说    明：直接读取初始化时设置的算法标记。
***************************************************************************/
signature_algorithm_type trusted_authority::get_signature_algorithm() const
{
    return signature_algorithm_;
}


/***************************************************************************
  函数名称：trusted_authority
  功    能：构造待初始化的可信机构对象
  输入参数：无
  返 回 值：无，构造函数
  说    明：构造函数为私有，由工厂函数设置机构身份和密钥。
***************************************************************************/
trusted_authority::trusted_authority()
{
}
