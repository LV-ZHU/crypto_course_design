#include "user.h"

#include "pki.h"

#include <stdexcept>
#include <utility>


/***************************************************************************
  函数名称：pki_user
  功    能：创建拥有独立加密和签名密钥的用户
  输入参数：std::string id：当前机构或用户的身份标识
  long rsa_prime_bits：RSA 每个素数 p、q 的位数
  返 回 值：无，构造函数
  说    明：两套 RSA 密钥分别生成，身份标识为空时抛出异常。
***************************************************************************/
pki_user::pki_user(std::string id, long rsa_prime_bits)
    : id_(id),
      encryption_key_pair_(generate_rsa_key_pair(rsa_prime_bits)),
      signature_key_pair_(generate_rsa_key_pair(rsa_prime_bits))
{
    if (id_.empty()) {
        throw std::invalid_argument("user ID cannot be empty");
    }
}

/***************************************************************************
  函数名称：request_certificates
  功    能：向 CA 申请加密与签名两种证书
  输入参数：const certificate_authority& authority：接受证书申请的 CA
  返 回 值：无
  说    明：两种证书对应不同公钥，保存证书后更新已申请标记。
***************************************************************************/
void pki_user::request_certificates(const certificate_authority& authority)
{
    encryption_certificate_ = authority.issue_certificate(
        id_, public_key_data::from_rsa(encryption_key_pair_.public_key), key_usage_type::ENCRYPTION);
    signature_certificate_ = authority.issue_certificate(
        id_, public_key_data::from_rsa(signature_key_pair_.public_key), key_usage_type::SIGNATURE);
    has_encryption_certificate_ = true;
    has_signature_certificate_ = true;
}

/***************************************************************************
  函数名称：id
  功    能：取得当前对象的身份标识
  输入参数：无
  返 回 值：身份字符串的只读引用
  说    明：引用的有效期与当前对象一致。
***************************************************************************/
const std::string& pki_user::id() const
{
    return id_;
}

/***************************************************************************
  函数名称：encryption_public_key
  功    能：取得用户的加密公钥
  输入参数：无
  返 回 值：加密公钥的只读引用
  说    明：对应加密密钥对，不用于消息签名。
***************************************************************************/
const rsa_public_key& pki_user::encryption_public_key() const
{
    return encryption_key_pair_.public_key;
}

/***************************************************************************
  函数名称：signature_public_key
  功    能：取得用户的签名公钥
  输入参数：无
  返 回 值：签名公钥的只读引用
  说    明：对应签名密钥对，供接收方验证消息。
***************************************************************************/
const rsa_public_key& pki_user::signature_public_key() const
{
    return signature_key_pair_.public_key;
}

/***************************************************************************
  函数名称：certificate
  功    能：取得对象持有的证书
  输入参数：key_usage_type key_usage：申请或查询的公钥用途
  返 回 值：证书的只读引用
  说    明：用户对象按用途选择证书，尚未申请对应证书时抛出异常。
***************************************************************************/
const certificate_data& pki_user::certificate(key_usage_type key_usage) const
{
    if (key_usage == key_usage_type::ENCRYPTION) {
        if (!has_encryption_certificate_) {
            throw std::runtime_error("encryption certificate has not been issued for " + id_);
        }
        return encryption_certificate_;
    }
    if (!has_signature_certificate_) {
        throw std::runtime_error("signature certificate has not been issued for " + id_);
    }
    return signature_certificate_;
}

/***************************************************************************
  函数名称：sign_message
  功    能：使用用户的签名私钥签署消息
  输入参数：const std::string& message：待加密、签名或验证的消息；指针参数用于输出正文
  返 回 值：RSA 签名整数
  说    明：调用统一 RSA 消息签名函数。
***************************************************************************/
big_integer pki_user::sign_message(const std::string& message) const
{
    return rsa_sign_message(message, signature_key_pair_);
}

/***************************************************************************
  函数名称：decrypt_text
  功    能：使用用户的加密私钥解密密文
  输入参数：const std::vector<big_integer>& cipher_blocks：按顺序排列的密文块
  返 回 值：恢复的文本
  说    明：调用 RSA 分块解密函数，密文必须对应当前用户的加密公钥。
***************************************************************************/
std::string pki_user::decrypt_text(const std::vector<big_integer>& cipher_blocks) const
{
    return rsa_decrypt_text(cipher_blocks, encryption_key_pair_);
}
