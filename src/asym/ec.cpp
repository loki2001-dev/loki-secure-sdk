#include "ec.h"
#include "core/exception.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/obj_mac.h>

#include <memory>
#include <string>

namespace loki::crypto {

    struct EC::Impl {
        EVP_PKEY* pkey = nullptr;

        Impl() = default;
        ~Impl() {
            if (pkey) EVP_PKEY_free(pkey);
        }
    };

    EC::EC()
            : _pimpl(std::make_unique<Impl>()) {

    }

    EC::~EC() = default;

    static int nid_from_curve(EC::Curve curve) {
        switch (curve) {
            case EC::Curve::SECP256R1: return NID_X9_62_prime256v1;
            case EC::Curve::SECP384R1: return NID_secp384r1;
            case EC::Curve::SECP521R1: return NID_secp521r1;
            default: throw core::CryptoException("Unsupported EC curve");
        }
    }

    void EC::generate_key(Curve curve) {
        int nid = nid_from_curve(curve);
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        if (!ctx) {
            throw core::CryptoException("Failed to create EVP_PKEY_CTX");
        }

        if (EVP_PKEY_paramgen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_paramgen_init failed");
        }

        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed");
        }

        EVP_PKEY* params = nullptr;
        if (EVP_PKEY_paramgen(ctx, &params) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_paramgen failed");
        }
        EVP_PKEY_CTX_free(ctx);

        ctx = EVP_PKEY_CTX_new(params, nullptr);
        EVP_PKEY_free(params);
        if (!ctx) {
            throw core::CryptoException("Failed to create EVP_PKEY_CTX for keygen");
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_keygen_init failed");
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_keygen failed");
        }
        EVP_PKEY_CTX_free(ctx);

        if (_pimpl->pkey) {
            EVP_PKEY_free(_pimpl->pkey);
        }
        _pimpl->pkey = pkey;
    }

    void EC::load_private_key(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio) {
            throw core::CryptoException("Failed to create BIO for private key");
        }

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) {
            throw core::CryptoException("Failed to read EC private key PEM");
        }

        if (_pimpl->pkey) {
            EVP_PKEY_free(_pimpl->pkey);
        }
        _pimpl->pkey = pkey;
    }

    void EC::load_public_key(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio) {
            throw core::CryptoException("Failed to create BIO for public key");
        }

        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) {
            throw core::CryptoException("Failed to read EC public key PEM");
        }

        if (_pimpl->pkey) {
            EVP_PKEY_free(_pimpl->pkey);
        }
        _pimpl->pkey = pkey;
    }

    std::string EC::export_private_key() const {
        if (!_pimpl->pkey) {
            throw core::CryptoException("Private key not loaded");
        }

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw core::CryptoException("Failed to create BIO");
        }

        if (PEM_write_bio_PrivateKey(bio, _pimpl->pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            BIO_free(bio);
            throw core::CryptoException("Failed to write private key PEM");
        }

        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len);
        BIO_free(bio);
        return pem;
    }

    std::string EC::export_public_key() const {
        if (!_pimpl->pkey) {
            throw core::CryptoException("Public key not loaded");
        }

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw core::CryptoException("Failed to create BIO");
        }

        if (PEM_write_bio_PUBKEY(bio, _pimpl->pkey) != 1) {
            BIO_free(bio);
            throw core::CryptoException("Failed to write public key PEM");
        }

        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len);
        BIO_free(bio);
        return pem;
    }

    ByteArray EC::sign(const ByteArray& message, const std::string& hash) const {
        if (!_pimpl->pkey) {
            throw core::CryptoException("Key not loaded");
        }

        const EVP_MD* md = nullptr;
        if (hash == "SHA256") {
            md = EVP_sha256();
        } else if (hash == "SHA384") {
            md = EVP_sha384();
        } else if (hash == "SHA512") {
            md = EVP_sha512();
        } else {
            throw core::CryptoException("Unsupported hash algorithm");
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw core::CryptoException("Failed to create EVP_MD_CTX");
        }

        if (EVP_DigestSignInit(ctx, nullptr, md, nullptr, _pimpl->pkey) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestSignInit failed");
        }

        if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestSignUpdate failed");
        }

        size_t siglen = 0;
        if (EVP_DigestSignFinal(ctx, nullptr, &siglen) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestSignFinal sizing failed");
        }

        ByteArray signature(siglen);
        if (EVP_DigestSignFinal(ctx, signature.data(), &siglen) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestSignFinal failed");
        }

        signature.resize(siglen);
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    bool EC::verify(const ByteArray& message, const ByteArray& signature, const std::string& hash) const {
        if (!_pimpl->pkey) {
            throw core::CryptoException("Key not loaded");
        }

        const EVP_MD* md = nullptr;
        if (hash == "SHA256") {
            md = EVP_sha256();
        } else if (hash == "SHA384") {
            md = EVP_sha384();
        } else if (hash == "SHA512") {
            md = EVP_sha512();
        } else {
            throw core::CryptoException("Unsupported hash algorithm");
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw core::CryptoException("Failed to create EVP_MD_CTX");
        }

        if (EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, _pimpl->pkey) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestVerifyInit failed");
        }

        if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestVerifyUpdate failed");
        }

        int ret = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
        EVP_MD_CTX_free(ctx);
        return ret == 1;
    }

} // namespace loki::crypto