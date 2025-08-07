#include "crypto/hash.h"
#include "core/exception.h"

namespace loki::crypto {
    Hash::Hash(const EVP_MD* md)
        : _md(md) {
        if (!_md) {
            throw core::InvalidArgumentException("Invalid message digest");
        }

        _ctx.reset(EVP_MD_CTX_new());
        if (!_ctx) {
            throw core::OutOfMemoryException("Failed to create MD context");
        }

        if (EVP_DigestInit_ex(_ctx.get(), _md, nullptr) != 1) {
            throw core::CryptoException("Failed to initialize digest: " + openssl_wrapper::get_last_error());
        }
    }

    void Hash::update(const uint8_t* data, size_t len) {
        if (!data || len == 0) return;

        if (EVP_DigestUpdate(_ctx.get(), data, len) != 1) {
            throw core::CryptoException("Failed to update digest: " + openssl_wrapper::get_last_error());
        }
    }

    void Hash::update(const ByteArray& data) {
        update(data.data(), data.size());
    }

    void Hash::update(const std::string& data) {
        update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }

    ByteArray Hash::finalize() {
        ByteArray result(EVP_MD_size(_md));
        unsigned int len = 0;

        if (EVP_DigestFinal_ex(_ctx.get(), result.data(), &len) != 1) {
            throw core::CryptoException("Failed to finalize digest: " + openssl_wrapper::get_last_error());
        }

        result.resize(len);
        reset();
        return result;
    }

    ByteArray Hash::hash(const uint8_t* data, size_t len) {
        update(data, len);
        return finalize();
    }

    ByteArray Hash::hash(const ByteArray& data) {
        return hash(data.data(), data.size());
    }

    ByteArray Hash::hash(const std::string& data) {
        return hash(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }

    void Hash::reset() {
        if (EVP_DigestInit_ex(_ctx.get(), _md, nullptr) != 1) {
            throw core::CryptoException("Failed to reset digest: " + openssl_wrapper::get_last_error());
        }
    }

    size_t Hash::digest_size() const {
        return EVP_MD_size(_md);
    }

    ByteArray Hash::quick_hash(const EVP_MD* md, const uint8_t* data, size_t len) {
        Hash hasher(md);
        return hasher.hash(data, len);
    }

    ByteArray Hash::quick_hash(const EVP_MD* md, const ByteArray& data) {
        return quick_hash(md, data.data(), data.size());
    }

    ByteArray Hash::quick_hash(const EVP_MD* md, const std::string& data) {
        return quick_hash(md, reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }
}