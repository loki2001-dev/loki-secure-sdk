
#include "crypto/sha512.h"
#include <openssl/sha.h>

namespace loki::crypto {
    SHA512::SHA512() : Hash(EVP_sha512()) {}

    ByteArray SHA512::hash(const uint8_t* data, size_t len) {
        return Hash::quick_hash(EVP_sha512(), data, len);
    }

    ByteArray SHA512::hash(const ByteArray& data) {
        return hash(data.data(), data.size());
    }

    ByteArray SHA512::hash(const std::string& data) {
        return hash(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }
}