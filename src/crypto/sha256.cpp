#include "crypto/sha256.h"
#include <openssl/sha.h>

namespace loki::crypto {
    SHA256::SHA256() : Hash(EVP_sha256()) {}

    ByteArray SHA256::hash(const uint8_t* data, size_t len) {
        return Hash::quick_hash(EVP_sha256(), data, len);
    }

    ByteArray SHA256::hash(const ByteArray& data) {
        return hash(data.data(), data.size());
    }

    ByteArray SHA256::hash(const std::string& data) {
        return hash(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }
}