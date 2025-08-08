#include "crypto/md5.h"
#include <openssl/md5.h>

namespace loki::crypto {
    MD5::MD5(std::string string)
        : Hash(EVP_md5()) {
    }

    ByteArray MD5::hash(const uint8_t* data, size_t len) {
        return Hash::quick_hash(EVP_md5(), data, len);
    }

    ByteArray MD5::hash(const ByteArray& data) {
        return hash(data.data(), data.size());
    }

    ByteArray MD5::hash(const std::string& data) {
        return hash(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }
}