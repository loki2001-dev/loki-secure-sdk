#pragma once

#include "hash.h"

namespace loki::crypto {
    class SHA256 : public Hash {
    public:
        static constexpr size_t DIGEST_SIZE = 32;

        SHA256();
        ~SHA256() override = default;

        static ByteArray hash(const uint8_t* data, size_t len);
        static ByteArray hash(const ByteArray& data);
        static ByteArray hash(const std::string& data);
    };
}