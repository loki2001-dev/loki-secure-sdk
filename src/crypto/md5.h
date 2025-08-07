#pragma once

#include "hash.h"

namespace loki::crypto {
    class MD5 : public Hash {
    public:
        static constexpr size_t DIGEST_SIZE = 16;

        MD5();
        ~MD5() override = default;

        static ByteArray hash(const uint8_t* data, size_t len);
        static ByteArray hash(const ByteArray& data);
        static ByteArray hash(const std::string& data);
    };
}