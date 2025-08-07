#pragma once

#include "../fwd.h"

namespace loki::crypto {
    class Random {
    public:
        static ByteArray bytes(size_t count);
        static bool bytes(uint8_t* buffer, size_t count);

        static uint32_t uint32();
        static uint64_t uint64();
        static int32_t int32(int32_t min, int32_t max);
        static uint32_t uint32(uint32_t min, uint32_t max);

        static std::string string(size_t length, const std::string& charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        static std::string hex_string(size_t length);
        static std::string base64_string(size_t length);

        static bool seed(const ByteArray& seed);
        static bool add_entropy(const ByteArray& data);

        static bool is_seeded();
    };
}