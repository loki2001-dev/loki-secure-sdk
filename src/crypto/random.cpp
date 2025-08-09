/*
 * Copyright 2025 loki2001-dev
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "crypto/random.h"
#include "core/exception.h"

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <sstream>
#include <iomanip>

namespace loki::crypto {

    ByteArray Random::bytes(size_t count) {
        ByteArray buffer(count);
        if (!bytes(buffer.data(), count)) {
            throw core::CryptoException("Failed to generate random bytes");
        }
        return buffer;
    }

    bool Random::bytes(uint8_t* buffer, size_t count) {
        return RAND_bytes(buffer, static_cast<int>(count)) == 1;
    }

    uint32_t Random::uint32() {
        uint32_t value;
        if (!bytes(reinterpret_cast<uint8_t*>(&value), sizeof(value))) {
            throw core::CryptoException("Failed to generate uint32");
        }
        return value;
    }

    uint64_t Random::uint64() {
        uint64_t value;
        if (!bytes(reinterpret_cast<uint8_t*>(&value), sizeof(value))) {
            throw core::CryptoException("Failed to generate uint64");
        }
        return value;
    }

    int32_t Random::int32(int32_t min, int32_t max) {
        if (min >= max) throw core::InvalidArgumentException("min must be less than max");
        auto range = static_cast<uint32_t>(max - min + 1);
        return static_cast<int32_t>(min + (uint32() % range));
    }

    uint32_t Random::uint32(uint32_t min, uint32_t max) {
        if (min >= max) throw core::InvalidArgumentException("min must be less than max");
        uint32_t range = max - min + 1;
        return min + (uint32() % range);
    }

    std::string Random::string(size_t length, const std::string& charset) {
        if (charset.empty()) throw core::InvalidArgumentException("Charset must not be empty");

        std::string result;
        result.reserve(length);

        for (size_t i = 0; i < length; ++i) {
            uint32_t index = uint32(0, static_cast<uint32_t>(charset.size() - 1));
            result += charset[index];
        }

        return result;
    }

    std::string Random::hex_string(size_t length) {
        ByteArray data = bytes(length);
        std::ostringstream oss;
        for (auto b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return oss.str();
    }

    std::string Random::base64_string(size_t length) {
        ByteArray data = bytes(length);

        static const char* base64_chars =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";

        std::string encoded;
        int val = 0, valb = -6;

        for (uint8_t c : data) {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }

        if (valb > -6) {
            encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
        }

        while (encoded.size() % 4) {
            encoded.push_back('=');
        }

        return encoded;
    }

    bool Random::seed(const ByteArray& seed) {
        RAND_seed(seed.data(), static_cast<int>(seed.size()));
        return RAND_status() == 1;
    }

    bool Random::add_entropy(const ByteArray& data) {
        RAND_add(data.data(), static_cast<int>(data.size()), (double)data.size());
        return true;
    }

    bool Random::is_seeded() {
        return RAND_status() == 1;
    }

} // namespace loki::crypto