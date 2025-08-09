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