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