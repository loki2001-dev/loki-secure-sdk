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

#include "cipher.h"

namespace loki::crypto {

    class ChaCha20 : public Cipher {
    public:
        static constexpr size_t KEY_SIZE = 32;      // 256 bits
        static constexpr size_t IV_SIZE = 16;       // 128 bits (12-byte nonce + 4-byte counter)
        static constexpr size_t NONCE_SIZE = 12;    // 96 bits (part of IV)

        ChaCha20();
        ~ChaCha20() override = default;

        void generate_key();

        static ByteArray encrypt(const ByteArray& plaintext, const ByteArray& key, const ByteArray& iv_or_nonce);
        static ByteArray decrypt(const ByteArray& ciphertext, const ByteArray& key, const ByteArray& iv_or_nonce);

    private:
        const EVP_CIPHER* get_cipher() const override;
    };

} // namespace loki::crypto