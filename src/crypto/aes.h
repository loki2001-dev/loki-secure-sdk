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
    class AES : public Cipher {
    public:
        enum class KeySize {
            AES_128 = 128,
            AES_192 = 192,
            AES_256 = 256
        };

        enum class Mode {
            ECB,
            CBC,
            CFB,
            OFB,
            GCM
        };

    private:
        KeySize _key_size;
        Mode _mode;

    public:
        explicit AES(KeySize key_size = KeySize::AES_256, Mode mode = Mode::CBC);
        ~AES() override = default;

        void generate_key();

        static ByteArray encrypt_cbc(const ByteArray& plaintext, const ByteArray& key, const ByteArray& iv);
        static ByteArray decrypt_cbc(const ByteArray& ciphertext, const ByteArray& key, const ByteArray& iv);

        static ByteArray encrypt_gcm(const ByteArray& plaintext, const ByteArray& key, const ByteArray& iv, ByteArray& tag);
        static ByteArray decrypt_gcm(const ByteArray& ciphertext, const ByteArray& key, const ByteArray& iv, const ByteArray& tag);

    private:
        static const EVP_CIPHER* select_cipher(KeySize key_size, Mode mode);
        const EVP_CIPHER* get_cipher() const override;
    };
}