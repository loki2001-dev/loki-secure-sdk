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
#include "../config.h"
#include "../openssl_wrapper.h"

namespace loki::crypto {
    class Cipher {
    protected:
        openssl_wrapper::secure_ptr::EVP_CIPHER_CTX_ptr _ctx;
        const EVP_CIPHER* _cipher;
        ByteArray _key;
        ByteArray _iv;

    public:
        explicit Cipher(const EVP_CIPHER* cipher);
        virtual ~Cipher() = default;
        virtual const EVP_CIPHER* get_cipher() const = 0;

        Cipher(const Cipher&) = delete;
        Cipher& operator=(const Cipher&) = delete;
        Cipher(Cipher&&) = default;
        Cipher& operator=(Cipher&&) = default;

        void set_key(const ByteArray& key);
        void set_iv(const ByteArray& iv);
        void generate_iv();

        ByteArray get_key() const { return _key; }
        ByteArray get_iv() const { return _iv; }

        ByteArray encrypt(const ByteArray& plaintext);
        ByteArray decrypt(const ByteArray& ciphertext);

        size_t key_size() const;
        size_t iv_size() const;
        size_t block_size() const;

        void reset();
    };
}