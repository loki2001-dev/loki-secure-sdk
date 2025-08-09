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
#include <openssl/ossl_typ.h>
#include <string>

namespace loki::crypto {

    class Signature {
    public:
        enum class Algorithm {
            RSA_PSS,
            RSA_PKCS1,
            ECDSA
        };

        enum class Hash {
            SHA256,
            SHA384,
            SHA512
        };

    public:
        explicit Signature(Algorithm algorithm = Algorithm::RSA_PSS, Hash hash = Hash::SHA256);
        ~Signature() = default;

        void set_private_key(const std::string& pem);
        void set_public_key(const std::string& pem);

        ByteArray sign(const ByteArray& message);
        bool verify(const ByteArray& message, const ByteArray& signature);

        static ByteArray sign(Algorithm algo, Hash hash, const std::string& private_key_pem, const ByteArray& message);
        static bool verify(Algorithm algo, Hash hash, const std::string& public_key_pem, const ByteArray& message, const ByteArray& signature);

        static std::string load_pem_file(const std::string& filepath);

        std::string to_hex_string(const ByteArray& data);

    private:
        Algorithm _algorithm;
        Hash _hash;
        EVP_PKEY* _private_key = nullptr;
        EVP_PKEY* _public_key = nullptr;

        const EVP_MD* get_md() const;
    };

} // namespace loki::crypto