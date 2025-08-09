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

#include "crypto/signature.h"
#include "core/exception.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ossl_typ.h>

#include <memory>
#include <sstream>
#include <fstream>
#include <iomanip>

namespace loki::crypto {

    namespace {
        using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
        using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

        EVP_PKEY* load_private_key(const std::string& pem) {
            BIO_ptr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
            if (!bio) throw core::CryptoException("Failed to create BIO for private key");

            EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
            if (!pkey) throw core::CryptoException("Failed to parse private key");
            return pkey;
        }

        EVP_PKEY* load_public_key(const std::string& pem) {
            BIO_ptr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
            if (!bio) throw core::CryptoException("Failed to create BIO for public key");

            EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
            if (!pkey) throw core::CryptoException("Failed to parse public key");
            return pkey;
        }
    }

    Signature::Signature(Algorithm algorithm, Hash hash)
        : _algorithm(algorithm),
        _hash(hash) {

    }

    std::string Signature::load_pem_file(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::in);
        if (!file.is_open()) {
            return {};
        }
        std::stringstream ss;
        ss << file.rdbuf();
        return ss.str();
    }

    void Signature::set_private_key(const std::string& pem) {
        if (_private_key) {
            EVP_PKEY_free(_private_key);
        }
        _private_key = load_private_key(pem);
    }

    void Signature::set_public_key(const std::string& pem) {
        if (_public_key) {
            EVP_PKEY_free(_public_key);
        }
        _public_key = load_public_key(pem);
    }

    ByteArray Signature::sign(const ByteArray& message) {
        if (!_private_key) {
            throw core::CryptoException("Private key not set");
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw core::OutOfMemoryException("Failed to allocate EVP_MD_CTX");
        }

        ByteArray signature;
        size_t siglen = 0;

        do {
            if (EVP_DigestSignInit(ctx, nullptr, get_md(), nullptr, _private_key) != 1) {
                break;
            }

            if (_algorithm == Algorithm::RSA_PSS) {
                EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(_private_key, nullptr);
                EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
            }

            if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) != 1) {
                break;
            }

            // Verifiy Signed Length
            if (EVP_DigestSignFinal(ctx, nullptr, &siglen) != 1) {
                break;
            }

            signature.resize(siglen);
            if (EVP_DigestSignFinal(ctx, signature.data(), &siglen) != 1) {
                break;
            }

            signature.resize(siglen);
            EVP_MD_CTX_free(ctx);
            return signature;
        } while (false);

        EVP_MD_CTX_free(ctx);
        throw core::CryptoException("Failed to sign message");
    }

    bool Signature::verify(const ByteArray& message, const ByteArray& sig) {
        if (!_public_key) {
            throw core::CryptoException("Public key not set");
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw core::OutOfMemoryException("Failed to allocate EVP_MD_CTX");
        }

        bool result = false;

        do {
            if (EVP_DigestVerifyInit(ctx, nullptr, get_md(), nullptr, _public_key) != 1) {
                break;
            }

            if (_algorithm == Algorithm::RSA_PSS) {
                EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(_public_key, nullptr);
                EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING);
            }

            if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) != 1) {
                break;
            }

            int ok = EVP_DigestVerifyFinal(ctx, sig.data(), sig.size());
            result = (ok == 1);
        } while (false);

        EVP_MD_CTX_free(ctx);
        return result;
    }

    ByteArray Signature::sign(Algorithm algo, Hash hash, const std::string& private_key_pem, const ByteArray& message) {
        Signature s(algo, hash);
        s.set_private_key(private_key_pem);
        return s.sign(message);
    }

    bool Signature::verify(Algorithm algo, Hash hash, const std::string& public_key_pem, const ByteArray& message, const ByteArray& sig) {
        Signature s(algo, hash);
        s.set_public_key(public_key_pem);
        return s.verify(message, sig);
    }

    const EVP_MD* Signature::get_md() const {
        switch (_hash) {
            case Hash::SHA256: return EVP_sha256();
            case Hash::SHA384: return EVP_sha384();
            case Hash::SHA512: return EVP_sha512();
        }
        return nullptr;
    }

    std::string Signature::to_hex_string(const ByteArray& data) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (auto b : data) {
            oss << std::setw(2) << static_cast<int>(b);
        }
        return oss.str();
    }

} // namespace loki::crypto