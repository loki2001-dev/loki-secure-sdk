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

#include "rsa.h"
#include "core/exception.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <memory>
#include <string>
#include <vector>

namespace loki::crypto {

    struct RSA::Impl {
        EVP_PKEY* pkey = nullptr;

        Impl() = default;

        ~Impl() {
            if (pkey) {
                EVP_PKEY_free(pkey);
            }
        }
    };

    RSA::RSA()
        : _pimpl(std::make_unique<Impl>()) {

    }

    RSA::~RSA() = default;

    void RSA::generate_key(size_t bits) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
            throw core::CryptoException("Failed to create EVP_PKEY_CTX");
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_keygen_init failed");
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, static_cast<int>(bits)) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_keygen failed");
        }
        EVP_PKEY_CTX_free(ctx);

        if (_pimpl->pkey) {
            EVP_PKEY_free(_pimpl->pkey);
        }
        _pimpl->pkey = pkey;
    }

    void RSA::load_private_key(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio) {
            throw core::CryptoException("Failed to create BIO for private key");
        }

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) {
            throw core::CryptoException("Failed to read private key PEM");
        }

        if (_pimpl->pkey) {
            EVP_PKEY_free(_pimpl->pkey);
        }
        _pimpl->pkey = pkey;
    }

    void RSA::load_public_key(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio) {
            throw core::CryptoException("Failed to create BIO for public key");
        }

        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) {
            throw core::CryptoException("Failed to read public key PEM");
        }

        if (_pimpl->pkey) {
            EVP_PKEY_free(_pimpl->pkey);
        }
        _pimpl->pkey = pkey;
    }

    std::string RSA::export_private_key() const {
        if (!_pimpl->pkey) {
            throw core::CryptoException("Private key not loaded");
        }

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw core::CryptoException("Failed to create BIO");
        }

        if (PEM_write_bio_PrivateKey(bio, _pimpl->pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            BIO_free(bio);
            throw core::CryptoException("Failed to write private key PEM");
        }

        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len);
        BIO_free(bio);
        return pem;
    }

    std::string RSA::export_public_key() const {
        if (!_pimpl->pkey) {
            throw core::CryptoException("Public key not loaded");
        }

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw core::CryptoException("Failed to create BIO");
        }

        if (PEM_write_bio_PUBKEY(bio, _pimpl->pkey) != 1) {
            BIO_free(bio);
            throw core::CryptoException("Failed to write public key PEM");
        }

        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len);
        BIO_free(bio);
        return pem;
    }

    ByteArray RSA::encrypt(const ByteArray& plaintext, Padding padding) const {
        if (!_pimpl->pkey) {
            throw core::CryptoException("Key not loaded");
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(_pimpl->pkey, nullptr);
        if (!ctx) {
            throw core::CryptoException("Failed to create EVP_PKEY_CTX");
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_encrypt_init failed");
        }

        switch (padding) {
            case Padding::PKCS1:
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
                break;
            case Padding::PSS:
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING);
                break;
            case Padding::OAEP:
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
                break;
        }

        size_t outlen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_encrypt sizing failed");
        }

        ByteArray ciphertext(outlen);
        if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_encrypt failed");
        }

        ciphertext.resize(outlen);
        EVP_PKEY_CTX_free(ctx);
        return ciphertext;
    }

    ByteArray RSA::decrypt(const ByteArray& ciphertext, Padding padding) const {
        if (!_pimpl->pkey) {
            throw core::CryptoException("Key not loaded");
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(_pimpl->pkey, nullptr);
        if (!ctx) {
            throw core::CryptoException("Failed to create EVP_PKEY_CTX");
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_decrypt_init failed");
        }

        switch (padding) {
            case Padding::PKCS1:
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
                break;
            case Padding::PSS:
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING);
                break;
            case Padding::OAEP:
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
                break;
        }

        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_decrypt sizing failed");
        }

        ByteArray plaintext(outlen);
        if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw core::CryptoException("EVP_PKEY_decrypt failed");
        }

        plaintext.resize(outlen);
        EVP_PKEY_CTX_free(ctx);
        return plaintext;
    }

    ByteArray RSA::sign(const ByteArray& message, Padding padding, const std::string& hash) const {
        if (!_pimpl->pkey) {
            throw core::CryptoException("Key not loaded");
        }

        const EVP_MD* md = nullptr;
        if (hash == "SHA256") {
            md = EVP_sha256();
        } else if (hash == "SHA384") {
            md = EVP_sha384();
        } else if (hash == "SHA512") {
            md = EVP_sha512();
        } else {
            throw core::CryptoException("Unsupported hash algorithm");
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw core::CryptoException("Failed to create EVP_MD_CTX");
        }

        if (EVP_DigestSignInit(ctx, nullptr, md, nullptr, _pimpl->pkey) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestSignInit failed");
        }

        if (padding == Padding::PSS) {
            EVP_PKEY_CTX* pkey_ctx = EVP_MD_CTX_pkey_ctx(ctx);
            if (pkey_ctx && EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
                EVP_MD_CTX_free(ctx);
                throw core::CryptoException("Failed to set RSA PSS padding");
            }
        } else if (padding == Padding::PKCS1) {
            EVP_PKEY_CTX* pkey_ctx = EVP_MD_CTX_pkey_ctx(ctx);
            if (pkey_ctx && EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0) {
                EVP_MD_CTX_free(ctx);
                throw core::CryptoException("Failed to set RSA PKCS1 padding");
            }
        } else {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("Unsupported padding for sign");
        }

        if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestSignUpdate failed");
        }

        size_t siglen = 0;
        if (EVP_DigestSignFinal(ctx, nullptr, &siglen) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestSignFinal sizing failed");
        }

        ByteArray signature(siglen);
        if (EVP_DigestSignFinal(ctx, signature.data(), &siglen) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestSignFinal failed");
        }

        signature.resize(siglen);
        EVP_MD_CTX_free(ctx);
        return signature;
    }

    bool RSA::verify(const ByteArray& message, const ByteArray& signature, Padding padding, const std::string& hash) const {
        if (!_pimpl->pkey) {
            throw core::CryptoException("Key not loaded");
        }

        const EVP_MD* md = nullptr;
        if (hash == "SHA256") {
            md = EVP_sha256();
        } else if (hash == "SHA384") {
            md = EVP_sha384();
        } else if (hash == "SHA512") {
            md = EVP_sha512();
        } else {
            throw core::CryptoException("Unsupported hash algorithm");
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) {
            throw core::CryptoException("Failed to create EVP_MD_CTX");
        }

        if (EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, _pimpl->pkey) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestVerifyInit failed");
        }

        if (padding == Padding::PSS) {
            EVP_PKEY_CTX* pkey_ctx = EVP_MD_CTX_pkey_ctx(ctx);
            if (pkey_ctx && EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0) {
                EVP_MD_CTX_free(ctx);
                throw core::CryptoException("Failed to set RSA PSS padding");
            }
        } else if (padding == Padding::PKCS1) {
            EVP_PKEY_CTX* pkey_ctx = EVP_MD_CTX_pkey_ctx(ctx);
            if (pkey_ctx && EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0) {
                EVP_MD_CTX_free(ctx);
                throw core::CryptoException("Failed to set RSA PKCS1 padding");
            }
        } else {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("Unsupported padding for verify");
        }

        if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) <= 0) {
            EVP_MD_CTX_free(ctx);
            throw core::CryptoException("EVP_DigestVerifyUpdate failed");
        }

        int ret = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
        EVP_MD_CTX_free(ctx);
        return ret == 1;
    }

} // namespace loki::crypto