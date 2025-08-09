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

#include "fwd.h"
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/aes.h>

namespace loki::openssl_wrapper {
    bool initialize();
    void cleanup() noexcept;

    std::string get_last_error();
    void clear_errors();

    bool random_bytes(uint8_t* buf, size_t len);
    bool random_pseudo_bytes(uint8_t* buf, size_t len);

    void secure_clear(void* ptr, size_t len);

    std::string get_version();
    long get_version_number();

    namespace secure_ptr {
        template<typename T, void(*Deleter)(T*)>
        class unique_ptr {
        private:
            T* _ptr;

        public:
            explicit unique_ptr(T* ptr = nullptr)
                : _ptr(ptr) {

            }

            ~unique_ptr() {
                if (_ptr) {
                    Deleter(_ptr);
                }
            }

            unique_ptr(const unique_ptr&) = delete;
            unique_ptr& operator=(const unique_ptr&) = delete;

            unique_ptr(unique_ptr&& other) noexcept
            : _ptr(other._ptr) {
                other._ptr = nullptr;
            }

            unique_ptr& operator=(unique_ptr&& other) noexcept {
                if (this != &other) {
                    if (_ptr) {
                        Deleter(_ptr);
                    }
                    _ptr = other._ptr;
                    other._ptr = nullptr;
                }
                return *this;
            }

            T* get() const noexcept {
                return _ptr;
            }

            T* release() noexcept {
                T* temp = _ptr;
                _ptr = nullptr;
                return temp;
            }

            void reset(T* ptr = nullptr) {
                if (_ptr) {
                    Deleter(_ptr);
                }
                _ptr = ptr;
            }

            explicit operator bool() const noexcept {
                return _ptr != nullptr;
            }

            T& operator*() const {
                return *_ptr;
            }

            T* operator->() const {
                return _ptr;
            }
        };

        // ALIAS
        using EVP_PKEY_ptr = unique_ptr<EVP_PKEY, EVP_PKEY_free>;
        using EVP_CIPHER_CTX_ptr = unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;
        using EVP_MD_CTX_ptr = unique_ptr<EVP_MD_CTX, EVP_MD_CTX_free>;
        //using BIO_ptr = unique_ptr<BIO, BIO_free>;
        using X509_ptr = unique_ptr<X509, X509_free>;
        using X509_REQ_ptr = unique_ptr<X509_REQ, X509_REQ_free>;
        using X509_CRL_ptr = unique_ptr<X509_CRL, X509_CRL_free>;
        using SSL_CTX_ptr = unique_ptr<SSL_CTX, SSL_CTX_free>;
        using SSL_ptr = unique_ptr<SSL, SSL_free>;
        using RSA_ptr = unique_ptr<RSA, RSA_free>;
        using EC_KEY_ptr = unique_ptr<EC_KEY, EC_KEY_free>;
        using DSA_ptr = unique_ptr<DSA, DSA_free>;
    }
}