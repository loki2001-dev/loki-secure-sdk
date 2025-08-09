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

#include "csr.h"
#include "core/exception.h"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <memory>
#include <string>

namespace loki::x509 {

    struct CSR::Impl {
        X509_REQ* req = nullptr;

        Impl() = default;
        ~Impl() {
            if (req) {
                X509_REQ_free(req);
            }
        }
    };

    CSR::CSR()
            : _pimpl(std::make_unique<Impl>()) {

    }

    CSR::~CSR() = default;

    void CSR::generate(const ByteArray& private_key_pem, const std::string& subject_dn, const std::string& hash_algo) {
        if (_pimpl->req) {
            X509_REQ_free(_pimpl->req);
            _pimpl->req = nullptr;
        }

        _pimpl->req = X509_REQ_new();
        if (!_pimpl->req) {
            throw core::CryptoException("Failed to create X509_REQ");
        }

        // Parse private key from PEM
        BIO* bio = BIO_new_mem_buf(private_key_pem.data(), static_cast<int>(private_key_pem.size()));
        if (!bio) {
            throw core::CryptoException("Failed to create BIO for private key");
        }

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) {
            throw core::CryptoException("Failed to parse private key PEM");
        }

        if (X509_REQ_set_pubkey(_pimpl->req, pkey) != 1) {
            EVP_PKEY_free(pkey);
            throw core::CryptoException("Failed to set public key to CSR");
        }

        X509_NAME* name = X509_NAME_new();
        if (!name) {
            EVP_PKEY_free(pkey);
            throw core::CryptoException("Failed to create X509_NAME");
        }

        // Parse subject_dn string (e.g. "CN=example.com,O=Org,C=US")
        size_t start = 0;
        while (start < subject_dn.size()) {
            size_t end = subject_dn.find(',', start);
            std::string token = (end == std::string::npos) ? subject_dn.substr(start) : subject_dn.substr(start, end - start);
            size_t eq_pos = token.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = token.substr(0, eq_pos);
                std::string value = token.substr(eq_pos + 1);
                X509_NAME_add_entry_by_txt(name, key.c_str(), MBSTRING_ASC,
                                           reinterpret_cast<const unsigned char*>(value.c_str()), -1, -1, 0);
            }
            if (end == std::string::npos) {
                break;
            }
            start = end + 1;
        }

        if (X509_REQ_set_subject_name(_pimpl->req, name) != 1) {
            X509_NAME_free(name);
            EVP_PKEY_free(pkey);
            throw core::CryptoException("Failed to set subject name to CSR");
        }
        X509_NAME_free(name);

        // Sign CSR
        const EVP_MD* md = EVP_get_digestbyname(hash_algo.c_str());
        if (!md) {
            EVP_PKEY_free(pkey);
            throw core::CryptoException("Unsupported hash algorithm: " + hash_algo);
        }

        if (X509_REQ_sign(_pimpl->req, pkey, md) <= 0) {
            EVP_PKEY_free(pkey);
            throw core::CryptoException("Failed to sign CSR");
        }

        EVP_PKEY_free(pkey);
    }

    void CSR::load_pem(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio) {
            throw core::CryptoException("Failed to create BIO for PEM");
        }

        X509_REQ* req = PEM_read_bio_X509_REQ(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!req) {
            throw core::CryptoException("Failed to parse PEM CSR");
        }

        if (_pimpl->req) {
            X509_REQ_free(_pimpl->req);
        }
        _pimpl->req = req;
    }

    void CSR::load_der(const ByteArray& der) {
        const unsigned char* ptr = der.data();
        X509_REQ* req = d2i_X509_REQ(nullptr, &ptr, static_cast<long>(der.size()));
        if (!req) {
            throw core::CryptoException("Failed to parse DER CSR");
        }

        if (_pimpl->req) {
            X509_REQ_free(_pimpl->req);
        }
        _pimpl->req = req;
    }

    std::string CSR::export_pem() const {
        if (!_pimpl->req) {
            throw core::CryptoException("CSR not loaded");
        }

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw core::CryptoException("Failed to create BIO");
        }

        if (PEM_write_bio_X509_REQ(bio, _pimpl->req) != 1) {
            BIO_free(bio);
            throw core::CryptoException("Failed to write PEM CSR");
        }

        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len);
        BIO_free(bio);
        return pem;
    }

    ByteArray CSR::export_der() const {
        if (!_pimpl->req) {
            throw core::CryptoException("CSR not loaded");
        }

        int len = i2d_X509_REQ(_pimpl->req, nullptr);
        if (len <= 0) {
            throw core::CryptoException("Failed to get DER length");
        }

        ByteArray der(len);
        unsigned char* ptr = der.data();
        int len2 = i2d_X509_REQ(_pimpl->req, &ptr);
        if (len2 != len) {
            throw core::CryptoException("DER encoding length mismatch");
        }

        return der;
    }

    std::string CSR::get_subject_dn() const {
        if (!_pimpl->req) {
            return {};
        }

        X509_NAME* name = X509_REQ_get_subject_name(_pimpl->req);
        if (!name) {
            return {};
        }

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            return {};
        }

        if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0) {
            BIO_free(bio);
            return {};
        }

        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string dn(data, len);
        BIO_free(bio);
        return dn;
    }

} // namespace loki::x509