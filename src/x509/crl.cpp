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

#include "crl.h"
#include "core/exception.h"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>

#include <memory>
#include <string>
#include <ctime>

namespace loki::x509 {

    struct CRL::Impl {
        X509_CRL* crl = nullptr;

        Impl() = default;
        ~Impl() {
            if (crl) {
                X509_CRL_free(crl);
            }
        }
    };

    CRL::CRL()
        : _pimpl(std::make_unique<Impl>()) {

    }

    CRL::~CRL() = default;

    void CRL::load_pem(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio) {
            throw core::CryptoException("Failed to create BIO for PEM");
        }

        X509_CRL* crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!crl) {
            throw core::CryptoException("Failed to parse PEM CRL");
        }

        if (_pimpl->crl) {
            X509_CRL_free(_pimpl->crl);
        }
        _pimpl->crl = crl;
    }

    void CRL::load_der(const ByteArray& der) {
        const unsigned char* ptr = der.data();
        X509_CRL* crl = d2i_X509_CRL(nullptr, &ptr, static_cast<long>(der.size()));
        if (!crl) {
            throw core::CryptoException("Failed to parse DER CRL");
        }

        if (_pimpl->crl) {
            X509_CRL_free(_pimpl->crl);
        }
        _pimpl->crl = crl;
    }

    std::string CRL::export_pem() const {
        if (!_pimpl->crl) {
            throw core::CryptoException("CRL not loaded");
        }

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw core::CryptoException("Failed to create BIO");
        }

        if (PEM_write_bio_X509_CRL(bio, _pimpl->crl) != 1) {
            BIO_free(bio);
            throw core::CryptoException("Failed to write PEM CRL");
        }

        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len);
        BIO_free(bio);
        return pem;
    }

    ByteArray CRL::export_der() const {
        if (!_pimpl->crl) {
            throw core::CryptoException("CRL not loaded");
        }

        int len = i2d_X509_CRL(_pimpl->crl, nullptr);
        if (len <= 0) {
            throw core::CryptoException("Failed to get DER length");
        }

        ByteArray der(len);
        unsigned char* ptr = der.data();
        int len2 = i2d_X509_CRL(_pimpl->crl, &ptr);
        if (len2 != len) {
            throw core::CryptoException("DER encoding length mismatch");
        }

        return der;
    }

    bool CRL::is_valid() const {
        if (!_pimpl->crl) return false;

        ASN1_TIME* next_update = X509_CRL_get_nextUpdate(_pimpl->crl);
        if (!next_update) {
            return false;
        }

        // ASN1_TIME to time_t
        auto asn1time_to_time_t = [](const ASN1_TIME* time) -> std::time_t {
            struct tm t{};
            const char* str = (const char*)time->data;
            size_t i = 0;

            if (time->type == V_ASN1_UTCTIME) {
                int year = (str[i++] - '0') * 10 + (str[i++] - '0');
                year += (year < 50) ? 2000 : 1900;
                t.tm_year = year - 1900;
                t.tm_mon = ((str[i++] - '0') * 10 + (str[i++] - '0')) - 1;
                t.tm_mday = (str[i++] - '0') * 10 + (str[i++] - '0');
                t.tm_hour = (str[i++] - '0') * 10 + (str[i++] - '0');
                t.tm_min = (str[i++] - '0') * 10 + (str[i++] - '0');
                t.tm_sec = (str[i++] - '0') * 10 + (str[i++] - '0');
            } else if (time->type == V_ASN1_GENERALIZEDTIME) {
                int year = (str[i++] - '0') * 1000 + (str[i++] - '0') * 100 + (str[i++] - '0') * 10 + (str[i++] - '0');
                t.tm_year = year - 1900;
                t.tm_mon = ((str[i++] - '0') * 10 + (str[i++] - '0')) - 1;
                t.tm_mday = (str[i++] - '0') * 10 + (str[i++] - '0');
                t.tm_hour = (str[i++] - '0') * 10 + (str[i++] - '0');
                t.tm_min = (str[i++] - '0') * 10 + (str[i++] - '0');
                t.tm_sec = (str[i++] - '0') * 10 + (str[i++] - '0');
            } else {
                return 0;
            }
            t.tm_isdst = 0;
            return timegm(&t);
        };

        std::time_t now = std::time(nullptr);
        std::time_t next = asn1time_to_time_t(next_update);

        return now <= next;
    }

} // namespace loki::x509