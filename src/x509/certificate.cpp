#include "certificate.h"
#include "core/exception.h"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>

#include <memory>
#include <string>
#include <ctime>

namespace loki::x509 {

    struct Certificate::Impl {
        X509* cert = nullptr;

        Impl() = default;
        ~Impl() {
            if (cert) X509_free(cert);
        }
    };

    Certificate::Certificate()
        : _pimpl(std::make_unique<Impl>()) {

    }

    Certificate::~Certificate() = default;

    void Certificate::load_pem(const std::string& pem) {
        BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
        if (!bio) {
            throw core::CryptoException("Failed to create BIO for PEM");
        }

        X509* x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!x509) {
            throw core::CryptoException("Failed to parse PEM certificate");
        }

        if (_pimpl->cert) {
            X509_free(_pimpl->cert);
        }
        _pimpl->cert = x509;
    }

    void Certificate::load_der(const ByteArray& der) {
        const unsigned char* ptr = der.data();
        X509* x509 = d2i_X509(nullptr, &ptr, static_cast<long>(der.size()));
        if (!x509) {
            throw core::CryptoException("Failed to parse DER certificate");
        }

        if (_pimpl->cert) {
            X509_free(_pimpl->cert);
        }
        _pimpl->cert = x509;
    }

    std::string Certificate::export_pem() const {
        if (!_pimpl->cert) {
            throw core::CryptoException("Certificate not loaded");
        }

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            throw core::CryptoException("Failed to create BIO");
        }

        if (PEM_write_bio_X509(bio, _pimpl->cert) != 1) {
            BIO_free(bio);
            throw core::CryptoException("Failed to write PEM certificate");
        }

        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len);
        BIO_free(bio);
        return pem;
    }

    ByteArray Certificate::export_der() const {
        if (!_pimpl->cert) {
            throw core::CryptoException("Certificate not loaded");
        }

        int len = i2d_X509(_pimpl->cert, nullptr);
        if (len <= 0) {
            throw core::CryptoException("Failed to get DER length");
        }

        ByteArray der(len);
        unsigned char* ptr = der.data();
        int len2 = i2d_X509(_pimpl->cert, &ptr);
        if (len2 != len) {
            throw core::CryptoException("DER encoding length mismatch");
        }

        return der;
    }

    static std::string get_cn_from_name(X509_NAME* name) {
        if (!name) {
            return {};
        }

        int idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if (idx < 0) {
            return {};
        }

        X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
        if (!entry) {
            return {};
        }

        ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
        if (!data) {
            return {};
        }

        unsigned char* utf8 = nullptr;
        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if (length < 0) {
            return {};
        }

        std::string cn(reinterpret_cast<char*>(utf8), length);
        OPENSSL_free(utf8);
        return cn;
    }

    std::string Certificate::get_common_name() const {
        if (!_pimpl->cert) {
            return {};
        }

        X509_NAME* subj = X509_get_subject_name(_pimpl->cert);
        return get_cn_from_name(subj);
    }

    std::string Certificate::get_issuer_common_name() const {
        if (!_pimpl->cert) {
            return {};
        }

        X509_NAME* issuer = X509_get_issuer_name(_pimpl->cert);
        return get_cn_from_name(issuer);
    }

    bool Certificate::is_valid() const {
        if (!_pimpl->cert) {
            return false;
        }

        ASN1_TIME* notBefore = X509_get_notBefore(_pimpl->cert);
        ASN1_TIME* notAfter = X509_get_notAfter(_pimpl->cert);
        if (!notBefore || !notAfter) {
            return false;
        }

        // ASN1_TIME to time_t
        auto asn1time_to_time_t = [](const ASN1_TIME* time) -> std::time_t {
            struct tm t{};
            const char* str = (const char*)time->data;
            size_t i = 0;

            if (time->type == V_ASN1_UTCTIME) {
                // Two digit year
                int year = (str[i++] - '0') * 10 + (str[i++] - '0');
                year += (year < 50) ? 2000 : 1900;
                t.tm_year = year - 1900;
                t.tm_mon = ((str[i++] - '0') * 10 + (str[i++] - '0')) - 1;
                t.tm_mday = (str[i++] - '0') * 10 + (str[i++] - '0');
                t.tm_hour = (str[i++] - '0') * 10 + (str[i++] - '0');
                t.tm_min = (str[i++] - '0') * 10 + (str[i++] - '0');
                t.tm_sec = (str[i++] - '0') * 10 + (str[i++] - '0');
            } else if (time->type == V_ASN1_GENERALIZEDTIME) {
                // Four digit year
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
            return timegm(&t);  // timegm: GMT TIME (POSIX)
        };

        std::time_t now = std::time(nullptr);
        std::time_t before = asn1time_to_time_t(notBefore);
        std::time_t after = asn1time_to_time_t(notAfter);

        return (now >= before) && (now <= after);
    }

} // namespace loki::x509