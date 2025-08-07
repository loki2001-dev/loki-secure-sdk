#include "bio.h"
#include "core/exception.h"

#include <openssl/err.h>
#include <cstring>

namespace loki::core {

    Bio::Bio() noexcept
            : _bio(nullptr) {
    }

    Bio::Bio(const void *data, int length) : _bio(nullptr) {
        _bio = BIO_new_mem_buf(data, length);
        if (!_bio) {
            throw core::CryptoException("Failed to create memory BIO");
        }
    }

    Bio::Bio(const std::string &filename, const std::string &mode) : _bio(nullptr) {
        _bio = BIO_new_file(filename.c_str(), mode.c_str());
        if (!_bio) {
            throw core::CryptoException("Failed to open file BIO: " + filename);
        }
    }

    Bio::~Bio() {
        if (_bio) {
            BIO_free(_bio);
            _bio = nullptr;
        }
    }

    Bio::Bio(Bio &&other) noexcept
        : _bio(other._bio) {
        other._bio = nullptr;
    }

    Bio &Bio::operator=(Bio &&other) noexcept {
        if (this != &other) {
            if (_bio) {
                BIO_free(_bio);
            }
            _bio = other._bio;
            other._bio = nullptr;
        }
        return *this;
    }

    BIO *Bio::get() const noexcept {
        return _bio;
    }

    int Bio::read(void *buf, int len) {
        if (!_bio) {
            return -1;
        }

        int ret = BIO_read(_bio, buf, len);
        if (ret <= 0) {
            if (BIO_should_retry(_bio)) {
                return 0;
            }
            return -1; // ERROR or EOF
        }
        return ret;
    }

    int Bio::write(const void *buf, int len) {
        if (!_bio) {
            return -1;
        }

        int ret = BIO_write(_bio, buf, len);
        if (ret <= 0) {
            if (BIO_should_retry(_bio)) {
                return 0;
            }
            return -1; // ERROR or EOF
        }
        return ret;
    }

    std::string Bio::to_string() const {
        if (!_bio) {
            return {};
        };

        char *data = nullptr;
        long len = BIO_get_mem_data(_bio, &data);
        if (len <= 0 || !data) {
            return {};
        };
        return std::string(data, static_cast<size_t>(len));
    }

    void Bio::reset(BIO *bio) noexcept {
        if (_bio) {
            BIO_free(_bio);
        }
        _bio = bio;
    }

} // namespace loki::core