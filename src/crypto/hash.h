#pragma once

#include "../fwd.h"
#include "../core/concepts.h"
#include "../openssl_wrapper.h"
#include <memory>

namespace loki::crypto {
    class Hash {
    protected:
        openssl_wrapper::secure_ptr::EVP_MD_CTX_ptr _ctx;
        const EVP_MD* _md;

    public:
        explicit Hash(const EVP_MD* md);
        virtual ~Hash() = default;

        Hash(const Hash&) = delete;
        Hash& operator=(const Hash&) = delete;
        Hash(Hash&&) = default;
        Hash& operator=(Hash&&) = default;

        void update(const uint8_t* data, size_t len);
        void update(const ByteArray& data);
        void update(const std::string& data);

        ByteArray finalize();
        ByteArray hash(const uint8_t* data, size_t len);
        ByteArray hash(const ByteArray& data);
        ByteArray hash(const std::string& data);

        void reset();
        size_t digest_size() const;

        static ByteArray quick_hash(const EVP_MD* md, const uint8_t* data, size_t len);
        static ByteArray quick_hash(const EVP_MD* md, const ByteArray& data);
        static ByteArray quick_hash(const EVP_MD* md, const std::string& data);
    };
}