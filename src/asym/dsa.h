#pragma once

#include "../fwd.h"
#include <string>

namespace loki::crypto {

    class DSA {
    public:
        DSA();
        ~DSA();

        // Generate DSA key (e.g., 1024, 2048, 3072)
        void generate_key(size_t bits = 2048);

        void load_private_key(const std::string& pem);
        void load_public_key(const std::string& pem);

        std::string export_private_key() const;
        std::string export_public_key() const;

        ByteArray sign(const ByteArray& message, const std::string& hash = "SHA256") const;
        bool verify(const ByteArray& message, const ByteArray& signature, const std::string& hash = "SHA256") const;

    private:
        struct Impl;
        std::unique_ptr<Impl> _pimpl;
    };

} // namespace loki::crypto