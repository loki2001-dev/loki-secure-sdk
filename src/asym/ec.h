#pragma once

#include "../fwd.h"
#include <string>

namespace loki::crypto {

    class EC {
    public:
        enum class Curve {
            SECP256R1,
            SECP384R1,
            SECP521R1
        };

        EC();
        ~EC();

        void generate_key(Curve curve = Curve::SECP256R1);

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