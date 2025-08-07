#pragma once

#include "../fwd.h"

namespace loki::crypto {

    class RSA {
    public:
        enum class Padding {
            PKCS1,
            PSS,
            OAEP
        };

        RSA();
        ~RSA();

        void generate_key(size_t bits = 2048);

        void load_private_key(const std::string& pem);
        void load_public_key(const std::string& pem);

        std::string export_private_key() const;
        std::string export_public_key() const;

        ByteArray encrypt(const ByteArray& plaintext, Padding padding = Padding::OAEP) const;
        ByteArray decrypt(const ByteArray& ciphertext, Padding padding = Padding::OAEP) const;

        ByteArray sign(const ByteArray& message, Padding padding = Padding::PSS, const std::string& hash = "SHA256") const;
        bool verify(const ByteArray& message, const ByteArray& signature, Padding padding = Padding::PSS, const std::string& hash = "SHA256") const;

    private:
        struct Impl;
        std::unique_ptr<Impl> _pimpl;
    };

} // namespace loki::crypto