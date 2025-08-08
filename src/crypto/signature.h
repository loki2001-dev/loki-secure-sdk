#pragma once

#include "../fwd.h"
#include <openssl/ossl_typ.h>
#include <string>

namespace loki::crypto {

    class Signature {
    public:
        enum class Algorithm {
            RSA_PSS,
            RSA_PKCS1,
            ECDSA
        };

        enum class Hash {
            SHA256,
            SHA384,
            SHA512
        };

    public:
        explicit Signature(Algorithm algorithm = Algorithm::RSA_PSS, Hash hash = Hash::SHA256);
        ~Signature() = default;

        void set_private_key(const std::string& pem);
        void set_public_key(const std::string& pem);

        ByteArray sign(const ByteArray& message);
        bool verify(const ByteArray& message, const ByteArray& signature);

        static ByteArray sign(Algorithm algo, Hash hash, const std::string& private_key_pem, const ByteArray& message);
        static bool verify(Algorithm algo, Hash hash, const std::string& public_key_pem, const ByteArray& message, const ByteArray& signature);

        static std::string load_pem_file(const std::string& filepath);

        std::string to_hex_string(const ByteArray& data);

    private:
        Algorithm _algorithm;
        Hash _hash;
        EVP_PKEY* _private_key = nullptr;
        EVP_PKEY* _public_key = nullptr;

        const EVP_MD* get_md() const;
    };

} // namespace loki::crypto