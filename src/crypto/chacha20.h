#pragma once

#include "cipher.h"

namespace loki::crypto {

    class ChaCha20 : public Cipher {
    public:
        static constexpr size_t KEY_SIZE = 32;      // 256 bits
        static constexpr size_t NONCE_SIZE = 12;    // 96 bits

        ChaCha20();
        ~ChaCha20() override = default;

        void generate_key();

        static ByteArray encrypt(const ByteArray& plaintext, const ByteArray& key, const ByteArray& nonce);
        static ByteArray decrypt(const ByteArray& ciphertext, const ByteArray& key, const ByteArray& nonce);

    private:
        const EVP_CIPHER* get_cipher() const override;
    };

} // namespace loki::crypto