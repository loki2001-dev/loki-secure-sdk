#pragma once

#include "cipher.h"

namespace loki::crypto {
    class AES : public Cipher {
    public:
        enum class KeySize {
            AES_128 = 128,
            AES_192 = 192,
            AES_256 = 256
        };

        enum class Mode {
            ECB,
            CBC,
            CFB,
            OFB,
            GCM
        };

    private:
        KeySize _key_size;
        Mode _mode;

    public:
        explicit AES(KeySize key_size = KeySize::AES_256, Mode mode = Mode::CBC);
        ~AES() override = default;

        void generate_key();

        static ByteArray encrypt_cbc(const ByteArray& plaintext, const ByteArray& key, const ByteArray& iv);
        static ByteArray decrypt_cbc(const ByteArray& ciphertext, const ByteArray& key, const ByteArray& iv);

        static ByteArray encrypt_gcm(const ByteArray& plaintext, const ByteArray& key, const ByteArray& iv, ByteArray& tag);
        static ByteArray decrypt_gcm(const ByteArray& ciphertext, const ByteArray& key, const ByteArray& iv, const ByteArray& tag);

    private:
        static const EVP_CIPHER* select_cipher(KeySize key_size, Mode mode);
        const EVP_CIPHER* get_cipher() const override;
    };
}