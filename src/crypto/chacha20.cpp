#include "crypto/chacha20.h"
#include "crypto/random.h"
#include "core/exception.h"

#include <openssl/evp.h>

namespace loki::crypto {

    ChaCha20::ChaCha20()
        : Cipher(EVP_chacha20()) {
        _ctx.reset(EVP_CIPHER_CTX_new());
        if (!_ctx) {
            throw core::OutOfMemoryException("Failed to create ChaCha20 context");
        }
    }

    void ChaCha20::generate_key() {
        _key = Random::bytes(KEY_SIZE);
    }

    ByteArray ChaCha20::encrypt(const ByteArray& plaintext, const ByteArray& key, const ByteArray& nonce) {
        if (key.size() != KEY_SIZE) {
            throw core::InvalidArgumentException("ChaCha20 key must be 32 bytes");
        }

        if (nonce.size() != NONCE_SIZE) {
            throw core::InvalidArgumentException("ChaCha20 nonce must be 12 bytes");
        }

        ChaCha20 chacha;
        chacha.set_key(key);
        chacha.set_iv(nonce);
        return chacha.Cipher::encrypt(plaintext);
    }

    ByteArray ChaCha20::decrypt(const ByteArray& ciphertext, const ByteArray& key, const ByteArray& nonce) {
        if (key.size() != KEY_SIZE) {
            throw core::InvalidArgumentException("ChaCha20 key must be 32 bytes");
        }
        if (nonce.size() != NONCE_SIZE) {
            throw core::InvalidArgumentException("ChaCha20 nonce must be 12 bytes");
        }

        ChaCha20 chacha;
        chacha.set_key(key);
        chacha.set_iv(nonce);
        return chacha.Cipher::decrypt(ciphertext);
    }

    const EVP_CIPHER* ChaCha20::get_cipher() const {
        return EVP_chacha20();
    }

} // namespace loki::crypto