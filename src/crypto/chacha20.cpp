#include "crypto/chacha20.h"
#include "crypto/random.h"
#include "core/exception.h"

#include <openssl/evp.h>
#include <algorithm>

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

    // 12바이트 nonce를 16바이트 IV로 확장 함수
    static ByteArray expand_nonce_to_iv(const ByteArray& iv_or_nonce) {
        if (iv_or_nonce.size() == ChaCha20::IV_SIZE) {
            // 이미 16바이트 IV이면 그대로 반환
            return iv_or_nonce;
        } else if (iv_or_nonce.size() == ChaCha20::NONCE_SIZE) {
            // 12바이트 nonce + 4바이트 counter(0) = 16바이트 IV 생성
            ByteArray iv(ChaCha20::IV_SIZE, 0x00);
            std::copy(iv_or_nonce.begin(), iv_or_nonce.end(), iv.begin());
            // 마지막 4바이트는 0 (초기 counter)
            return iv;
        } else {
            throw core::InvalidArgumentException("ChaCha20 IV must be 16 bytes or nonce must be 12 bytes");
        }
    }

    ByteArray ChaCha20::encrypt(const ByteArray& plaintext, const ByteArray& key, const ByteArray& iv_or_nonce) {
        if (key.size() != KEY_SIZE) {
            throw core::InvalidArgumentException("ChaCha20 key must be 32 bytes");
        }

        ByteArray iv = expand_nonce_to_iv(iv_or_nonce);

        ChaCha20 chacha;
        chacha.set_key(key);
        chacha.set_iv(iv);
        return chacha.Cipher::encrypt(plaintext);
    }

    ByteArray ChaCha20::decrypt(const ByteArray& ciphertext, const ByteArray& key, const ByteArray& iv_or_nonce) {
        if (key.size() != KEY_SIZE) {
            throw core::InvalidArgumentException("ChaCha20 key must be 32 bytes");
        }

        ByteArray iv = expand_nonce_to_iv(iv_or_nonce);

        ChaCha20 chacha;
        chacha.set_key(key);
        chacha.set_iv(iv);
        return chacha.Cipher::decrypt(ciphertext);
    }

    const EVP_CIPHER* ChaCha20::get_cipher() const {
        return EVP_chacha20();
    }

} // namespace loki::crypto