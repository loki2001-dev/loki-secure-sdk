
#include "crypto/cipher.h"
#include "crypto/random.h"
#include "core/exception.h"

namespace loki::crypto {
    Cipher::Cipher(const EVP_CIPHER* cipher)
    : _cipher(cipher) {
        if (!_cipher) {
            throw core::InvalidArgumentException("Invalid cipher");
        }

        _ctx.reset(EVP_CIPHER_CTX_new());
        if (!_ctx) {
            throw core::OutOfMemoryException("Failed to create cipher context");
        }
    }

    void Cipher::set_key(const ByteArray& key) {
        if (key.size() != key_size()) {
            throw core::InvalidArgumentException("Invalid key size");
        }
        _key = key;
    }

    void Cipher::set_iv(const ByteArray& iv) {
        if (iv.size() != iv_size()) {
            throw core::InvalidArgumentException("Invalid IV size");
        }
        _iv = iv;
    }

    void Cipher::generate_iv() {
        _iv = Random::bytes(iv_size());
    }

    ByteArray Cipher::encrypt(const ByteArray& plaintext) {
        if (_key.empty()) {
            throw core::InvalidArgumentException("Key not set");
        }

        if (_iv.empty() && iv_size() > 0) {
            generate_iv();
        }

        if (EVP_EncryptInit_ex(_ctx.get(), _cipher, nullptr, _key.data(), _iv.empty() ? nullptr : _iv.data()) != 1) {
            throw core::CryptoException("Failed to initialize encryption: " + openssl_wrapper::get_last_error());
        }

        ByteArray ciphertext(plaintext.size() + block_size());
        int len = 0, final_len = 0;

        if (EVP_EncryptUpdate(_ctx.get(), ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            throw core::CryptoException("Failed to encrypt data: " + openssl_wrapper::get_last_error());
        }

        if (EVP_EncryptFinal_ex(_ctx.get(), ciphertext.data() + len, &final_len) != 1) {
            throw core::CryptoException("Failed to finalize encryption: " + openssl_wrapper::get_last_error());
        }

        ciphertext.resize(len + final_len);
        return ciphertext;
    }

    ByteArray Cipher::decrypt(const ByteArray& ciphertext) {
        if (_key.empty()) {
            throw core::InvalidArgumentException("Key not set");
        }

        if (_iv.empty() && iv_size() > 0) {
            throw core::InvalidArgumentException("IV not set");
        }

        if (EVP_DecryptInit_ex(_ctx.get(), _cipher, nullptr, _key.data(), _iv.empty() ? nullptr : _iv.data()) != 1) {
            throw core::CryptoException("Failed to initialize decryption: " + openssl_wrapper::get_last_error());
        }

        ByteArray plaintext(ciphertext.size() + block_size());
        int len = 0, final_len = 0;

        if (EVP_DecryptUpdate(_ctx.get(), plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            throw core::CryptoException("Failed to decrypt data: " + openssl_wrapper::get_last_error());
        }

        if (EVP_DecryptFinal_ex(_ctx.get(), plaintext.data() + len, &final_len) != 1) {
            throw core::CryptoException("Failed to finalize decryption: " + openssl_wrapper::get_last_error());
        }

        plaintext.resize(len + final_len);
        return plaintext;
    }

    size_t Cipher::key_size() const {
        return EVP_CIPHER_key_length(_cipher);
    }

    size_t Cipher::iv_size() const {
        return EVP_CIPHER_iv_length(_cipher);
    }

    size_t Cipher::block_size() const {
        return EVP_CIPHER_block_size(_cipher);
    }

    void Cipher::reset() {
        EVP_CIPHER_CTX_reset(_ctx.get());
    }
}