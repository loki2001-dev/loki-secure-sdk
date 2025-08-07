#include "crypto/aes.h"
#include "crypto/random.h"
#include "core/exception.h"
#include <openssl/evp.h>
#include <openssl/err.h>

namespace loki::crypto {
    AES::AES(KeySize key_size, Mode mode)
        : _key_size(key_size),
        _mode(mode),
        Cipher(select_cipher(key_size, mode)) {
        _ctx.reset(EVP_CIPHER_CTX_new());
        if (!_ctx) {
            throw core::OutOfMemoryException("Failed to create AES context");
        }

        _ctx.reset(EVP_CIPHER_CTX_new());
        if (!_ctx) {
            throw core::OutOfMemoryException("Failed to create AES context");
        }
    }

    const EVP_CIPHER* AES::select_cipher(KeySize key_size, Mode mode) {
        switch (key_size) {
            case KeySize::AES_128:
                switch (mode) {
                    case Mode::ECB: return EVP_aes_128_ecb();
                    case Mode::CBC: return EVP_aes_128_cbc();
                    case Mode::CFB: return EVP_aes_128_cfb();
                    case Mode::OFB: return EVP_aes_128_ofb();
                    case Mode::GCM: return EVP_aes_128_gcm();
                    default: return nullptr;
                }
            case KeySize::AES_192:
                switch (mode) {
                    case Mode::ECB: return EVP_aes_192_ecb();
                    case Mode::CBC: return EVP_aes_192_cbc();
                    case Mode::CFB: return EVP_aes_192_cfb();
                    case Mode::OFB: return EVP_aes_192_ofb();
                    case Mode::GCM: return EVP_aes_192_gcm();
                    default: return nullptr;
                }
            case KeySize::AES_256:
                switch (mode) {
                    case Mode::ECB: return EVP_aes_256_ecb();
                    case Mode::CBC: return EVP_aes_256_cbc();
                    case Mode::CFB: return EVP_aes_256_cfb();
                    case Mode::OFB: return EVP_aes_256_ofb();
                    case Mode::GCM: return EVP_aes_256_gcm();
                    default: return nullptr;
                }
            default:
                return nullptr;
        }
    }

    void AES::generate_key() {
        _key = Random::bytes(static_cast<size_t>(_key_size) / 8);
    }

    ByteArray AES::encrypt_cbc(const ByteArray& plaintext, const ByteArray& key, const ByteArray& iv) {
        AES aes(key.size() == 16 ? KeySize::AES_128 : key.size() == 24 ? KeySize::AES_192 : KeySize::AES_256, Mode::CBC);
        aes.set_key(key);
        aes.set_iv(iv);
        return aes.encrypt(plaintext);
    }

    ByteArray AES::decrypt_cbc(const ByteArray& ciphertext, const ByteArray& key, const ByteArray& iv) {
        AES aes(key.size() == 16 ? KeySize::AES_128 : key.size() == 24 ? KeySize::AES_192 : KeySize::AES_256, Mode::CBC);
        aes.set_key(key);
        aes.set_iv(iv);
        return aes.decrypt(ciphertext);
    }

    ByteArray AES::encrypt_gcm(const ByteArray& plaintext, const ByteArray& key, const ByteArray& iv, ByteArray& tag) {
        AES aes(key.size() == 16 ? KeySize::AES_128 : key.size() == 24 ? KeySize::AES_192 : KeySize::AES_256, Mode::GCM);
        aes.set_key(key);
        aes.set_iv(iv);

        EVP_CIPHER_CTX* ctx = aes._ctx.get();
        ByteArray ciphertext(plaintext.size());

        int len = 0;
        int ciphertext_len = 0;

        if (EVP_EncryptInit_ex(ctx, aes._cipher, nullptr, nullptr, nullptr) != 1) {
            throw core::CryptoException("EVP_EncryptInit_ex failed");
        }

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr);
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            throw core::CryptoException("EVP_EncryptInit_ex (key/iv) failed");
        }

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            throw core::CryptoException("EVP_EncryptUpdate failed");
        }
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            throw core::CryptoException("EVP_EncryptFinal_ex failed");
        }
        ciphertext_len += len;

        tag.resize(16);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
            throw core::CryptoException("Failed to get GCM tag");
        }

        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }

    ByteArray AES::decrypt_gcm(const ByteArray& ciphertext, const ByteArray& key, const ByteArray& iv, const ByteArray& tag) {
        AES aes(key.size() == 16 ? KeySize::AES_128 : key.size() == 24 ? KeySize::AES_192 : KeySize::AES_256, Mode::GCM);
        aes.set_key(key);
        aes.set_iv(iv);

        EVP_CIPHER_CTX* ctx = aes._ctx.get();
        ByteArray plaintext(ciphertext.size());

        int len = 0;
        int plaintext_len = 0;

        if (EVP_DecryptInit_ex(ctx, aes._cipher, nullptr, nullptr, nullptr) != 1) {
            throw core::CryptoException("EVP_DecryptInit_ex failed");
        }

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr);
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
            throw core::CryptoException("EVP_DecryptInit_ex (key/iv) failed");
        }

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
            throw core::CryptoException("EVP_DecryptUpdate failed");
        }
        plaintext_len = len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data())) != 1) {
            throw core::CryptoException("Failed to set GCM tag");
        }

        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
        if (ret <= 0) {
            throw core::CryptoException("GCM tag verification failed");
        }

        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return plaintext;
    }

    const EVP_CIPHER* AES::get_cipher() const {
        switch (_key_size) {
            case KeySize::AES_128:
                switch (_mode) {
                    case Mode::ECB: return EVP_aes_128_ecb();
                    case Mode::CBC: return EVP_aes_128_cbc();
                    case Mode::CFB: return EVP_aes_128_cfb();
                    case Mode::OFB: return EVP_aes_128_ofb();
                    case Mode::GCM: return EVP_aes_128_gcm();
                    default: break; // 알 수 없는 mode
                }
                break;
            case KeySize::AES_192:
                switch (_mode) {
                    case Mode::ECB: return EVP_aes_192_ecb();
                    case Mode::CBC: return EVP_aes_192_cbc();
                    case Mode::CFB: return EVP_aes_192_cfb();
                    case Mode::OFB: return EVP_aes_192_ofb();
                    case Mode::GCM: return EVP_aes_192_gcm();
                    default: break;
                }
                break;
            case KeySize::AES_256:
                switch (_mode) {
                    case Mode::ECB: return EVP_aes_256_ecb();
                    case Mode::CBC: return EVP_aes_256_cbc();
                    case Mode::CFB: return EVP_aes_256_cfb();
                    case Mode::OFB: return EVP_aes_256_ofb();
                    case Mode::GCM: return EVP_aes_256_gcm();
                    default: break;
                }
                break;
            default:
                break;
        }
        return nullptr;
    }

} // namespace loki::crypto