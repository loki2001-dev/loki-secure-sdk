#include "openssl_wrapper.h"
#include "crypto/aes.h"
#include "crypto/chacha20.h"
#include "crypto/md5.h"
#include "crypto/signature.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "crypto/random.h"
#include <spdlog/spdlog.h>

using namespace loki;
using namespace loki::openssl_wrapper;
using namespace loki::crypto;

int main() {
    // Initialize OpenSSL
    if (!initialize()) {
        spdlog::error("OpenSSL initialization failed: {}", get_last_error());
        return 1;
    }

    // OpenSSL Version
    spdlog::info("===== OpenSSL Version Info =====");
    spdlog::info("OpenSSL Version: {}", get_version());
    spdlog::info("OpenSSL Version Number: {:#x}\n", get_version_number());

    spdlog::info("OpenSSL initialized successfully\n");

    // SHA-256
    {
        spdlog::info("===== SHA-256 Hashing =====");
        const std::string message = "Hello OpenSSL World";

        loki::crypto::SHA256 sha256;
        ByteArray digest = sha256.hash(message);

        std::string hex_digest;
        for (auto byte : digest) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            hex_digest += buf;
        }
        spdlog::info("SHA-256('{}') = {}\n", message, hex_digest);
    }

    // SHA-512
    {
        spdlog::info("===== SHA-512 Hashing =====");
        const std::string message = "Hello OpenSSL World";

        loki::crypto::SHA512 sha512;
        ByteArray digest1 = sha512.hash(message);
        std::string hex_digest1;
        for (auto byte : digest1) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            hex_digest1 += buf;
        }
        spdlog::info("SHA-512(std::string): '{}' = {}", message, hex_digest1);

        ByteArray data(message.begin(), message.end());
        ByteArray digest2 = sha512.hash(data);
        std::string hex_digest2;
        for (auto byte : digest2) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            hex_digest2 += buf;
        }
        spdlog::info("SHA-512(ByteArray): '{}' = {}", message, hex_digest2);

        ByteArray digest3 = sha512.hash(reinterpret_cast<const uint8_t*>(message.data()), message.size());
        std::string hex_digest3;
        for (auto byte : digest3) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            hex_digest3 += buf;
        }
        spdlog::info("SHA-512(uint8_t*, size): '{}' = {}\n", message, hex_digest3);
    }

    // ChaCha20
    {
        spdlog::info("===== ChaCha20 Encryption (12-byte nonce) =====");

        std::string plaintext = "Hello ChaCha20 World!";
        ByteArray plain_data(plaintext.begin(), plaintext.end());
        spdlog::info("Plaintext: {}", plaintext);

        loki::crypto::Random random;
        ByteArray key(ChaCha20::KEY_SIZE);
        for (auto& b : key) b = static_cast<uint8_t>(random.uint32() & 0xFF);

        // 12-byte nonce
        ByteArray nonce(ChaCha20::NONCE_SIZE);
        for (auto& b : nonce) b = static_cast<uint8_t>(random.uint32() & 0xFF);

        spdlog::info("Key: {}", random.hex_string(key.size()));
        spdlog::info("Nonce (12B): {}", random.hex_string(nonce.size()));

        ByteArray encrypted = ChaCha20::encrypt(plain_data, key, nonce);
        spdlog::info("Encrypted (12B nonce): {}", random.hex_string(encrypted.size()));

        ByteArray decrypted = ChaCha20::decrypt(encrypted, key, nonce);
        spdlog::info("Decrypted (12B nonce): {}\n", std::string(decrypted.begin(), decrypted.end()));
    }

    {
        spdlog::info("===== ChaCha20 Encryption (16-byte IV) =====");

        std::string plaintext = "Hello ChaCha20 with IV!";
        ByteArray plain_data(plaintext.begin(), plaintext.end());
        spdlog::info("Plaintext: {}", plaintext);

        loki::crypto::Random random;
        ByteArray key(ChaCha20::KEY_SIZE);
        for (auto& b : key) b = static_cast<uint8_t>(random.uint32() & 0xFF);

        // 16-byte IV
        ByteArray iv(ChaCha20::IV_SIZE);
        for (auto& b : iv) b = static_cast<uint8_t>(random.uint32() & 0xFF);

        spdlog::info("Key: {}", random.hex_string(key.size()));
        spdlog::info("IV (16B): {}", random.hex_string(iv.size()));

        ByteArray encrypted = ChaCha20::encrypt(plain_data, key, iv);
        spdlog::info("Encrypted (16B IV): {}", random.hex_string(encrypted.size()));

        ByteArray decrypted = ChaCha20::decrypt(encrypted, key, iv);
        spdlog::info("Decrypted (16B IV): {}\n", std::string(decrypted.begin(), decrypted.end()));
    }

    // AES (ECB)
    {
        spdlog::info("===== AES Encryption (ECB, 128-bit key) =====");
        loki::crypto::AES aes(AES::KeySize::AES_128, AES::Mode::ECB);

        std::vector<uint8_t> key(16, 0x01);  // 128bit key
        aes.set_key(key);

        std::vector<uint8_t> plain = { 'H', 'E', 'L', 'L', 'O', ' ', 'O', 'P', 'E', 'N', 'S', 'S', 'L', ' ', 'W', 'O', 'R', 'L', 'D', 0, 0, 0, 0 };
        spdlog::info("Plaintext: {}", std::string(plain.begin(), plain.end()));

        std::vector<uint8_t> encrypted = aes.encrypt(plain);

        std::string encrypted_hex;
        for (uint8_t b : encrypted) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02X ", b);
            encrypted_hex += buf;
        }
        spdlog::info("Encrypted data: {}", encrypted_hex);

        std::vector<uint8_t> decrypted = aes.decrypt(encrypted);
        std::string decrypted_str(decrypted.begin(), decrypted.end());
        spdlog::info("Decrypted data: {}\n", decrypted_str);
    }

    // AES (CBC)
    {
        spdlog::info("===== AES Encryption (CBC, 128-bit key) =====");
        loki::crypto::AES aes(AES::KeySize::AES_128, AES::Mode::CBC);

        std::vector<uint8_t> key(16, 0x02);  // 128bit key
        aes.set_key(key);

        std::vector<uint8_t> plain = { 'H', 'E', 'L', 'L', 'O', ' ', 'O', 'P', 'E', 'N', 'S', 'S', 'L', ' ', 'W', 'O', 'R', 'L', 'D', 0, 0, 0, 0 };
        spdlog::info("Plaintext: {}", std::string(plain.begin(), plain.end()));

        std::vector<uint8_t> encrypted = aes.encrypt(plain);

        std::string encrypted_hex;
        for (uint8_t b : encrypted) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02X ", b);
            encrypted_hex += buf;
        }
        spdlog::info("Encrypted data: {}", encrypted_hex);

        std::vector<uint8_t> decrypted = aes.decrypt(encrypted);
        std::string decrypted_str(decrypted.begin(), decrypted.end());
        spdlog::info("Decrypted data: {}\n", decrypted_str);
    }

    // Random
    {
        spdlog::info("===== Random Generation =====");
        loki::crypto::Random random;

        spdlog::info("Random uint32: {}", random.uint32());
        spdlog::info("Random uint64: {}", random.uint64());
        spdlog::info("Random base64 string (64 bytes): {}", random.base64_string(64));
        spdlog::info("Random hex string (64 bytes): {}\n", random.hex_string(64));
    }

    // MD5
    {
        spdlog::info("===== MD5 =====");
        std::string input = "Hello OpenSSL World";

        loki::crypto::MD5 md5(input);

        ByteArray digest1 = md5.hash(input);
        std::string hex_digest1;
        for (auto byte : digest1) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            hex_digest1 += buf;
        }
        spdlog::info("MD5(std::string): \"{}\" -> {}", input, hex_digest1);

        ByteArray data2(input.begin(), input.end());
        ByteArray digest2 = md5.hash(data2);
        std::string hex_digest2;
        for (auto byte : digest2) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            hex_digest2 += buf;
        }
        spdlog::info("MD5(ByteArray): \"{}\" -> {}", input, hex_digest2);

        ByteArray digest3 = md5.hash(reinterpret_cast<const uint8_t*>(input.data()), input.size());
        std::string hex_digest3;
        for (auto byte : digest3) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", byte);
            hex_digest3 += buf;
        }
        spdlog::info("MD5(uint8_t*, size): \"{}\" -> {}\n", input, hex_digest3);
    }

    // Signature
    {
        spdlog::info("===== Signature =====");
        std::string input = "Hello OpenSSL World";
        ByteArray message(input.begin(), input.end());

        loki::crypto::Signature signature(loki::crypto::Signature::Algorithm::RSA_PKCS1, loki::crypto::Signature::Hash::SHA256);

        const auto public_key = signature.load_pem_file("../pem/public_key.pem");
        signature.set_public_key(public_key);

        const auto private_key = signature.load_pem_file("../pem/private_key.pem");
        signature.set_private_key(private_key);

        const auto signature_message = signature.sign(message);
        const auto signature_message_str = signature.to_hex_string(signature_message);

        spdlog::info("Signature message: {}", signature_message_str);
        spdlog::info("Signature size: {}", signature_message_str.size());

        bool ok = signature.verify(message, signature_message);
        spdlog::info("Verification result: {}\n", ok ? "Success" : "Failure");
    }

    cleanup();
    spdlog::info("OpenSSL free successfully\n");

    return 0;
}