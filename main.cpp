#include "openssl_wrapper.h"
#include "crypto/sha256.h"
#include "crypto/aes.h"
#include "crypto/md5.h"
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

    cleanup();
    spdlog::info("OpenSSL free successfully\n");

    return 0;
}