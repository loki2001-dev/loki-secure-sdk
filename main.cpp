#include "openssl_wrapper.h"
#include "asym/dsa.h"
#include "asym/ec.h"
#include "asym/rsa.h"
#include "crypto/aes.h"
#include "crypto/chacha20.h"
#include "crypto/md5.h"
#include "crypto/signature.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "crypto/random.h"
#include "x509/csr.h"
#include "x509/crl.h"
#include <spdlog/spdlog.h>
#include <fstream>

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

    // DSA
    {
        spdlog::info("===== DSA =====");
        std::string input = "Hello OpenSSL World";

        loki::crypto::DSA dsa;
        dsa.generate_key(2048);
        spdlog::info("DSA key pair generated (2048 bits)");

        ByteArray data(input.begin(), input.end());

        auto signature = dsa.sign(data);
        spdlog::info("DSA signature generated ({} bytes)", signature.size());

        auto priv_key = dsa.export_private_key();
        auto pub_key = dsa.export_public_key();
        spdlog::info("DSA Private Key:\n{}", priv_key);
        spdlog::info("DSA Public Key:\n{}", pub_key);

        bool ok = dsa.verify(data, signature);
        spdlog::info("DSA signature verification result: {}\n", ok ? "Success" : "Failure");
    }

    // EC
    {
        spdlog::info("===== EC =====");
        std::string input = "Hello OpenSSL World";

        loki::crypto::EC ec;
        ec.generate_key(EC::Curve::SECP256R1);
        spdlog::info("EC key pair generated (Curve: SECP256R1)");

        ByteArray data(input.begin(), input.end());

        auto sig = ec.sign(data);
        spdlog::info("EC signature generated ({} bytes)", sig.size());

        auto priv_key = ec.export_private_key();
        auto pub_key = ec.export_public_key();
        spdlog::info("EC Private Key:\n{}", priv_key);
        spdlog::info("EC Public Key:\n{}", pub_key);

        bool valid = ec.verify(data, sig);
        spdlog::info("EC signature verification result: {}\n", valid ? "Success" : "Failure");
    }

    // RSA
    {
        spdlog::info("===== RSA =====");
        std::string input = "Hello OpenSSL World";

        loki::crypto::RSA rsa;
        rsa.generate_key(2048);
        spdlog::info("RSA key pair generated (2048 bits)");

        ByteArray data(input.begin(), input.end());

        auto ciphertext = rsa.encrypt(data);
        spdlog::info("RSA encryption done (ciphertext size: {})", ciphertext.size());

        auto decrypted = rsa.decrypt(ciphertext);
        spdlog::info("RSA decryption done (plaintext size: {})", decrypted.size());
        spdlog::info("Decrypted text: {}", std::string(decrypted.begin(), decrypted.end()));

        auto signature = rsa.sign(data);
        spdlog::info("RSA signature generated ({} bytes)", signature.size());

        bool ok = rsa.verify(data, signature);
        spdlog::info("RSA signature verification result: {}\n", ok ? "Success" : "Failure");
    }

    // X509/CSR
    {
        spdlog::info("===== X509/CSR ===== ");
        std::ifstream keyfile("../pem/private_key.pem");
        std::string private_key_pem((std::istreambuf_iterator<char>(keyfile)), std::istreambuf_iterator<char>());

        loki::x509::CSR csr;
        csr.generate(ByteArray(private_key_pem.begin(), private_key_pem.end()), "CN=example.com,O=ExampleOrg,C=US");

        std::string csr_pem = csr.export_pem();
        spdlog::info("Generated CSR PEM:\n{}", csr_pem);

        std::string subject_dn = csr.get_subject_dn();
        spdlog::info("CSR Subject DN: {}\n", subject_dn);
    }

    // X509/CRL
    {
        spdlog::info("===== X509/CRL with PEM and DER ===== ");
        std::ifstream crlfile_pem("../pem/crl.pem", std::ios::binary);
        std::string crl_pem((std::istreambuf_iterator<char>(crlfile_pem)), std::istreambuf_iterator<char>());

        loki::x509::CRL crl;
        loki::x509::CRL crl_from_der;

        crl.load_pem(crl_pem);
        spdlog::info("Loaded CRL from PEM");

        loki::ByteArray crl_der = crl.export_der();
        spdlog::info("Exported CRL to DER ({} bytes)", crl_der.size());

        crl_from_der.load_der(crl_der);
        spdlog::info("Loaded CRL again from DER");

        std::string crl_pem2 = crl_from_der.export_pem();
        spdlog::info("Exported CRL back to PEM:\n{}", crl_pem2);

        bool valid = crl_from_der.is_valid();
        spdlog::info("CRL valid: {}\n", valid ? "Yes" : "No");
    }

    cleanup();
    spdlog::info("OpenSSL free successfully\n");

    return 0;
}