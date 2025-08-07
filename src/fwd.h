#pragma once

#include <memory>
#include <string>
#include <vector>
#include <cstdint>

struct evp_pkey_st;
struct evp_cipher_ctx_st;
struct evp_md_ctx_st;
struct x509_st;
struct x509_req_st;
struct x509_crl_st;
struct ssl_st;
struct ssl_ctx_st;
struct bio_st;

namespace loki {
    using ByteArray = std::vector<uint8_t>;
    using SecureString = std::string;

    namespace core {
        template<typename T>
        class SecureAllocator;

        class Exception;
        class Initializer;
    }

    namespace crypto {
        class Hash;
        class SHA256;
        class SHA512;
        class MD5;
        class Cipher;
        class AES;
        class ChaCha20;
        class Signature;
        class Random;
    }

    namespace asym {
        class RSA;
        class EC;
        class DSA;
    }

    namespace x509 {
        class Certificate;
        class CSR;
        class CRL;
    }

    namespace tls {
        class Context;
        class Connection;
        class Client;
        class Server;
    }

    namespace io {
        class PEM;
        class DER;
        class BIO;
    }
}