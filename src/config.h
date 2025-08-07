#pragma once

#include "fwd.h"
#include <string>
#include <unordered_map>

namespace loki {
    namespace config {
        // VERSION
        constexpr const char* SDK_VERSION = "1.0.0";
        constexpr int SDK_VERSION_MAJOR = 1;
        constexpr int SDK_VERSION_MINOR = 0;
        constexpr int SDK_VERSION_PATCH = 0;

        // DEFAULT CONFIGURATIONS
        constexpr size_t DEFAULT_KEY_SIZE = 2048;
        constexpr size_t DEFAULT_BUFFER_SIZE = 8192;
        constexpr int DEFAULT_ITERATIONS = 10000;

        enum class CipherMode {
            ECB,
            CBC,
            CFB,
            OFB,
            GCM
        };

        enum class PaddingMode {
            PKCS7,
            ZERO,
            NONE
        };

        enum class HashAlgorithm {
            MD5,
            SHA1,
            SHA256,
            SHA512
        };

        enum class KeyType {
            RSA,
            EC,
            DSA,
            ED25519,
            X25519
        };

        class Config {
        private:
            std::unordered_map<std::string, std::string> _settings;

        public:
            Config();
            ~Config() = default;

            void set(const std::string& key, const std::string& value);
            std::string get(const std::string& key) const;
            std::string get(const std::string& key, const std::string& default_value) const;

            bool has(const std::string& key) const;
            void remove(const std::string& key);
            void clear();

            static Config& instance();
        };
    }
}