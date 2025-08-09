/*
 * Copyright 2025 loki2001-dev
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "openssl_wrapper.h"
#include "core/exception.h"
#include <openssl/opensslconf.h>
#include <openssl/engine.h>
#include <mutex>
#include <vector>

namespace loki::openssl_wrapper {
    static bool g_initialized = false;
    static std::mutex g_init_mutex;

    thread_local char error_buffer[256];

    bool initialize() {
        std::lock_guard<std::mutex> lock(g_init_mutex);

        if (g_initialized) {
            return true;
        }

        // Initialize OpenSSL
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();

        // Initialize RANDOM generator
        if (RAND_poll() != 1) {
            return false;
        }

        g_initialized = true;
        return true;
    }

    void cleanup() noexcept {
        std::lock_guard<std::mutex> lock(g_init_mutex);
        if (!g_initialized) {
            return;
        }

        // Cleanup OpenSSL
        EVP_cleanup();
        ERR_free_strings();
        CRYPTO_cleanup_all_ex_data();
        g_initialized = false;
}

std::string get_last_error() {
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return "No error";
    }

    ERR_error_string_n(err, error_buffer, sizeof(error_buffer));
    return std::string(error_buffer);
}

void clear_errors() {
    ERR_clear_error();
}

bool random_bytes(uint8_t* buf, size_t len) {
    if (!buf || len == 0) {
        return false;
    }

    return RAND_bytes(buf, static_cast<int>(len)) == 1;
}

bool random_pseudo_bytes(uint8_t* buf, size_t len) {
    if (!buf || len == 0) {
        return false;
    }

    return RAND_pseudo_bytes(buf, static_cast<int>(len)) >= 0;
}

void secure_clear(void* ptr, size_t len) {
    if (ptr && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

std::string get_version() {
    return std::string(OPENSSL_VERSION_TEXT);
}

long get_version_number() {
    return OPENSSL_VERSION_NUMBER;
}

}