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

#include "core/initializer.h"
#include "openssl_wrapper.h"
#include <mutex>

namespace loki::core {
    bool Initializer::_initialized = false;
    int Initializer::_ref_count = 0;

    static std::mutex init_mutex;

    Initializer::Initializer() {
        std::lock_guard<std::mutex> lock(init_mutex);
        if (_ref_count == 0) {
            initialize();
        }
        ++_ref_count;
    }

    Initializer::~Initializer() {
        std::lock_guard<std::mutex> lock(init_mutex);
        --_ref_count;
        if (_ref_count == 0) {
            cleanup();
        }
    }

    bool Initializer::is_initialized() noexcept {
    std::lock_guard<std::mutex> lock(init_mutex);
    return _initialized;
}

void Initializer::force_initialize() {
    std::lock_guard<std::mutex> lock(init_mutex);
    if (!_initialized) {
        initialize();
    }
}

void Initializer::force_cleanup() noexcept {
std::lock_guard<std::mutex> lock(init_mutex);
if (_initialized) {
cleanup();
    _ref_count = 0;
}
}

void Initializer::initialize() {
    if (!_initialized) {
        if (!openssl_wrapper::initialize()) {
            throw InitializationException("Failed to initialize OpenSSL");
        }
        _initialized = true;
    }
}

void Initializer::cleanup() noexcept {
if (_initialized) {
openssl_wrapper::cleanup();
    _initialized = false;
}
}
}