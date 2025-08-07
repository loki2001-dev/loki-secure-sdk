
// core/initializer.cpp
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