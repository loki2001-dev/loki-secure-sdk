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

#include "core/exception.h"

namespace loki::core {
    Exception::Exception(const std::string& message)
        : std::runtime_error(message),
        _message(message) {
    }

    Exception::Exception(const char* message)
        : std::runtime_error(message),
        _message(message) {
    }

    const char* Exception::what() const noexcept {
        return _message.c_str();
    }

CryptoException::CryptoException(const std::string& message)
    : Exception("Crypto error: " + message) {

    }

CryptoException::CryptoException(const char* message)
    : Exception(std::string("Crypto error: ") + message) {

    }

InitializationException::InitializationException(const std::string& message)
    : Exception("Initialization error: " + message) {

    }

InitializationException::InitializationException(const char* message)
    : Exception(std::string("Initialization error: ") + message) {

    }

InvalidArgumentException::InvalidArgumentException(const std::string& message)
    : Exception("Invalid argument: " + message) {

    }

InvalidArgumentException::InvalidArgumentException(const char* message)
    : Exception(std::string("Invalid argument: ") + message) {

    }

OutOfMemoryException::OutOfMemoryException(const std::string& message)
    : Exception("Out of memory: " + message) {

    }

OutOfMemoryException::OutOfMemoryException(const char* message)
    : Exception(std::string("Out of memory: ") + message) {

    }
}