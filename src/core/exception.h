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

#pragma once

#include "../fwd.h"
#include <stdexcept>
#include <string>

namespace loki::core {
    class Exception : public std::runtime_error {
    public:
        explicit Exception(const std::string& message);
        explicit Exception(const char* message);

        const char* what() const noexcept override;

    private:
        std::string _message;
    };

    class CryptoException : public Exception {
    public:
        explicit CryptoException(const std::string& message);
        explicit CryptoException(const char* message);
    };

    class InitializationException : public Exception {
    public:
        explicit InitializationException(const std::string& message);
        explicit InitializationException(const char* message);
    };

    class InvalidArgumentException : public Exception {
    public:
        explicit InvalidArgumentException(const std::string& message);
        explicit InvalidArgumentException(const char* message);
    };

    class OutOfMemoryException : public Exception {
    public:
        explicit OutOfMemoryException(const std::string& message);
        explicit OutOfMemoryException(const char* message);
    };
}