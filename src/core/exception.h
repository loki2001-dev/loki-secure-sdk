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