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