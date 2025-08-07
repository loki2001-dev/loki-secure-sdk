#pragma once

#include "../fwd.h"
#include <concepts>
#include <type_traits>

namespace loki::core::concepts {
    // concepts - Cryptography
    template<typename T>
    concept Hashable = requires(T t) {
        { t.hash() } -> std::convertible_to<ByteArray>;
        { t.update(std::declval<const uint8_t *>(), std::declval<size_t>()) } -> std::same_as<void>;
        { t.finalize() } -> std::convertible_to<ByteArray>;
    };

    template<typename T>
    concept Cipher = requires(T t) {
        { t.encrypt(std::declval<const ByteArray &>()) } -> std::convertible_to<ByteArray>;
        { t.decrypt(std::declval<const ByteArray &>()) } -> std::convertible_to<ByteArray>;
        { t.set_key(std::declval<const ByteArray &>()) } -> std::same_as<void>;
    };

    template<typename T>
    concept AsymmetricKey = requires(T t) {
        { t.generate(std::declval<size_t>()) } -> std::same_as<void>;
        { t.get_public_key() } -> std::convertible_to<ByteArray>;
        { t.get_private_key() } -> std::convertible_to<ByteArray>;
        { t.load_public_key(std::declval<const ByteArray &>()) } -> std::same_as<void>;
        { t.load_private_key(std::declval<const ByteArray &>()) } -> std::same_as<void>;
    };

    template<typename T>
    concept Signable = AsymmetricKey<T> && requires(T t) {
        { t.sign(std::declval<const ByteArray &>()) } -> std::convertible_to<ByteArray>;
        { t.verify(std::declval<const ByteArray &>(), std::declval<const ByteArray &>()) } -> std::convertible_to<bool>;
    };

    // concepts - Memory
    template<typename T>
    concept SecureErasable = requires(T t) {
        { t.secure_clear() } -> std::same_as<void>;
    };

    // concepts - Serialization
    template<typename T>
    concept Serializable = requires(T t) {
        { t.to_pem() } -> std::convertible_to<std::string>;
        { t.to_der() } -> std::convertible_to<ByteArray>;
        { t.from_pem(std::declval<const std::string &>()) } -> std::same_as<void>;
        { t.from_der(std::declval<const ByteArray &>()) } -> std::same_as<void>;
    };
}