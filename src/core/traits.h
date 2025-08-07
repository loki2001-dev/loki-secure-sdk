#pragma once

#include "../fwd.h"
#include <type_traits>

namespace loki::core::traits {
    template<typename T>
    struct is_hash_algorithm : std::false_type {};

    template<typename T>
    struct is_cipher_algorithm : std::false_type {};

    template<typename T>
    struct is_asymmetric_key : std::false_type {};

    template<typename T>
    struct key_size {
        static constexpr size_t value = 0;
    };

    template<typename T>
    struct block_size {
        static constexpr size_t value = 0;
    };

    template<typename T>
    struct hash_size {
        static constexpr size_t value = 0;
    };

    template<typename T>
    inline constexpr bool is_hash_algorithm_v = is_hash_algorithm<T>::value;

    template<typename T>
    inline constexpr bool is_cipher_algorithm_v = is_cipher_algorithm<T>::value;

    template<typename T>
    inline constexpr bool is_asymmetric_key_v = is_asymmetric_key<T>::value;

    template<typename T>
    inline constexpr size_t key_size_v = key_size<T>::value;

    template<typename T>
    inline constexpr size_t block_size_v = block_size<T>::value;

    template<typename T>
    inline constexpr size_t hash_size_v = hash_size<T>::value;
}