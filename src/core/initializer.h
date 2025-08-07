#pragma once

#include "../fwd.h"
#include "exception.h"

namespace loki::core {
    class Initializer {
    private:
        static bool _initialized;
        static int _ref_count;

    public:
        Initializer();
        ~Initializer();

        // non-copyable, non-movable
        Initializer(const Initializer&) = delete;
        Initializer& operator=(const Initializer&) = delete;

        Initializer(Initializer&&) = delete;
        Initializer& operator=(Initializer&&) = delete;

        static bool is_initialized() noexcept;
        static void force_initialize();
        static void force_cleanup() noexcept;

    private:
        static void initialize();
        static void cleanup() noexcept;
    };

    class LibraryGuard {
    private:
        Initializer _init;

    public:
        LibraryGuard() = default;
        ~LibraryGuard() = default;

        // non-copyable, non-movable
        LibraryGuard(const LibraryGuard&) = delete;
        LibraryGuard& operator=(const LibraryGuard&) = delete;

        LibraryGuard(LibraryGuard&&) = delete;
        LibraryGuard& operator=(LibraryGuard&&) = delete;
    };
}