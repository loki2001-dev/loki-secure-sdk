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