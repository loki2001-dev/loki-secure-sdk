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

#include <openssl/bio.h>
#include <memory>
#include <string>

namespace loki::core {

    class Bio {
    public:
        Bio() noexcept;

        explicit Bio(const void* data, int length);

        explicit Bio(const std::string& filename, const std::string& mode);

        ~Bio();

        Bio(const Bio&) = delete;
        Bio& operator=(const Bio&) = delete;

        Bio(Bio&& other) noexcept;
        Bio& operator=(Bio&& other) noexcept;

        BIO* get() const noexcept;

        int read(void* buf, int len);

        int write(const void* buf, int len);

        std::string to_string() const;

        void reset(BIO* bio = nullptr) noexcept;

    private:
        BIO* _bio;
    };

} // namespace loki::core