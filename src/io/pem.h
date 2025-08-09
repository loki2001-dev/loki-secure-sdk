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

#include <cstdint>
#include <string>
#include <vector>

namespace loki::core {

    using ByteArray = std::vector<uint8_t>;

    class PEM {
    public:
        // Convert DER bytes to PEM string with specified PEM type (e.g., "CERTIFICATE", "PRIVATE KEY")
        static std::string der_to_pem(const ByteArray& der_data, const std::string& pem_type);

        // Convert PEM string to DER bytes
        static ByteArray pem_to_der(const std::string& pem_str);

        // Load PEM file contents as string
        static std::string load_pem_file(const std::string& filepath);

        // Save PEM string to file
        static bool save_pem_file(const std::string& filepath, const std::string& pem_str);

    private:
        PEM() = delete;
    };

} // namespace loki::core