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

#include <vector>
#include <string>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

namespace loki::core {

    using ByteArray = std::vector<uint8_t>;

    class DER {
    public:
        // Encode raw data to DER format using ASN1_OCTET_STRING
        static ByteArray encode_octet_string(const ByteArray& data);

        // Decode DER-encoded octet string to raw data
        static ByteArray decode_octet_string(const ByteArray& der_data);

        // Load DER data from a file
        static ByteArray load_der_file(const std::string& filepath);

        // Save DER data to a file
        static bool save_der_file(const std::string& filepath, const ByteArray& der_data);

    private:
        DER() = delete;
    };

} // namespace loki::core