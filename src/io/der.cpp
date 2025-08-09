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

#include "der.h"
#include <openssl/asn1.h>
#include <fstream>

namespace loki::core {

    ByteArray DER::encode_octet_string(const ByteArray& data) {
        ASN1_OCTET_STRING* oct = ASN1_OCTET_STRING_new();
        if (!oct) {
            throw std::runtime_error("Failed to allocate ASN1_OCTET_STRING");
        }

        ByteArray der_encoded;
        do {
            if (!ASN1_OCTET_STRING_set(oct, data.data(), static_cast<int>(data.size()))) break;

            int len = i2d_ASN1_OCTET_STRING(oct, nullptr);
            if (len <= 0) break;

            der_encoded.resize(len);
            unsigned char* p = der_encoded.data();
            if (i2d_ASN1_OCTET_STRING(oct, &p) != len) break;

            ASN1_OCTET_STRING_free(oct);
            return der_encoded;
        } while (false);

        ASN1_OCTET_STRING_free(oct);
        throw std::runtime_error("DER encoding failed");
    }

    ByteArray DER::decode_octet_string(const ByteArray& der_data) {
        const unsigned char* p = der_data.data();
        ASN1_OCTET_STRING* oct = d2i_ASN1_OCTET_STRING(nullptr, &p, static_cast<long>(der_data.size()));
        if (!oct) {
            throw std::runtime_error("DER decoding failed");
        }

        ByteArray raw(oct->data, oct->data + oct->length);
        ASN1_OCTET_STRING_free(oct);
        return raw;
    }

    ByteArray DER::load_der_file(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open DER file: " + filepath);
        }
        return ByteArray(std::istreambuf_iterator<char>(file), {});
    }

    bool DER::save_der_file(const std::string& filepath, const ByteArray& der_data) {
        std::ofstream file(filepath, std::ios::binary);
        if (!file) return false;
        file.write(reinterpret_cast<const char*>(der_data.data()), static_cast<std::streamsize>(der_data.size()));
        return file.good();
    }

} // namespace loki::core