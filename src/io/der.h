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