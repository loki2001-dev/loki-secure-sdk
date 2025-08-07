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