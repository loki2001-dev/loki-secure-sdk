#include "pem.h"
#include "core/exception.h"

#include <openssl/bio.h>
#include <openssl/pem.h>

#include <fstream>
#include <sstream>

namespace loki::core {

    std::string PEM::der_to_pem(const ByteArray& der_data, const std::string& pem_type) {
        std::string pem;
        pem += "-----BEGIN " + pem_type + "-----\n";

        BIO* mem = BIO_new(BIO_s_mem());
        BIO* b64 = BIO_new(BIO_f_base64());
        mem = BIO_push(b64, mem);

        // DISABLE
        BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);

        // Write DER data to BIO (Base64 encode)
        BIO_write(mem, der_data.data(), static_cast<int>(der_data.size()));
        BIO_flush(mem);

        BUF_MEM* bptr = nullptr;
        BIO_get_mem_ptr(mem, &bptr);
        if (bptr && bptr->length > 0) {
            pem.append(bptr->data, bptr->length);
        }

        BIO_free_all(mem);

        pem += "\n-----END " + pem_type + "-----\n";
        return pem;
    }

    ByteArray PEM::pem_to_der(const std::string& pem_str) {
        BIO* bio = BIO_new_mem_buf(pem_str.data(), static_cast<int>(pem_str.size()));
        if (!bio) throw std::runtime_error("Failed to create BIO");

        char* data_ptr = nullptr;
        long len = BIO_get_mem_data(bio, &data_ptr);
        if (len <= 0) {
            BIO_free(bio);
            throw std::runtime_error("Empty PEM data");
        }

        std::string pem_content(data_ptr, len);
        BIO_free(bio);

        // Find PEM headers
        size_t begin_pos = pem_content.find("-----BEGIN ");
        size_t end_pos = pem_content.find("-----END ");

        if (begin_pos == std::string::npos || end_pos == std::string::npos) {
            throw std::runtime_error("Invalid PEM format: missing headers");
        }

        // Find the end of BEGIN header line
        size_t begin_line_end = pem_content.find('\n', begin_pos);
        if (begin_line_end == std::string::npos) {
            throw std::runtime_error("Invalid PEM format: malformed BEGIN header");
        }

        // Extract base64 content between headers
        std::string base64_content = pem_content.substr(begin_line_end + 1, end_pos - begin_line_end - 1);

        // Remove any whitespace and newlines from base64 content
        std::string clean_base64;
        for (char c : base64_content) {
            if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
                clean_base64 += c;
            }
        }

        if (clean_base64.empty()) {
            throw std::runtime_error("Empty base64 content in PEM");
        }

        // Create BIO for base64 decoding
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* mem = BIO_new_mem_buf(clean_base64.data(), static_cast<int>(clean_base64.size()));
        mem = BIO_push(b64, mem);

        // Disable newline handling for base64
        BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);

        ByteArray der_data;
        const int buffer_size = 1024;
        char buffer[buffer_size];
        int bytes_read;

        // Read and decode base64 data
        while ((bytes_read = BIO_read(mem, buffer, buffer_size)) > 0) {
            der_data.insert(der_data.end(), buffer, buffer + bytes_read);
        }

        BIO_free_all(mem);

        if (der_data.empty()) {
            throw std::runtime_error("Failed to decode PEM to DER");
        }

        return der_data;
    }

    std::string PEM::load_pem_file(const std::string& filepath) {
        std::ifstream file(filepath);
        if (!file) throw std::runtime_error("Cannot open PEM file: " + filepath);
        std::stringstream ss;
        ss << file.rdbuf();
        return ss.str();
    }

    bool PEM::save_pem_file(const std::string& filepath, const std::string& pem_str) {
        std::ofstream file(filepath);
        if (!file) return false;
        file << pem_str;
        return file.good();
    }

} // namespace loki::core