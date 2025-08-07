#pragma once

#include "../fwd.h"
#include <string>

namespace loki::x509 {

    class Certificate {
    public:
        Certificate();
        ~Certificate();

        // Load certificate from PEM string
        void load_pem(const std::string& pem);

        // Load certificate from DER binary data
        void load_der(const ByteArray& der);

        // Export certificate as PEM string
        std::string export_pem() const;

        // Export certificate as DER binary
        ByteArray export_der() const;

        // Get subject common name (CN)
        std::string get_common_name() const;

        // Get issuer common name (CN)
        std::string get_issuer_common_name() const;

        // Check if certificate is valid at current time
        bool is_valid() const;

    private:
        struct Impl;
        std::unique_ptr<Impl> _pimpl;
    };

} // namespace loki::x509