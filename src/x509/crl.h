#pragma once

#include "../fwd.h"
#include <string>
#include <memory>

namespace loki::x509 {

    class CRL {
    public:
        CRL();
        ~CRL();

        // Load CRL from PEM string
        void load_pem(const std::string& pem);

        // Load CRL from DER binary data
        void load_der(const ByteArray& der);

        // Export CRL as PEM string
        std::string export_pem() const;

        // Export CRL as DER binary
        ByteArray export_der() const;

        // Check if CRL is currently valid (not expired)
        bool is_valid() const;

    private:
        struct Impl;
        std::unique_ptr<Impl> _pimpl;
    };

} // namespace loki::x509