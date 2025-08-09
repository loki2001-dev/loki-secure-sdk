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
#include <string>
#include <memory>

namespace loki::x509 {

    class CSR {
    public:
        CSR();
        ~CSR();

        // Generate new CSR with given key and subject DN (e.g., "CN=example.com,O=Org,C=US")
        void generate(const ByteArray& private_key_pem, const std::string& subject_dn, const std::string& hash_algo = "SHA256");

        // Load CSR from PEM string
        void load_pem(const std::string& pem);

        // Load CSR from DER binary data
        void load_der(const ByteArray& der);

        // Export CSR as PEM string
        std::string export_pem() const;

        // Export CSR as DER binary data
        ByteArray export_der() const;

        // Get subject DN string (e.g. "CN=example.com,O=Org,C=US")
        std::string get_subject_dn() const;

    private:
        struct Impl;
        std::unique_ptr<Impl> _pimpl;
    };

} // namespace loki::x509