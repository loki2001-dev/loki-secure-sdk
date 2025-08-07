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