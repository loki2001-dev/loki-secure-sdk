#pragma once

#include "../fwd.h"
#include <memory>
#include <cstddef>

namespace loki::core {
    template<typename T>
    class SecureAllocator {
    public:
        using value_type = T;
        using pointer = T*;
        using const_pointer = const T*;
        using reference = T&;
        using const_reference = const T&;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;

        template<typename U>
        struct rebind {
            using other = SecureAllocator<U>;
        };

        SecureAllocator() noexcept = default;

        template<typename U>
        explicit SecureAllocator(const SecureAllocator<U>&) noexcept {}

        pointer allocate(size_type n);
        void deallocate(pointer p, size_type n) noexcept;

        template<typename U, typename... Args>
        void construct(U* p, Args&&... args);

        template<typename U>
        void destroy(U* p);

        bool operator==(const SecureAllocator& other) const noexcept;
        bool operator!=(const SecureAllocator& other) const noexcept;
    };

    class SecureMemory {
    public:
        static void* allocate(size_t size);
        static void deallocate(void* ptr, size_t size) noexcept;
        static void zero(void* ptr, size_t size) noexcept;
        static void lock(void* ptr, size_t size);
        static void unlock(void* ptr, size_t size) noexcept;

    private:
        static bool is_locked(void* ptr, size_t size) noexcept;
    };

    template<typename T>
    class SecurePtr {
    private:
        T* _ptr;
        size_t _size;

    public:
        explicit SecurePtr(size_t count = 1);
        ~SecurePtr();

        // non-copyable
        SecurePtr(const SecurePtr&) = delete;
        SecurePtr& operator=(const SecurePtr&) = delete;

        // movable
        SecurePtr(SecurePtr&& other) noexcept;
        SecurePtr& operator=(SecurePtr&& other) noexcept;

        T* get() const noexcept { return _ptr; }
        T& operator*() const { return *_ptr; }
        T* operator->() const { return _ptr; }
        T& operator[](size_t index) const { return _ptr[index]; }

        explicit operator bool() const noexcept { return _ptr != nullptr; }

        void reset(size_t count = 1);
        T* release() noexcept;
    };
}