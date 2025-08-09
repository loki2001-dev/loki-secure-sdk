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

#include "core/memory.h"
#include "core/exception.h"
#include <algorithm>
#include <sys/mman.h>

namespace loki::core {

    template<typename T>
    typename SecureAllocator<T>::pointer SecureAllocator<T>::allocate(size_type n) {
        if (n == 0) {
            return nullptr;
        }

        auto p = static_cast<pointer>(SecureMemory::allocate(n * sizeof(T)));
        if (!p) {
            throw OutOfMemoryException("Failed to allocate secure memory");
        }

        try {
            SecureMemory::lock(p, n * sizeof(T));
        } catch (...) {
            SecureMemory::deallocate(p, n * sizeof(T));
            throw;
        }

        return p;
    }

    template<typename T>
    void SecureAllocator<T>::deallocate(pointer p, size_type n) noexcept {
        if (p) {
            SecureMemory::unlock(p, n * sizeof(T));
            SecureMemory::deallocate(p, n * sizeof(T));
        }
    }

    template<typename T>
    template<typename U, typename... Args>
    void SecureAllocator<T>::construct(U *p, Args &&... args) {
        new(p) U(std::forward<Args>(args)...);
    }

    template<typename T>
    template<typename U>
    void SecureAllocator<T>::destroy(U *p) {
        p->~U();
    }

    template<typename T>
    bool SecureAllocator<T>::operator==(const SecureAllocator &other) const noexcept {
        return true;
    }

    template<typename T>
    bool SecureAllocator<T>::operator!=(const SecureAllocator &other) const noexcept {
        return false;
    }


    // SecureMemory implementation
    void *SecureMemory::allocate(size_t size) {
        if (size == 0) return nullptr;

        void *ptr = std::aligned_alloc(64, size); // alignment
        if (!ptr) {
            throw OutOfMemoryException("Failed to allocate memory");
        }

        zero(ptr, size);
        return ptr;
    }

    void SecureMemory::deallocate(void *ptr, size_t size) noexcept {
        if (ptr) {
            zero(ptr, size);
            std::free(ptr);
        }
    }

    void SecureMemory::zero(void *ptr, size_t size) noexcept {
        if (ptr && size > 0) {
            volatile char *vptr = static_cast<volatile char *>(ptr);
            for (size_t i = 0; i < size; ++i) {
                vptr[i] = 0;
            }
        }
    }

    void SecureMemory::lock(void *ptr, size_t size) {
        if (!ptr || size == 0) {
            return;
        }

        if (mlock(ptr, size) != 0) {
            throw Exception("Failed to lock memory");
        }
    }

    void SecureMemory::unlock(void *ptr, size_t size) noexcept {
        if (!ptr || size == 0) {
            return;
        }

        munlock(ptr, size);
    }

    bool SecureMemory::is_locked(void *ptr, size_t size) noexcept {
        return false;
    }


    // SecurePtr implementation
    template<typename T>
    SecurePtr<T>::SecurePtr(size_t count)
        : _ptr(nullptr),
        _size(count * sizeof(T)) {
        if (count > 0) {
            _ptr = static_cast<T *>(SecureMemory::allocate(_size));
            SecureMemory::lock(_ptr, _size);
        }
    }

    template<typename T>
    SecurePtr<T>::~SecurePtr() {
        if (_ptr) {
            SecureMemory::unlock(_ptr, _size);
            SecureMemory::deallocate(_ptr, _size);
        }
    }

    template<typename T>
    SecurePtr<T>::SecurePtr(SecurePtr &&other) noexcept
        : _ptr(other._ptr), _size(other._size) {
        other._ptr = nullptr;
        other._size = 0;
    }

    template<typename T>
    SecurePtr<T> &SecurePtr<T>::operator=(SecurePtr &&other) noexcept {
        if (this != &other) {
            if (_ptr) {
                SecureMemory::unlock(_ptr, _size);
                SecureMemory::deallocate(_ptr, _size);
            }

            _ptr = other._ptr;
            _size = other._size;
            other._ptr = nullptr;
            other._size = 0;
        }
        return *this;
    }

    template<typename T>
    void SecurePtr<T>::reset(size_t count) {
        if (_ptr) {
            SecureMemory::unlock(_ptr, _size);
            SecureMemory::deallocate(_ptr, _size);
        }

        _size = count * sizeof(T);
        if (count > 0) {
            _ptr = static_cast<T *>(SecureMemory::allocate(_size));
            SecureMemory::lock(_ptr, _size);
        } else {
            _ptr = nullptr;
        }
    }

    template<typename T>
    T *SecurePtr<T>::release() noexcept {
        T *temp = _ptr;
        _ptr = nullptr;
        _size = 0;
        return temp;
    }


    // Explicit instantiations for common types
    template
    class SecureAllocator<uint8_t>;

    template
    class SecureAllocator<char>;

    template
    class SecurePtr<uint8_t>;

    template
    class SecurePtr<char>;
}