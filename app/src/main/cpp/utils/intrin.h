#pragma once

#include <stdint.h>
#include <endian.h>

class intrin {
public:
    static inline uint64_t byteswap(const uint64_t v) {
        return __swap64(v);
    }

    static inline int64_t byteswap(const int64_t v) {
        return static_cast<int64_t>(__swap64(static_cast<uint64_t>(v)));
    }

    static inline uint32_t byteswap(const uint32_t v) {
        return __swap32(v);
    }

    static inline int32_t byteswap(const int32_t v) {
        return static_cast<int32_t>(__swap32(static_cast<uint32_t>(v)));
    }

    static inline uint16_t byteswap(const uint16_t v) {
        return __swap16(v);
    }

    static inline int16_t byteswap(const int16_t v) {
        return static_cast<int16_t>(__swap16(static_cast<uint16_t>(v)));
    }
};