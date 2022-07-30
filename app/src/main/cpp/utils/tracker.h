#pragma once

#include <stdint.h>
#include <pthread.h>

template<class T>
class tracker {
private:
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    volatile intptr_t table[UINT16_MAX + 1] = {};

public:
    T *get(const uint16_t port) const {
        return reinterpret_cast<T *>(__atomic_load_n(&table[port], __ATOMIC_ACQUIRE));
    }

    T *setup(const uint16_t port, T *const info) {
        intptr_t expected = 0;
        if (!__atomic_compare_exchange_n(&table[port], &expected,
                                         reinterpret_cast<intptr_t>(info), false,
                                         __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            return reinterpret_cast<T *>(expected);
        }
        return info;
    }

    bool clear(const uint16_t port, T *const info) {
        auto expected = reinterpret_cast<intptr_t>(info);
        return __atomic_compare_exchange_n(&table[port], &expected, 0L, false,
                                           __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    }

    void lock() {
        pthread_mutex_lock(&this->mutex);
    }

    void unlock() {
        pthread_mutex_unlock(&this->mutex);
    }
};