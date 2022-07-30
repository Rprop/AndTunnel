#pragma once

#include <pthread.h>
#include <sys/cdefs.h>
#include "log.h"

class threads {
private:
    static volatile intptr_t s_threads;

public:
    static void create(void *(*route)(void *), void *param = nullptr) {
        pthread_t thread;
        __atomic_add_fetch(&s_threads, 1, __ATOMIC_ACQ_REL);
        const int r = pthread_create(&thread, nullptr, route, param);
        if (__predict_true(r == 0)) {
            pthread_detach(thread);
        } else {
            __atomic_sub_fetch(&s_threads, 1, __ATOMIC_ACQ_REL);
            LOGE("pthread_create failed with %d", errno);
        }
    }

    static void commit() {
        __atomic_sub_fetch(&s_threads, 1, __ATOMIC_ACQ_REL);
    }

    static void wait(const intptr_t num, const useconds_t __microseconds = 8000ul) {
        // waits for any threads
        while (__atomic_load_n(&s_threads, __ATOMIC_ACQUIRE) > num) {
            usleep(__microseconds);
        }
    }
};

__attribute__((weak)) volatile intptr_t threads::s_threads = 0l;