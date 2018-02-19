#pragma once
#include <jni.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include "httpmodifier.h"

class tasks
{
private:
    static volatile long s_threads;

public:
    static void join(void *(*route)(void *), void *param = NULL) {
        pthread_t threads;
        __atomic_increase(&s_threads);
        int r = pthread_create(&threads, NULL, route, param);
        if (__predict_true(r == 0)) {
            pthread_detach(threads);
        } else { // error
            __atomic_decrease(&s_threads);
            LOGE("pthread_create failed with errno = %d", errno);
        } //ifs
    }
    static void commit() {
        __atomic_decrease(&s_threads);
    }
    static void wait(unsigned long t = 8000ul) {
        // waits for any threads
        while (s_threads > 0) {
            usleep(t);
        }
    }
};
__selectany volatile long tasks::s_threads = 0l;