#pragma once

#include <unistd.h>
#include <sys/epoll.h>

class events {
public:
    static int s_epoll_fd;

public:
    static void construct_epoll() {
        s_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    }

    static void destroy_epoll() {
        close(s_epoll_fd);
        s_epoll_fd = -1;
    }

    static void register_fd(const int fd, const void *ptr, const uint32_t events) {
        epoll_event evt = {
                .events = events,
                .data = {.ptr = const_cast<void *>(ptr)}
        };
        epoll_ctl(s_epoll_fd, EPOLL_CTL_ADD, fd, &evt);
    }

    static void rearm_fd(const int fd, const void *ptr, const uint32_t events) {
        epoll_event evt = {
                .events = events,
                .data = {.ptr = const_cast<void *>(ptr)}
        };
        epoll_ctl(s_epoll_fd, EPOLL_CTL_MOD, fd, &evt);
    }

    static void unregister_fd(const int fd) {
        epoll_ctl(s_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
    }
};

__attribute__((weak)) int events::s_epoll_fd = -1;