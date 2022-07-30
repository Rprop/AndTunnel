#include <jni.h>
#include <unistd.h>
#include <errno.h> // NOLINT(modernize-deprecated-headers)
#include <string.h> // NOLINT(modernize-deprecated-headers)
#include <assert.h> // NOLINT(modernize-deprecated-headers)
#include <asm-generic/fcntl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <malloc.h>
#include <sched.h>
#include "network/ipv4_packet.h"
#include "utils/log.h"
#include "utils/threads.h"
#include "utils/intrin.h"
#include "utils/events.h"
#include "utils/tracker.h"

#if (__GNUC__ >= 3)
# define likely(x)      __builtin_expect(!!(x), 1)
# define unlikely(x)    __builtin_expect(!!(x), 0)
#else
# define likely(x)	    (x)
# define unlikely(x)	(x)
#endif

#define TEST_CHECKSUM 0
extern "C" {
#if defined(__aarch64__)
#include "kernel/arm64/checksum.h"
#elif defined(__arm__)
#include "kernel/arm/checksum.h"
#endif
}

// -------------------------------------------------------------------------------------------------

static JavaVM *sJavaVM;
static jint sVpnFd;
static jweak sVpnService;
static jmethodID method_VpnService_protect;

// -------------------------------------------------------------------------------------------------

extern "C" JNIEXPORT void JNICALL
Java_rprop_net_tunnel_CoreService_closeFd(JNIEnv *, jclass, jint fd) {
    close(fd);
}

// -------------------------------------------------------------------------------------------------

static void protect_socket(const int fd) {
    JNIEnv *env;
    sJavaVM->AttachCurrentThread(&env, nullptr);
    jboolean ret = env->CallBooleanMethod(sVpnService, method_VpnService_protect, fd);
    if (env->ExceptionCheck() || !ret) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        LOGE("protect socket failed %d", fd);
    }
    sJavaVM->DetachCurrentThread();
}

// -------------------------------------------------------------------------------------------------

struct epoll_info {
    uint32_t events;
    int fd;
    void *callback;
    pthread_mutex_t mutex;
    ipv4_packet packet;
    uint16_t port;

public:
    void lock() {
        pthread_mutex_lock(&this->mutex);
    }

    void unlock() {
        pthread_mutex_unlock(&this->mutex);
    }

protected:
    void close_fd() {
        if (this->fd >= 0) {
            close(this->fd);
            this->fd = -1;
        }
    }

    void destroy_lock() {
        while (pthread_mutex_destroy(&this->mutex) == EBUSY) {
            usleep(10);
        }
    }

protected:
    static void *allocate(const size_t byte_count) {
        auto info = static_cast<epoll_info *>(malloc(byte_count));
        info->fd = -1;
        info->mutex = PTHREAD_MUTEX_INITIALIZER;
        return info;
    }

    static void deallocate(epoll_info *const info) {
        info->close_fd();
        info->destroy_lock();
        free(info);
    }
};

static void *dispatch_epoll_events(void *) {
    epoll_event evt[64];
    int r;
    while ((r = epoll_wait(events::s_epoll_fd, evt, sizeof(evt) / sizeof(evt[0]), -1)) >= 0) {
        while (--r >= 0) {
            auto info = static_cast<epoll_info *>(evt[r].data.ptr);
            info->events = evt[r].events;
            threads::create(reinterpret_cast<void *(*)(void *)>(info->callback), info);
        }
    }
    return nullptr;
}

// -------------------------------------------------------------------------------------------------

static inline void initialize_ipv4_hdr(ipv4_hdr *const ipv4, const uint8_t protocol,
                                       const uint32_t src, const uint32_t dst) {
    memset(ipv4, 0, sizeof(*ipv4));
    ipv4->hdrlen = sizeof(ipv4_hdr) / 4u;
    ipv4->version = 4u;
    ipv4->protocol = protocol;
    ipv4->srcaddr = src;
    ipv4->dstaddr = dst;
}

static inline void hex_print(const char *tag, const void *ptr, const size_t len) {
    const auto *data = static_cast<const unsigned char *>(ptr);
    int k = 0;
    char sb[kPacketSize];
    sb[0] = '\0';
    for (size_t i = 0; i < len; ++i) {
        if (i != 0 && i % 16 == 0) k += sprintf(sb + k, "\n");
        k += sprintf(sb + k, "%02hhx ", data[i]);
    }
    LOGI("%s\n%s", tag, sb);
}

// -------------------------------------------------------------------------------------------------

struct udp_info : epoll_info {
public:
    static udp_info *allocate(const uint16_t port) {
        auto info = static_cast<udp_info *>(epoll_info::allocate(sizeof(udp_info)));
        info->port = port;
        return info;
    }

public:
    void destroy() {
        epoll_info::deallocate(this);
    }
};

static tracker<udp_info> sUdpTracker;

static void destroy_locked_udp_info(udp_info *const info) {
    if (sUdpTracker.clear(info->port, info)) {
        // unnecessary since we get called from transfer_udp_reply.
        // events::unregister_fd(info->fd);
        info->unlock();
        sched_yield();
        sched_yield();
        info->lock();
        info->unlock();
        info->destroy();
    }
}

static void *transfer_udp_reply(udp_info *const info) {
    info->lock();
    if (info->events & EPOLLERR) {
        UDP_LOGE("[UDP] EPOLLERR on socket %d", info->fd);
        destroy_locked_udp_info(info);
        return reinterpret_cast<void *>(EPOLLERR); // Make lint happy
    }

    sockaddr_in address = {};
    socklen_t address_len = sizeof(address);
    ssize_t r = recvfrom(info->fd, info->packet.udp_payload, sizeof(info->packet.udp_payload),
                         0, reinterpret_cast<sockaddr *>(&address), &address_len);
    if (r < 0) {
        UDP_LOGE("[UDP] recvfrom failed with %d from " DOT_IPV4_PORT_FORMAT,
                 errno,
                 DOT_IPV4_PORT(&info->packet.ipv4.srcaddr, info->packet.udp.srcport));
        destroy_locked_udp_info(info);
        return nullptr;
    }

    UDP_LOGI("[UDP] received %zd bytes from " DOT_IPV4_PORT_FORMAT " on socket %d",
             r,
             DOT_IPV4_PORT(&address.sin_addr.s_addr, address.sin_port),
             info->fd);

    // ipv4 header
    const size_t ipv4_size = sizeof(ipv4_hdr) + sizeof(udp_hdr) + r;
    info->packet.ipv4.len = intrin::byteswap(static_cast<uint16_t>(ipv4_size));
    info->packet.ipv4.srcaddr = address.sin_addr.s_addr;
    info->packet.ipv4.checksum = 0;
    info->packet.ipv4.checksum = ip_fast_csum(&info->packet.ipv4, info->packet.ipv4.hdrlen);

    // udp header
    const auto payload_len = static_cast<__u32>(sizeof(udp_hdr) + r);
    info->packet.udp.len = intrin::byteswap(static_cast<uint16_t>(payload_len));
    info->packet.udp.srcport = address.sin_port;
    info->packet.udp.checksum = 0;
    const auto partial = csum_partial(&info->packet.udp, static_cast<int>(payload_len), 0);
    info->packet.udp.checksum = csum_tcpudp_magic(info->packet.ipv4.srcaddr,
                                                  info->packet.ipv4.dstaddr,
                                                  payload_len,
                                                  IPPROTO_UDP,
                                                  partial);
    // write back
    r = write(sVpnFd, &info->packet.ipv4, ipv4_size);

    UDP_LOGI(
            "[UDP] transferd %zd bytes from " DOT_IPV4_PORT_FORMAT " to " DOT_IPV4_PORT_FORMAT,
            r,
            DOT_IPV4_PORT(&info->packet.ipv4.srcaddr, info->packet.udp.srcport),
            DOT_IPV4_PORT(&info->packet.ipv4.dstaddr, info->packet.udp.dstport));

    events::rearm_fd(info->fd, info, EPOLLIN | EPOLLONESHOT);
    info->unlock();
    return nullptr;
}

static void transfer_udp_req(ipv4_hdr *const ipv4, udp_hdr *const udp) {
    UDP_LOGI("[UDP] from " DOT_IPV4_PORT_FORMAT " to " DOT_IPV4_PORT_FORMAT ", checksum 0x%.8x",
             DOT_IPV4_PORT(&ipv4->srcaddr, udp->srcport),
             DOT_IPV4_PORT(&ipv4->dstaddr, udp->dstport),
             udp->checksum);
    const __u32 ip_payload_len = intrin::byteswap(ipv4->len) - sizeof(ipv4_hdr);
#if TEST_CHECKSUM
    udp->checksum = 0;
    UDP_LOGI("[UDP] checksum 0x%.8x", csum_tcpudp_magic(ipv4->srcaddr,
                                                        ipv4->dstaddr,
                                                        ip_payload_len,
                                                        IPPROTO_UDP,
                                                        csum_partial(udp, ip_payload_len, 0)));
#endif // TEST_CHECKSUM

    auto info = udp_info::allocate(intrin::byteswap(udp->srcport));
    auto exist = sUdpTracker.setup(info->port, info);
    if (info != exist) {
        exist->lock();
        info->destroy();
        info = exist;
    } else {
        info->lock();
    }

    if (info->fd < 0) {
        // TODO UDP Socket Pool
        const int udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
        if (udp_fd < 0) {
            UDP_LOGE("[UDP] socket failed with %d", errno);
            info->unlock();
            return;
        }

        protect_socket(udp_fd);
        info->callback = reinterpret_cast<void *>(transfer_udp_reply);
        info->fd = udp_fd;
        initialize_ipv4_hdr(&info->packet.ipv4, IPPROTO_UDP, INADDR_NONE, ipv4->srcaddr);
        info->packet.udp.dstport = udp->srcport;
        events::register_fd(udp_fd, info, EPOLLIN | EPOLLONESHOT);
    }

    const sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_port = udp->dstport,
            .sin_addr = {.s_addr = ipv4->dstaddr}
    };
    const size_t len = ip_payload_len - sizeof(udp_hdr);
    const ssize_t rt = sendto(info->fd, udp + 1, len, MSG_NOSIGNAL,
                              reinterpret_cast<const sockaddr *>(&address), sizeof(address));
    if (rt > 0 && rt >= len) {
        UDP_LOGI("[UDP] sent %zd bytes to " DOT_IPV4_PORT_FORMAT " on socket %d",
                 rt,
                 DOT_IPV4_PORT(&address.sin_addr.s_addr, address.sin_port),
                 info->fd);
    } else {
        UDP_LOGE("[UDP] failed to send %zd bytes to " DOT_IPV4_PORT_FORMAT " on socket %d",
                 rt,
                 DOT_IPV4_PORT(&address.sin_addr.s_addr, address.sin_port),
                 info->fd);
    }

    info->unlock();
}

// -------------------------------------------------------------------------------------------------

struct retransmit_packet {
    ipv4_packet packet;
    __kernel_old_time_t tv_sec;
    LIST_ENTRY(retransmit_packet) entries;

public:
    static retransmit_packet *allocate(const ipv4_packet *packet, const size_t size) {
        auto pk = static_cast<retransmit_packet *>(malloc(sizeof(retransmit_packet)));
        memcpy(&pk->packet, packet, size);
        pk->tv_sec = 0;
        assert(size == intrin::byteswap(pk->packet.ipv4.len));
        return pk;
    }

    void destroy() {
        free(this);
    }
};

LIST_HEAD(retransmit_list, retransmit_packet);

struct tcp_info : epoll_info {
    ipv4_packet packet;
    ipv4_packet *backlog[128];
    uint16_t count;
    uint16_t port;
    retransmit_list retransmit;

public:
    static tcp_info *allocate(const uint16_t port) {
        auto info = static_cast<tcp_info *>(epoll_info::allocate(sizeof(tcp_info)));
        info->port = port;
        info->count = 0;
        LIST_INIT(&info->retransmit);
        return info;
    }

    static void dump(const ipv4_hdr *const ipv4, const tcp_hdr *const tcp) {
        const __u32 ip_payload_len = intrin::byteswap(ipv4->len) - sizeof(ipv4_hdr);
        const __u32 tcp_payload_len = ip_payload_len - tcp->hdrlen * 4u;
        TCP_LOGI(
                "[TCP] " DOT_IPV4_PORT_FORMAT " -> " DOT_IPV4_PORT_FORMAT ", seq %u, ack %u, '%s%s%s%s%s%s%s%s', windows %u, tcp payload %u",
                DOT_IPV4_PORT(&ipv4->srcaddr, tcp->srcport),
                DOT_IPV4_PORT(&ipv4->dstaddr, tcp->dstport),
                intrin::byteswap(tcp->seqnum),
                intrin::byteswap(tcp->acknum),
                tcp->fin ? "fin" : "",
                tcp->syn ? "syn" : "",
                tcp->rst ? "rst" : "",
                tcp->psh ? "psh" : "",
                tcp->ack ? "ack" : "",
                tcp->urg ? "urg" : "",
                tcp->ece ? "ece" : "",
                tcp->cwr ? "cwr" : "",
                intrin::byteswap(tcp->window),
                tcp_payload_len);
        // hex_print("[TCP]", TCP_PAYLOAD(tcp), tcp_payload_len);
    }

public:
    void push_backlog(ipv4_packet *const pk) {
        if (this->count > 0) {
            const uint16_t index = find_backlog(pk->tcp.seqnum);
            if (index != UINT16_MAX) {
                this->backlog[index]->destroy();
                this->backlog[index] = pk;
                return;
            }
            if (this->count >= sizeof(this->backlog) / sizeof(this->backlog[0])) {
                TCP_LOGE("[TCP] backlog full on port %u", this->port);
                return;
            }
        }
        this->backlog[this->count] = pk;
        ++this->count;
    }

    uint16_t find_backlog(const uint32_t seq) {
        for (uint16_t index = 0; index < this->count; ++index) {
            if (this->backlog[index]->tcp.seqnum == seq) {
                return index;
            }
        }
        return UINT16_MAX;
    }

    ipv4_packet *pop_backlog(const uint16_t position) {
        ipv4_packet *const pk = this->backlog[position];
        for (uint16_t index = position + 1; index < this->count; ++index) {
            this->backlog[index - 1] = this->backlog[index];
        }
        --this->count;
        return pk;
    }

    void clear_backlog() {
        for (uint16_t index = 0; index < this->count; ++index) {
            this->backlog[index]->destroy();
        }
        this->count = 0;
    }

public:
    void push_retransmit(retransmit_packet *const item) {
        const uint32_t seq = intrin::byteswap(item->packet.tcp.seqnum);
        TCP_DEBUG("[TCP_DEBUG] push_retransmit seq %u", seq);
        auto n = LIST_FIRST(&this->retransmit);
        while (n != nullptr) {
            const uint32_t n_seq = intrin::byteswap(n->packet.tcp.seqnum);
            if (seq >= n_seq) {
                LIST_INSERT_BEFORE(n, item, entries);
                return;
            }
            n = LIST_NEXT(n, entries);
        }
        LIST_INSERT_HEAD(&this->retransmit, item, entries);
    }

    void pop_ack_retransmit(const uint32_t ack) {
        auto n1 = LIST_FIRST(&this->retransmit);
        while (n1 != nullptr) {
            const uint32_t n_seq = intrin::byteswap(n1->packet.tcp.seqnum);
            if (ack > n_seq) {
                do {
                    auto *n2 = LIST_NEXT(n1, entries);
                    LIST_REMOVE(n1, entries);
                    TCP_DEBUG("[TCP_DEBUG] pop_ack_retransmit seq %u",
                              intrin::byteswap(n1->packet.tcp.seqnum));
                    n1->destroy();
                    n1 = n2;
                } while (n1 != nullptr);
                break;
            }
            n1 = LIST_NEXT(n1, entries);
        }
    }

    void check_retransmit(const uint32_t ack) {
        struct timeval tv = {};
        gettimeofday(&tv, nullptr);

        auto n1 = LIST_FIRST(&this->retransmit);
        while (n1 != nullptr) {
            const uint32_t n_seq = intrin::byteswap(n1->packet.tcp.seqnum);
            if (ack == n_seq) {
                if ((tv.tv_sec - n1->tv_sec) > 1) {
                    TCP_DEBUG("[TCP_DEBUG] check_retransmit resend seq %u", n_seq);
                    n1->tv_sec = tv.tv_sec;
                    write(sVpnFd, &n1->packet.ipv4, intrin::byteswap(n1->packet.ipv4.len));
                }
            } else if (ack > n_seq) {
                break;
            }
            n1 = LIST_NEXT(n1, entries);
        }
    }

    void clear_retransmit() {
        auto n1 = LIST_FIRST(&this->retransmit);
        while (n1 != nullptr) {
            auto *n2 = LIST_NEXT(n1, entries);
            n1->destroy();
            n1 = n2;
        }
        LIST_INIT(&this->retransmit);
    }

public:
    ssize_t send_ipv4_to_local(const __u32 tcp_payload_len) {
        // ipv4 header
        const size_t ipv4_size = sizeof(ipv4_hdr) + sizeof(tcp_hdr) + tcp_payload_len;
        packet.ipv4.len = intrin::byteswap(static_cast<uint16_t>(ipv4_size));
        packet.ipv4.checksum = 0;
        packet.ipv4.checksum = ip_fast_csum(&packet.ipv4, packet.ipv4.hdrlen);

        // tcp header
        const __u32 ip_payload_len = ipv4_size - sizeof(ipv4_hdr);
        packet.tcp.checksum = 0;
        packet.tcp.checksum = csum_tcpudp_magic(packet.ipv4.srcaddr,
                                                packet.ipv4.dstaddr,
                                                ip_payload_len,
                                                IPPROTO_TCP,
                                                csum_partial(&packet.tcp,
                                                             static_cast<int>(ip_payload_len),
                                                             0));

        if (tcp_payload_len > 0) {
            push_retransmit(retransmit_packet::allocate(&packet, ipv4_size));
        }

        // write back
        return write(sVpnFd, &packet.ipv4, ipv4_size);
    }

    void dump() const {
        dump(&packet.ipv4, &packet.tcp);
    }

    void destroy() {
        clear_backlog();
        clear_retransmit();
        epoll_info::deallocate(this);
    }
};

static tracker<tcp_info> sTcpTracker;

static void destroy_locked_tcp_info(tcp_info *const info) {
    if (sTcpTracker.clear(info->port, info)) {
        events::unregister_fd(info->fd);
        info->unlock();
        sched_yield();
        sched_yield();
        info->lock();
        info->unlock();
        info->destroy();
    }
}

static void *transfer_tcp_reply(tcp_info *info) {
    info->lock();
    if (info->events & EPOLLERR) {
        TCP_LOGE("[TCP] EPOLLERR on socket %d", info->fd);
        // RST
        info->packet.tcp.syn = 0;
        info->packet.tcp.ack = 1;
        info->packet.tcp.rst = 1;
        info->send_ipv4_to_local(0);
        info->dump();
        destroy_locked_tcp_info(info);
        return reinterpret_cast<void *>(EPOLLERR); // Make lint happy
    }

    auto &packet = info->packet;
    if (info->events & EPOLLOUT) {
        TCP_LOGI("[TCP] connected on socket %d", info->fd);
        packet.tcp.ack = 1;
        info->send_ipv4_to_local(0);
        info->dump();
        packet.tcp.seqnum = intrin::byteswap(intrin::byteswap(packet.tcp.seqnum) + 1);
        events::rearm_fd(info->fd, info, EPOLLIN | EPOLLONESHOT);
    } else { // EPOLLIN
        TCP_LOGI("[TCP] data avail on socket %d", info->fd);
        const ssize_t rt = read(info->fd, packet.tcp_payload, sizeof(packet.tcp_payload));
        if (rt < 0) {
            TCP_LOGE("[TCP] read failed with %d from " DOT_IPV4_PORT_FORMAT,
                     errno,
                     DOT_IPV4_PORT(&info->packet.ipv4.srcaddr, info->packet.udp.srcport));
            // RST
            info->packet.tcp.syn = 0;
            info->packet.tcp.ack = 1;
            info->packet.tcp.rst = 1;
            info->send_ipv4_to_local(0);
            info->dump();
            destroy_locked_tcp_info(info);
            return nullptr;
        }
        if (unlikely(rt == 0)) {
            TCP_LOGE("[TCP] read zero bytes from " DOT_IPV4_PORT_FORMAT,
                     DOT_IPV4_PORT(&info->packet.ipv4.srcaddr, info->packet.udp.srcport));
            // FIN
            info->packet.tcp.syn = 0;
            info->packet.tcp.ack = 1;
            info->packet.tcp.fin = 1;
            info->send_ipv4_to_local(0);
            info->dump();
        } else {
            TCP_LOGI(
                    "[TCP] transferd %zd bytes from " DOT_IPV4_PORT_FORMAT " to " DOT_IPV4_PORT_FORMAT,
                    rt,
                    DOT_IPV4_PORT(&packet.ipv4.srcaddr, packet.udp.srcport),
                    DOT_IPV4_PORT(&packet.ipv4.dstaddr, packet.udp.dstport));
            packet.tcp.syn = 0;
            packet.tcp.ack = 1;
            info->send_ipv4_to_local(rt);
            info->dump();

            packet.tcp.seqnum = intrin::byteswap(
                    static_cast<uint32_t>(intrin::byteswap(packet.tcp.seqnum) + rt));
            events::rearm_fd(info->fd, info, EPOLLIN | EPOLLONESHOT);
        }
    }
    info->unlock();
    return nullptr;
}

static void transfer_tcp_req_rst(tcp_hdr *const tcp) {
    auto info = sTcpTracker.get(intrin::byteswap(tcp->srcport));
    if (info == nullptr) {
        TCP_LOGE("[TCP] no tcp info port %d", intrin::byteswap(tcp->srcport));
        return;
    }
    info->lock();
    destroy_locked_tcp_info(info);
}

static void transfer_tcp_req_fin(tcp_hdr *const tcp) {
    auto info = sTcpTracker.get(intrin::byteswap(tcp->srcport));
    if (info == nullptr) {
        TCP_LOGE("[TCP] no tcp info port %d", intrin::byteswap(tcp->srcport));
        return;
    }
    info->lock();

    info->packet.tcp.syn = 0;
    info->packet.tcp.ack = 1;
    info->packet.tcp.fin = 1;
    info->packet.tcp.acknum = intrin::byteswap(intrin::byteswap(info->packet.tcp.acknum) + 1);
    info->send_ipv4_to_local(0);
    info->dump();

    destroy_locked_tcp_info(info);
}

static bool transfer_tcp_req_data_locked(tcp_info *const info, ipv4_packet *const packet) {
    const __u32 ip_payload_len = intrin::byteswap(packet->ipv4.len) - sizeof(ipv4_hdr);
    const __u32 tcp_payload_len = ip_payload_len - packet->tcp.hdrlen * 4u;
    if (tcp_payload_len > 0) {
        info->packet.tcp.acknum = intrin::byteswap(
                intrin::byteswap(packet->tcp.seqnum) + tcp_payload_len);
        const ssize_t rt = send(info->fd, TCP_PAYLOAD(&packet->tcp), tcp_payload_len, 0);
        if (rt < 0) {
            TCP_LOGE("[TCP] send failed with %d to " DOT_IPV4_PORT_FORMAT,
                     errno,
                     DOT_IPV4_PORT(&info->packet.ipv4.srcaddr, info->packet.udp.srcport));
            // RST
            info->packet.tcp.syn = 0;
            info->packet.tcp.ack = 1;
            info->packet.tcp.rst = 1;
            info->send_ipv4_to_local(0);
            info->dump();
            destroy_locked_tcp_info(info);
            return false;
        }
        TCP_LOGI(
                "[TCP] transferd %zd bytes from " DOT_IPV4_PORT_FORMAT " to " DOT_IPV4_PORT_FORMAT,
                rt,
                DOT_IPV4_PORT(&info->packet.ipv4.dstaddr, info->packet.udp.dstport),
                DOT_IPV4_PORT(&info->packet.ipv4.srcaddr, info->packet.udp.srcport));

        info->packet.tcp.syn = 0;
        info->packet.tcp.ack = 1;
        info->send_ipv4_to_local(0);
        info->dump();
    } else {
        info->check_retransmit(intrin::byteswap(packet->tcp.acknum));
    }
    return true;
}

static bool transfer_tcp_req_data(ipv4_packet *const packet, tcp_hdr *const tcp) {
    auto info = sTcpTracker.get(intrin::byteswap(tcp->srcport));
    if (info == nullptr) {
        TCP_LOGE("[TCP] no tcp info port %d", intrin::byteswap(tcp->srcport));
        return false;
    }
    info->lock();
    info->pop_ack_retransmit(intrin::byteswap(tcp->acknum));

    if (tcp->seqnum != info->packet.tcp.acknum) {
        TCP_DEBUG("[TCP_DEBUG] push_backlog port %u seq %u ack %u",
                  info->port,
                  intrin::byteswap(tcp->seqnum),
                  intrin::byteswap(info->packet.tcp.acknum));
        info->push_backlog(packet);
        info->unlock();
        return true; // keep packet alive
    }

    if (!transfer_tcp_req_data_locked(info, packet)) return false;

    uint32_t index;
    while ((index = info->find_backlog(info->packet.tcp.acknum)) != UINT16_MAX) {
        ipv4_packet *const backlog_packet = info->pop_backlog(index);
        const bool r = transfer_tcp_req_data_locked(info, backlog_packet);
        backlog_packet->destroy();
        if (!r) return false;
    }

    info->unlock();
    return false;
}

static void transfer_tcp_req_syn(ipv4_hdr *const ipv4, tcp_hdr *const tcp) {
    auto info = tcp_info::allocate(intrin::byteswap(tcp->srcport));
    auto exist = sTcpTracker.setup(info->port, info);
    if (info != exist) {
        TCP_LOGE("[TCP] duplicated syn on port %d", info->port);
        info->destroy();
        return;
    }
    info->lock();

    const int tcp_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    if (tcp_fd < 0) {
        TCP_LOGE("[TCP] socket failed with %d", errno);
        destroy_locked_tcp_info(info);
        return;
    }
    info->fd = tcp_fd;
    protect_socket(tcp_fd);

    const sockaddr_in address = {
            .sin_family = AF_INET,
            .sin_port = tcp->dstport,
            .sin_addr = {.s_addr = ipv4->dstaddr}
    };
    const int rt = connect(tcp_fd, reinterpret_cast<const sockaddr *>(&address),
                           sizeof(address));
    if (rt < 0 && errno != EINPROGRESS) {
        TCP_LOGE("[TCP] connect failed with %d", errno);
        destroy_locked_tcp_info(info);
        return;
    }

    info->callback = reinterpret_cast<void *>(transfer_tcp_reply);
    initialize_ipv4_hdr(&info->packet.ipv4, IPPROTO_TCP, ipv4->dstaddr, ipv4->srcaddr);
    memset(&info->packet.tcp, 0, sizeof(info->packet.tcp));
    info->packet.tcp.srcport = tcp->dstport;
    info->packet.tcp.dstport = tcp->srcport;
    info->packet.tcp.seqnum = 0; // should be random
    info->packet.tcp.acknum = intrin::byteswap(intrin::byteswap(tcp->seqnum) + 1);
    info->packet.tcp.hdrlen = sizeof(tcp_hdr) / 4;
    info->packet.tcp.syn = 1;
    info->packet.tcp.window = 65535;
    events::register_fd(tcp_fd, info, EPOLLOUT | EPOLLONESHOT);

    info->unlock();
}

static void transfer_tcp_req(ipv4_packet *const packet, ipv4_hdr *const ipv4, tcp_hdr *const tcp) {
#if TEST_CHECKSUM
    const __u32 ip_payload_len = intrin::byteswap(ipv4->len) - sizeof(ipv4_hdr);
    const __u32 tcp_payload_len = ip_payload_len - tcp->hdrlen * 4u;
    TCP_LOGI("[TCP] from " DOT_IPV4_PORT_FORMAT " to " DOT_IPV4_PORT_FORMAT ", checksum 0x%.8x",
             DOT_IPV4_PORT(&ipv4->srcaddr, tcp->srcport),
             DOT_IPV4_PORT(&ipv4->dstaddr, tcp->dstport),
             tcp->checksum);
    tcp->checksum = 0;
    TCP_LOGI("[TCP] checksum 0x%.8x", csum_tcpudp_magic(ipv4->srcaddr,
                                                        ipv4->dstaddr,
                                                        ip_payload_len,
                                                        IPPROTO_TCP,
                                                        csum_partial(tcp, ip_payload_len, 0)));
    TCP_LOGI("[TCP] ipv4 header size %u, size %u, tcp header size %u, size %u, tcp payload %u",
             sizeof(ipv4_hdr),
             __swap16(ipv4->len),
             sizeof(tcp_hdr),
             tcp->hdrlen * 4,
             tcp_payload_len);
#endif // TEST_CHECKSUM
    tcp_info::dump(ipv4, tcp);

    if (tcp->syn) {
        transfer_tcp_req_syn(ipv4, tcp);
    } else if (tcp->rst) {
        transfer_tcp_req_rst(tcp);
    } else if (tcp->ack) {
        if (transfer_tcp_req_data(packet, tcp)) {
            return;
        }
        if (tcp->fin) {
            transfer_tcp_req_fin(tcp);
        }
    } else {
        TCP_LOGE("[TCP] Unknown tcp packet without 'ack' flag");
    }

    packet->destroy();
}

// -------------------------------------------------------------------------------------------------

static void transfer_ip(ipv4_packet *const packet) {
    const ssize_t len = __swap16(packet->ipv4.len);
    LOGI("[IP] from " DOT_IPV4_FORMAT " to " DOT_IPV4_FORMAT ", size %zd, checksum 0x%.8x",
         DOT_IPV4(&packet->ipv4.srcaddr),
         DOT_IPV4(&packet->ipv4.dstaddr),
         len,
         packet->ipv4.checksum);
#if TEST_CHECKSUM
    packet->ipv4.checksum = 0;
    LOGI("[IP] checksum 0x%.8x", ip_fast_csum(&packet->ipv4, packet->ipv4.hdrlen));
#endif // TEST_CHECKSUM

    switch (packet->ipv4.protocol) {
        case IPPROTO_TCP: {
            transfer_tcp_req(packet, &packet->ipv4, &packet->tcp);
            return;
        }
        case IPPROTO_UDP: {
            transfer_udp_req(&packet->ipv4, &packet->udp);
            break;
        }
        default: {
            LOGE("[IP] Unknown protocol %u, packet len %u", packet->ipv4.protocol,
                 packet->ipv4.len);
            break;
        }
    }

    packet->destroy();
}

// -------------------------------------------------------------------------------------------------

extern "C" JNIEXPORT void JNICALL
Java_rprop_net_tunnel_CoreService_transferIpPackage(JNIEnv *env, jclass clazz, jint fd,
                                                    jobject vpn) {
    LOGI("Native started: %p, %p, 0x%.8x, %p", env, clazz, fd, vpn);

    env->GetJavaVM(&sJavaVM);
    sVpnFd = fd;
    sVpnService = env->NewWeakGlobalRef(vpn);
    method_VpnService_protect = env->GetMethodID(env->GetObjectClass(vpn), "protect", "(I)Z");
    LOGI("ref = %p, protect = %p", sVpnService, method_VpnService_protect);

    // ---------------------------------------------------------------------------------------------

    threads::create([](void *) -> void * {
        fcntl(sVpnFd, F_SETFL, fcntl(sVpnFd, F_GETFL) & ~O_NONBLOCK);
        events::construct_epoll();
        threads::create(dispatch_epoll_events, nullptr);

        ssize_t len;
        auto packet = ipv4_packet::allocate();
        while ((len = read(sVpnFd, packet, sizeof(ipv4_packet))) > 0) {
            LOGI("Read %zd bytes from /dev/tun %d", len, sVpnFd);
            if (len <= static_cast<ssize_t>(sizeof(ipv4_hdr)) ||
                len != __swap16(packet->ipv4.len)) {
                LOGE("Wrong ipv4 packet, got %zd bytes", len);
                continue;
            }
            if (packet->ipv4.version != 4u) {
                LOGE("Unsupported Ip version %u", packet->ipv4.version);
                continue;
            }
            if (packet->ipv4.hdrlen != sizeof(ipv4_hdr) / 4u) {
                LOGE("Invalid Ip header length %u", packet->ipv4.hdrlen);
                continue;
            }
            threads::create(reinterpret_cast<void *(*)(void *)>(transfer_ip), packet);
            packet = ipv4_packet::allocate();
        }
        if (packet != nullptr) packet->destroy();
        LOGI("Packet transfer exited with %d", errno);

        threads::wait(1);
        threads::commit();

        events::destroy_epoll();

        JNIEnv *env;
        sJavaVM->AttachCurrentThread(&env, nullptr);
        env->DeleteWeakGlobalRef(sVpnService);
        sJavaVM->DetachCurrentThread();
        sJavaVM = nullptr;
        sVpnService = nullptr;
        sVpnFd = -1;

        return nullptr;
    }, nullptr);
}