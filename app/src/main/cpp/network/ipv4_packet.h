#pragma once

#include <malloc.h>
#include "protocol/ip.h"
#include "protocol/udp.h"
#include "protocol/tcp.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic ignored "-Wmissing-declarations"
#pragma pack(1)
static constexpr int kPacketSize = 65535; // MTU
struct ipv4_packet {
    ipv4_hdr ipv4;
    union {
        struct {
            tcp_hdr tcp;
            // tcp options + payload + paddings
            char tcp_payload[kPacketSize - sizeof(ipv4_hdr) - sizeof(tcp_hdr)];
        };
        struct {
            udp_hdr udp;
            // payload + paddings
            char udp_payload[kPacketSize - sizeof(ipv4_hdr) - sizeof(udp_hdr)];
        };
    };

public:
    static ipv4_packet *allocate() {
        return static_cast<ipv4_packet *>(malloc(sizeof(ipv4_packet)));
    }

    void destroy() {
        free(this);
    }
};

static_assert(sizeof(ipv4_packet) <= kPacketSize, "kPacketSize");
#pragma pack()
#pragma clang diagnostic pop