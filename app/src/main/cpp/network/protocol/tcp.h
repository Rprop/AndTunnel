#pragma once

#pragma pack(1)
struct tcp_hdr {
    uint16_t srcport;
    uint16_t dstport;
    uint32_t seqnum;
    uint32_t acknum;
#if BYTE_ORDER == LITTLE_ENDIAN
    uint16_t reserved1: 4;
    uint16_t hdrlen: 4; // doff, hdrlen * 4 bytes = tcp header(with options) bytes
    uint16_t fin: 1;
    uint16_t syn: 1;
    uint16_t rst: 1;
    uint16_t psh: 1;
    uint16_t ack: 1;
    uint16_t urg: 1;
    uint16_t ece: 1;
    uint16_t cwr: 1;
#else
    uint16_t hdrlen : 4; // doff
    uint16_t reserved1 : 4;
    uint16_t cwr : 1;
    uint16_t ece : 1;
    uint16_t urg : 1;
    uint16_t ack : 1;
    uint16_t psh : 1;
    uint16_t rst : 1;
    uint16_t syn : 1;
    uint16_t fin : 1;
#endif
    uint16_t window; // << n
    uint16_t checksum;
    uint16_t urgptr;
    // options [0, 40]
    // data
};
#pragma pack()

#define TCP_PAYLOAD(hdr) ((char *)(hdr) + (hdr)->hdrlen * 4)