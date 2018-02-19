#pragma once
#include <jni.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <android/log.h>

#include <jni/utils/Macros.h>
#include <jni/utils/LogUtil.h>

#include "network/net/ip.h"
#include "network/net/udp.h"
#include "network/net/tcp.h"
#include "network/intrin.h"
#include "network/checksum.h"

#define LOG_MAIN       1
#define LOG_IP         1
#define LOG_TCP        1
#define LOG_UDP        1
#define EXCHANGE(a, b) ((a) ^= ((b) ^= ((a) ^= (b))))
#define BUFFER_SIZE    (1024 * 64)
#pragma pack(1)
typedef struct
{
	ip_hdr ip;
	union {
		struct {
			tcp_hdr tcp;
			char    tcp_payload[BUFFER_SIZE - sizeof(ip_hdr) - sizeof(tcp_hdr) - sizeof(intptr_t)]; // options, with paddings
		};
		struct {
			udp_hdr udp;
			char    udp_payload[BUFFER_SIZE - sizeof(ip_hdr) - sizeof(udp_hdr) - sizeof(intptr_t)]; // with paddings
		};
	};
} packet;
#pragma pack()
typedef struct
{
	packet   pk;
	intptr_t len;
} packet_info;

__LIBC_HIDDEN__ extern jint s_fd;
__LIBC_HIDDEN__ extern void protect_socket(JNIEnv *env, int s);
__LIBC_HIDDEN__ extern void hprint(const void *vdata, int len);
__LIBC_HIDDEN__ extern void udp_transfer(JNIEnv *env, packet_info *pi);
__LIBC_HIDDEN__ extern void tcp_transfer(JNIEnv *env, packet_info *pi);
__LIBC_HIDDEN__ extern void destroy_conntrack();
__LIBC_HIDDEN__ extern bool construct_tcp_epoll();
__LIBC_HIDDEN__ extern void destroy_tcp_epoll();