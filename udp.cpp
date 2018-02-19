#include "httpmodifier.h"
#define UDP_PK_SIZE static_cast<int>(sizeof(ip_hdr) + sizeof(udp_hdr))

//-------------------------------------------------------------------------

__LIBC_HIDDEN__ void udp_transfer(JNIEnv *env, packet_info *pi)
{
#if LOG_UDP
	LOGI("Protocol UDP from " DOT_IP_PORT_FORMAT " to " DOT_IP_PORT_FORMAT ", checksum 0x%.8x",
		 DOT_IP_PORT(&pi->pk.ip.srcaddr, pi->pk.udp.srcport),
		 DOT_IP_PORT(&pi->pk.ip.dstaddr, pi->pk.udp.dstport), pi->pk.udp.checksum);
#endif // LOG_UDP
	int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	protect_socket(env, s);
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port   = pi->pk.udp.dstport;
	addr.sin_addr.s_addr = pi->pk.ip.dstaddr;
	ssize_t r = ::sendto(s, pi->pk.udp_payload, pi->len, NULL,
						 reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
	if (r >= pi->len) {
#if LOG_UDP
		LOGI("sent %d bytes from " DOT_IP_PORT_FORMAT,
			 r, DOT_IP_PORT(&addr.sin_addr.s_addr, addr.sin_port));
#endif // LOG_UDP
		static timeval tv = { 3, 0 };
		::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
//__again:
		r = ::recvfrom(s, pi->pk.udp_payload, sizeof(pi->pk.udp_payload), 0,
					   NULL, 0);
		if (r > 0) {
#if LOG_UDP
			LOGI("received %d bytes from " DOT_IP_PORT_FORMAT,
				 r, DOT_IP_PORT(&addr.sin_addr.s_addr, addr.sin_port));
#endif // LOG_UDP
			// ip header
			pi->pk.ip.len = intrin::byteswap(static_cast<uint16_t>(UDP_PK_SIZE + r));
			EXCHANGE(pi->pk.ip.srcaddr, pi->pk.ip.dstaddr);
			ip_checksum(&pi->pk.ip);

			// udp header
			EXCHANGE(pi->pk.udp.srcport, pi->pk.udp.dstport);
			pi->pk.udp.len = intrin::byteswap(static_cast<uint16_t>(sizeof(udp_hdr) + r));
			udp_checksum(&pi->pk.udp);

#if LOG_UDP
			// debug print
			hprint(&pi->pk, UDP_PK_SIZE + r);
			errno = 0;
#endif // LOG_UDP

			// write back
			r = ::write(s_fd, &pi->pk, UDP_PK_SIZE + r);

#if LOG_UDP
			LOGI("transfer from " DOT_IP_PORT_FORMAT " to " DOT_IP_PORT_FORMAT ", %d bytes sent(%d, %d)",
				 DOT_IP_PORT(&pi->pk.ip.srcaddr, pi->pk.udp.srcport),
				 DOT_IP_PORT(&pi->pk.ip.dstaddr, pi->pk.udp.dstport),
				 r, intrin::byteswap(pi->pk.ip.len), errno);
#endif // LOG_UDP

//			goto __again;
        } else {
#if LOG_UDP
            LOGW("failed to received %d bytes from " DOT_IP_PORT_FORMAT,
                 r, DOT_IP_PORT(&addr.sin_addr.s_addr, addr.sin_port));
#endif // LOG_UDP
        } //if
    } else {
#if LOG_UDP
        LOGW("failed to send %d bytes from " DOT_IP_PORT_FORMAT,
             r, DOT_IP_PORT(&addr.sin_addr.s_addr, addr.sin_port));
#endif // LOG_UDP
    } //if
	::close(s);
}
