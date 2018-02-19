#define  __STDINT_LIMITS
#define  RESERVED_PORT 1024
#include "httpmodifier.h"
#include "threadfactory.h"
#include <sys/queue.h>
#include <sys/epoll.h>

//-------------------------------------------------------------------------
typedef int jsocket;
typedef struct
{
	pthread_mutex_t lock;
	jsocket  s;
    ip_hdr   ip;
    tcp_hdr  tcp;
} *jconnTrack;
static jsocket  s_epfd;
static intptr_t s_tracktable[UINT16_MAX - RESERVED_PORT] = { 0 };

//-------------------------------------------------------------------------

static void push_epoll(jconnTrack jck)
{
	epoll_event evt;
	evt.events   = EPOLLIN | EPOLLONESHOT;
    evt.data.ptr = jck;
	epoll_ctl(s_epfd, EPOLL_CTL_ADD, jck->s, &evt);
}

//-------------------------------------------------------------------------

static void push_epoll_again(jconnTrack jck)
{
    epoll_event evt;
    evt.events = EPOLLIN | EPOLLONESHOT;
    evt.data.ptr = jck;
    epoll_ctl(s_epfd, EPOLL_CTL_MOD, jck->s, &evt);
}

//-------------------------------------------------------------------------

static void pop_epoll(int fd)
{
	epoll_ctl(s_epfd, EPOLL_CTL_DEL, fd, NULL);
}

//-------------------------------------------------------------------------

static void *tcp_reply(void *p)
{
    jconnTrack jck = static_cast<jconnTrack>(p);
    if (jck->s <= 0) {
        LOGE("unknown error occurred during %s", __FUNCTION__);
        return; // ?
    } //if

    pthread_mutex_lock(&jck->lock);

    pthread_mutex_unlock(&jck->lock);
    /*
    tcp->ack = 1;

    ssize_t ret = recv(jck->s, payload, sizeof(pi->pk.tcp_payload) - (payload - pi->pk.tcp_payload),
                       MSG_DONTWAIT);
    if (ret > 0) {
        tcp->psh = 1;

        pi->pk.ip.len = intrin::byteswap(static_cast<uint16_t>(sizeof(ip_hdr) + tcp->hdrlen * 4u + ret));
        ip_checksum(&pi->pk.ip);
    } else {
        tcp->psh = 0;
    } //if

    tcp_checksum(tcp, &pi->pk.ip);
    tcp_out(pi);
    tcp_print(tcp, false);

    // sends fin&ack to terminate current connection
    pi->pk.ip.len = intrin::byteswap(static_cast<uint16_t>(sizeof(ip_hdr) + tcp->hdrlen * 4u));
    ip_checksum(&pi->pk.ip);
    tcp->ack = 0u;
    tcp->fin = 1u;
    tcp->psh = 0u;
    tcp->seqnum = intrin::byteswap(intrin::byteswap(tcp->seqnum) + payllen);
    tcp_checksum(tcp, &pi->pk.ip);
    tcp_out(pi);
    tcp_print(tcp, false);
    */
}

//-------------------------------------------------------------------------

static void *tcp_wait(void *p)
{
    epoll_event evts[64];
    int r;
    while ((r = epoll_wait(s_epfd, evts, __countof(evts), -1)) >= 0) {
        while (--r >= 0) {
            tasks::join(tcp_reply, evts[r].data.ptr);
        }
    }
    LOGE("epoll_wait with result = %d, errno = %d", r, errno);
}

//-------------------------------------------------------------------------

__LIBC_HIDDEN__ bool construct_tcp_epoll()
{
    s_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (__predict_false(s_epfd <= -1)) {
        return false;
    } //if

    tasks::join(tcp_wait);
    return true;
}

//-------------------------------------------------------------------------

__LIBC_HIDDEN__ void destroy_tcp_epoll()
{
	if (__predict_false(s_epfd == -1)) {
		return;
	} //if

	close(s_epfd);
	s_epfd = -1;
}

//-------------------------------------------------------------------------

static jconnTrack get_conntrack(uint16_t port)
{
	return reinterpret_cast<jconnTrack>(s_tracktable[port - RESERVED_PORT - 1]);
}

//-------------------------------------------------------------------------

static void destroy_conntrack(jconnTrack jck)
{
	while (pthread_mutex_destroy(&jck->lock) == EBUSY) {
		usleep(10);
	}
	if (jck->s > 0) ::close(jck->s);
	::free(jck);
}

//-------------------------------------------------------------------------

static jconnTrack init_conntrack(uint16_t port, packet_info *pi)
{
	jconnTrack jck = static_cast<jconnTrack>(::malloc(sizeof(jconnTrack)));
    jck->s         = 0;
    pthread_mutex_init(&jck->lock, NULL);

	intptr_t &trackslot = s_tracktable[port - RESERVED_PORT - 1];	
	if (!__sync_cmpswap(&trackslot, 0, reinterpret_cast<intptr_t>(jck))) {
		destroy_conntrack(jck);
		jck = NULL;
	} //if
	return jck;
}

//-------------------------------------------------------------------------

static void destroy_conntrack_by_port(uint16_t port)
{
    intptr_t *pck = &s_tracktable[port - RESERVED_PORT - 1];
    intptr_t  jck = *pck;
	if (__sync_cmpswap(pck, jck, 0)) {
		destroy_conntrack(reinterpret_cast<jconnTrack>(jck));
	} //if
}

//-------------------------------------------------------------------------

__LIBC_HIDDEN__ void destroy_conntrack()
{
	for (intptr_t i = 0; i < __countof(s_tracktable); ++i)
	{
		if (s_tracktable[i] != 0) {
			destroy_conntrack(reinterpret_cast<jconnTrack>(s_tracktable[i]));
			s_tracktable[i] = 0;
		} //if
	} //for
}

//-------------------------------------------------------------------------

static void tcp_print(tcp_hdr *tcp, bool isin = true)
{
	char flags[32]; flags[0] = 0;
	if (tcp->syn) strcat(flags, " syn");
	if (tcp->ack) strcat(flags, " ack");
	if (tcp->psh) strcat(flags, " psh");
	if (tcp->fin) strcat(flags, " fin");
	if (tcp->rst) strcat(flags, " rst");
	if (isin) {
		LOGI("seq %u, ack %u, flags%s, windows %u",
			 intrin::byteswap(tcp->seqnum),
			 intrin::byteswap(tcp->acknum),
			 flags,
			 intrin::byteswap(tcp->window));
	} else {
		LOGD("seq %u, ack %u, flags%s, windows %u",
			 intrin::byteswap(tcp->seqnum),
			 intrin::byteswap(tcp->acknum),
			 flags,
			 intrin::byteswap(tcp->window));
	} //if
}

//-------------------------------------------------------------------------

static void tcp_out(packet_info *pi)
{
	// write back
	int ret = ::write(s_fd, &pi->pk, intrin::byteswap(pi->pk.ip.len));
#if LOG_TCP
	if (ret <= 0) {
		LOGE("write back %d bytes failed, errno = %d", intrin::byteswap(pi->pk.ip.len), errno);
	} //if
#endif // LOG_TCP
}

//-------------------------------------------------------------------------

static bool tcp_syn(JNIEnv *env, packet_info *pi, tcp_hdr *tcp, jconnTrack jck)
{
	if (jck->s > 0) {
		LOGD("dropped syn packet");
		return false;
	} //if

	jck->s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	protect_socket(env, jck->s);
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port   = tcp->srcport;
	addr.sin_addr.s_addr = pi->pk.ip.srcaddr;
	int ret = ::connect(jck->s, 
						reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
	if (ret != 0) {
		// rst
		::close(jck->s); jck->s = 0;
		tcp->syn = 0u;
		tcp->rst = 1u;
	} else {
		// ack, connected
        ::fcntl(jck->s, F_SETFL, ::fcntl(jck->s, F_GETFL, 0) | O_NONBLOCK);
	} //if

    tcp->ack    = 1u;
    tcp->acknum = intrin::byteswap(intrin::byteswap(tcp->seqnum) + 1);
    tcp->seqnum = reinterpret_cast<uint32_t>(tcp); // should be random

	tcp_checksum(tcp, &pi->pk.ip);
	tcp_out(pi);
	tcp_print(tcp, false);

    // failed and already send rst?
    if (ret != 0) return true;

    static_assert(sizeof(jck->ip) == sizeof(pi->pk.ip), "BOOM");
    static_assert(sizeof(jck->tcp) == sizeof(*tcp), "BOOM");
    memcpy(&jck->ip, &pi->pk.ip, sizeof(jck->ip));
    memcpy(&jck->tcp, tcp, sizeof(jck->tcp));
    push_epoll(jck);
    return false;
}

//-------------------------------------------------------------------------

static void tcp_fin(JNIEnv *env, packet_info *pi, tcp_hdr *tcp, jconnTrack jck)
{
	tcp->fin     = 0;
	tcp->ack     = 1u;
	uint32_t ack = tcp->acknum;
	tcp->acknum  = intrin::byteswap(intrin::byteswap(tcp->seqnum) + 1);
	tcp->seqnum  = ack;
	tcp_checksum(tcp, &pi->pk.ip);
	tcp_out(pi);
	tcp_print(tcp, false);
}

//-------------------------------------------------------------------------

static bool tcp_psh(JNIEnv *env, packet_info *pi, tcp_hdr *tcp, jconnTrack jck)
{
	char   *payload = TCP_PAYLOAD(tcp);
	ssize_t payllen = pi->len - (payload - pi->pk.tcp_payload); // excludes tcp options length

	uint32_t ack = tcp->acknum;
	tcp->acknum  = intrin::byteswap(intrin::byteswap(tcp->seqnum) + payllen);
	tcp->seqnum  = ack;
	if (jck->s <= 0) {
__send_rst:
		tcp->ack = tcp->psh = 0;
		tcp->rst = 1; // connection reset by peer
		tcp_checksum(tcp, &pi->pk.ip);
		tcp_out(pi);
		tcp_print(tcp, false);
		return true;
	} //if

	if (send(jck->s, payload, payllen, MSG_NOSIGNAL) < payllen) {
		goto __send_rst;
	} //if

	tcp->ack = 1;
    tcp->psh = 0;
    pi->pk.ip.len = intrin::byteswap(static_cast<uint16_t>(sizeof(ip_hdr) + tcp->hdrlen * 4u + 0u));
    ip_checksum(&pi->pk.ip);
	tcp_checksum(tcp, &pi->pk.ip);
	tcp_out(pi);
	tcp_print(tcp, false);

	return false;
}

//-------------------------------------------------------------------------

__LIBC_HIDDEN__ void tcp_transfer(JNIEnv *env, packet_info *pi)
{
	tcp_hdr *tcp = &pi->pk.tcp;

#if LOG_TCP
	LOGI("Protocol TCP from " DOT_IP_PORT_FORMAT " to " DOT_IP_PORT_FORMAT ", checksum 0x%.8x",
		 DOT_IP_PORT(&pi->pk.ip.srcaddr, tcp->srcport),
		 DOT_IP_PORT(&pi->pk.ip.dstaddr, tcp->dstport), tcp->checksum);
	tcp_print(tcp);
#endif // LOG_TCP

    // filter out unused packet
    if (!(tcp->fin | tcp->syn | tcp->rst | tcp->psh)) {
        return LOGD("discarded unused packet");
    } //if
	
	// ip direction
	EXCHANGE(pi->pk.ip.srcaddr, pi->pk.ip.dstaddr);
	ip_checksum(&pi->pk.ip);

	// tcp direction
	EXCHANGE(tcp->srcport, tcp->dstport);

	// connection track
	uint16_t srcport = intrin::byteswap(tcp->dstport);
	jconnTrack jck   = get_conntrack(srcport);
	if (jck == NULL) {
		if (!tcp->syn) {
			return LOGD("discarded untracked packet");
		} //if

		jck = init_conntrack(srcport, pi);
		if (!jck) {
			return LOGD("discarded redundant syn packet");
		} //if
	} //if

	bool should_destroy = false;

	pthread_mutex_lock(&jck->lock);
	if (tcp->syn) {
		should_destroy = tcp_syn(env, pi, tcp, jck);
	} else if (tcp->fin) {
		tcp_fin(env, pi, tcp, jck);
		should_destroy = true;
	} else if (tcp->psh) {
		 should_destroy = tcp_psh(env, pi, tcp, jck);
	} else { // rst, no ack required
		should_destroy = true;
	} //if
	pthread_mutex_unlock(&jck->lock);

	if (should_destroy) {
		destroy_conntrack_by_port(srcport);
	} //if
}