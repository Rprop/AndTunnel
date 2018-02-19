#include "httpmodifier.h"
#include "threadfactory.h"

//-------------------------------------------------------------------------

typedef volatile int jatomic;
__LIBC_HIDDEN__ jint s_fd;
static JavaVM   *s_javavm;
static jmethodID s_protect;
static jobject   s_vpn;
__COPYRIGHT("http://rlib.cf/");

//-------------------------------------------------------------------------

__LIBC_HIDDEN__ void protect_socket(JNIEnv *env, int s)
{
	jboolean jret = env->CallBooleanMethod(s_vpn, s_protect, s);
	if (unlikely(!jret)) {
		LOGW("protect socket failed %d", s);
	} //if
}

//-------------------------------------------------------------------------

__LIBC_HIDDEN__ void hprint(const void *vdata, int len)
{
	const unsigned char *data = static_cast<const unsigned char *>(vdata);
	int k = 0;
	char sb[BUFFER_SIZE];
	for (int i = 0; i < len; ++i) {
		k += sprintf(sb + k, "%02hhx ", *(data + i));
		if (i % 16 == 0 && i != 0) k += sprintf(sb + k, "\n");
	}
	LOGI("%s\n", sb);
}

//-------------------------------------------------------------------------

static void *transfer(packet_info *pi)
{
	JNIEnv *env;
	s_javavm->AttachCurrentThread(&env, NULL);
	pi->pk.ip.protocol == IPPROTO_TCP ? 
		tcp_transfer(env, pi) : udp_transfer(env, pi);
	s_javavm->DetachCurrentThread();
	::free(pi);
	
	tasks::commit();
	return NULL;
}

//-------------------------------------------------------------------------

static void setup_transfer(packet_info *pi)
{
	tasks::join(reinterpret_cast<void *(*)(void *)>(transfer), pi);
}

//-------------------------------------------------------------------------

static bool ip_transfer(packet_info *pi)
{
	ip_hdr *ip = &pi->pk.ip;

	if (unlikely(ip->version != 4u)) {
		LOGW("Unsupported Ip version %u", ip->version);
		return false;
	} //if
	
	if (unlikely(ip->hdrlen != sizeof(ip_hdr) / 4u)) {
		LOGW("Ip header length %u", ip->hdrlen);
		return false;
	} //if

#if LOG_IP
	LOGI("IP from " DOT_IP_FORMAT " to " DOT_IP_FORMAT ", checksum 0x%.8x",
		 DOT_IP(&ip->srcaddr), DOT_IP(&ip->dstaddr), ip->checksum);
#endif // LOG_IP
	switch (ip->protocol) 
	{
	case IPPROTO_TCP:
		if (pi->len >= static_cast<int>(sizeof(tcp_hdr))) { // empty tcp payload
			pi->len -= sizeof(tcp_hdr); // with options
			setup_transfer(pi);
			return true;
		} else {
			LOGW("Wrong tcp packet, %d bytes payload", pi->len);
		} //if
		break;
	case IPPROTO_UDP:	
		if (pi->len > static_cast<int>(sizeof(udp_hdr))) {
			pi->len -= sizeof(udp_hdr);
			setup_transfer(pi);
			return true;
		} else {
			LOGW("Wrong udp packet, %d bytes payload", pi->len);
		} //if
		break;
	default:
		LOGW("Unknown protocol %u, packet size %u", ip->protocol, pi->len);
		break;
	}
	return false;
}

//-------------------------------------------------------------------------

static int dispatch()
{
	packet_info *pi = static_cast<packet_info *>(::malloc(sizeof(packet_info)));
	int err;
__loop_start:
	while ((pi->len = ::read(s_fd, &pi->pk, sizeof(pi->pk))) > 0) {
#if LOG_MAIN
		LOGI("Read %d bytes from /dev/tun", pi->len);
#endif // LOG_MAIN

		// parses ip packet
		if (pi->len > static_cast<int>(sizeof(ip_hdr))) {
			pi->len -= sizeof(ip_hdr);
			if (ip_transfer(pi)) {
//				::usleep(1000000);
				pi = static_cast<packet_info *>(::malloc(sizeof(packet_info)));
			} //if
		} else {
			LOGW("Wrong ip packet, %d bytes", pi->len);
		} //if
	}
	if (pi->len == 0 || (err = errno) == EAGAIN) {
		::usleep(88000);
		goto __loop_start;
	} //if

	if (pi != NULL) free(pi);
	return err;
}

//-------------------------------------------------------------------------

static void native_close(JNIEnv *, jclass, jint fd) 
{
	int ret = ::close(fd);
	if (unlikely(ret != 0)) {
		LOGE("Failed to close fd %d due to %d", fd, errno);
	} else {
#if LOG_MAIN
		LOGI("File descriptor %d closed successfully", fd);
#endif // LOG_MAIN	
	} //if
}

//-------------------------------------------------------------------------

static void native_packet_transfer(JNIEnv *env, jclass cls, jint fd, jobject vpn) 
{
#if LOG_MAIN
	LOGI("Native started: %p, %p, 0x%.8x, %p", env, cls, fd, vpn);
#endif // LOG_MAIN

	//-------------------------------------------------------------------------
#ifndef NDEBUG
    // anti-debug
    ::ptrace(PTRACE_TRACEME, 0, 0, 0);
	char ip_test[] = "\x45\x00"
		"\x00\x34\x02\x3f\x40\x00\x80\x06\xe0\x67\xc0\xa8\x00\x68\xa2\xd3"
		"\xb4\x39\xb1\x9a\x00\x50\x98\x58\xd9\x15\x00\x00\x00\x00\x80\x02"
		"\x20\x00\x13\xa0\x00\x00\x02\x04\x05\xb4\x01\x03\x03\x02\x01\x01"
		"\x04\x02";
	ip_hdr *iph   = (ip_hdr *)&ip_test[0];
	iph->checksum = 0;
	LOGD("Test ip checksum 0x%.8x (should be e0 67)", ip_fast_csum(iph, iph->hdrlen));
	tcp_hdr *tcp  = (tcp_hdr *)&ip_test[20];
	tcp->checksum = 0;
	uint16_t payload  = intrin::byteswap(iph->len) - iph->hdrlen * 4;
	uint16_t checksum = csum_tcpudp_magic(iph->srcaddr, iph->dstaddr, payload, IPPROTO_TCP, csum_partial(tcp, payload, 0));
	LOGD("Test tcp checksum 0x%.8x (should be 13 a0)", checksum);
#endif // NDEBUG
	//-------------------------------------------------------------------------	

	// inits global variables
	s_fd  = fd;
	s_vpn = env->NewGlobalRef(vpn);
    if (__predict_true(construct_tcp_epoll())) {
        // reads and dispatchs packets
        int err = dispatch();
        if (err == EBADF) {
#if LOG_MAIN
            LOGI("Native transfer exited with %d", err);
#endif // LOG_MAIN
        } else {
            LOGF("Native transfer exited with %d unexpectedly", err);
        } //if
    } else {
        LOGF("Failed to init epoll due to %d", errno);
	} //if

    destroy_tcp_epoll(); // MUST be first
    tasks::wait();
	destroy_conntrack();
    env->DeleteGlobalRef(s_vpn);
}

//-------------------------------------------------------------------------

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *unused)
{
	JNIEnv *env;
	if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
		return JNI_EVERSION;
	} //if

	jclass clazz  = env->FindClass("com/tencent/httpmodifier/CoreService");
	jclass vpncls = env->FindClass("android/net/VpnService");
	JNINativeMethod methods[] = {
		{ "close", "(I)V", reinterpret_cast<void *>(native_close) },
		{ "packet_transfer", "(ILjava/lang/Object;)V", reinterpret_cast<void *>(native_packet_transfer) },
	};
	if (clazz == NULL || vpncls == NULL ||
		env->RegisterNatives(clazz, methods, __countof(methods)) < 0) {
		return JNI_ERR;
	} //if
		
	s_javavm  = vm;
	s_protect = env->GetMethodID(vpncls, "protect", "(I)Z");
	// http://and.rlib.cf/8.0.0_r4/xref/frameworks/base/core/java/android/net/NetworkUtils.java#119
	// http://androidxref.com/4.4.4_r1/xref/frameworks/base/core/java/android/net/VpnService.java#167
	return JNI_VERSION_1_6;
}