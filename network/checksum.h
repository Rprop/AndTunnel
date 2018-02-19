#pragma once
#include <linux/types.h>
#include "net/ip.h"
#include "net/tcp.h"

/*
 *	Helper funtions
 */
typedef uint32_t u32;
typedef u32 __bitwise __wsum;
#ifdef __i386__
# define asmlinkage   extern "C" __attribute__((regparm(0),visibility("hidden")))
#else
# define asmlinkage   extern "C" __LIBC_HIDDEN__
#endif // __i386__
#define unlikely(x)	  __builtin_expect(!!(x), 0)
/**
 * csum_fold - Fold and invert a 32bit partial checksum without adding pseudo headers.
 * csum: 32bit unfolded sum
 *
 * Fold a 32bit running checksum to 16bit and invert it. This is usually
 * the last step before putting a checksum into a packet.
 * Make sure not to mix with 64bit checksums.
 */
template<typename __sum16 = uint16_t> inline __sum16 csum_fold(__wsum csum)
{
#ifdef __arm__
	__asm__(
		"add %0, %1, %1, ror #16	@ csum_fold"
		: "=r" (csum)
		: "r" (csum)
		: "cc");
	return (__force __sum16)(~(__force u32)csum >> 16);
#elif defined(__i386__)
	asm("addl %1,%0\n"
		"adcl $0xffff, %0"
		: "=r" (csum)
		: "r" ((__force u32)csum << 16),
		"0" ((__force u32)csum & 0xffff0000));
	return (__force __sum16)(~(__force u32)csum >> 16);
#else
	u32 sum = (__force u32)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__force __sum16)~sum;
#endif // __arm__
}
#ifdef __i386__
template<typename __sum16 = uint16_t> inline __sum16 csum_ipv6_magic(const struct in6_addr *saddr,
																	 const struct in6_addr *daddr,
																	 __u32 len, unsigned short proto,
																	 __wsum sum)
{
	asm("addl 0(%1), %0	;\n"
		"adcl 4(%1), %0	;\n"
		"adcl 8(%1), %0	;\n"
		"adcl 12(%1), %0	;\n"
		"adcl 0(%2), %0	;\n"
		"adcl 4(%2), %0	;\n"
		"adcl 8(%2), %0	;\n"
		"adcl 12(%2), %0	;\n"
		"adcl %3, %0	;\n"
		"adcl %4, %0	;\n"
		"adcl $0, %0	;\n"
		: "=&r" (sum)
		: "r" (saddr), "r" (daddr),
		"r" (htonl(len)), "r" (htonl(proto)), "0" (sum)
		: "memory");

	return csum_fold(sum);
}
#elif defined(__arm__)
asmlinkage __wsum csum_ipv6_magic(const struct in6_addr *saddr, const struct in6_addr *daddr, __be32 len,
								  __be32 proto, __wsum sum);
#endif // __i386__
/*
 *	This is a version of ip_compute_csum() optimized for IP headers,
 *	which always checksum on 4 octet boundaries.
 *
 *	By Jorge Cwik <jorge@laser.satlink.net>, adapted for linux by
 *	Arnt Gulbrandsen.
 */
template<typename __sum16 = uint16_t> inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	/* ihl is always 5 or greater, almost always is 5, and iph is word aligned
	 * the majority of the time.
	 */
#ifdef __i386__
	unsigned int sum;
	asm volatile("movl (%1), %0	;\n"
				 "subl $4, %2	;\n"
				 "jbe 2f		;\n"
				 "addl 4(%1), %0	;\n"
				 "adcl 8(%1), %0	;\n"
				 "adcl 12(%1), %0;\n"
				 "1:	adcl 16(%1), %0	;\n"
				 "lea 4(%1), %1	;\n"
				 "decl %2	;\n"
				 "jne 1b		;\n"
				 "adcl $0, %0	;\n"
				 "movl %0, %2	;\n"
				 "shrl $16, %0	;\n"
				 "addw %w2, %w0	;\n"
				 "adcl $0, %0	;\n"
				 "notl %0	;\n"
				 "2:		;\n"
				 /* Since the input registers which are loaded with iph and ihl
				 are modified, we must also specify them as outputs, or gcc
				 will assume they contain their original values. */
				 : "=r" (sum), "=r" (iph), "=r" (ihl)
				 : "1" (iph), "2" (ihl)
				 : "memory");
	return (__force __sum16)sum;
#elif defined(__arm__)
	unsigned int tmp1;
	__wsum sum;

	__asm__ __volatile__(
		"ldr	%0, [%1], #4		@ ip_fast_csum		\n\
		ldr	%3, [%1], #4					\n\
		sub	%2, %2, #5					\n\
		adds	%0, %0, %3					\n\
		ldr	%3, [%1], #4					\n\
		adcs	%0, %0, %3					\n\
		ldr	%3, [%1], #4					\n\
		1:	adcs	%0, %0, %3					\n\
		ldr	%3, [%1], #4					\n\
		tst	%2, #15			@ do this carefully	\n\
		it ne			@ the it mnemonic doesn't generate any code on non-Thumb targets, by rrrfff	\n\
		subne	%2, %2, #1		@ without destroying	\n\
		bne	1b			@ the carry flag	\n\
		adcs	%0, %0, %3					\n\
		adc	%0, %0, #0"
		: "=r" (sum), "=r" (iph), "=r" (ihl), "=r" (tmp1)
		: "1" (iph), "2" (ihl)
		: "cc", "memory");
	return csum_fold(sum);
#endif // __i386__
}
/**
 * csum_tcpup_nofold - Compute an IPv4 pseudo header checksum.
 * @saddr: source address
 * @daddr: destination address
 * @len: length of packet
 * @proto: ip protocol of packet
 * @sum: initial sum to be added in (32bit unfolded)
 *
 * Returns the pseudo header checksum the input data. Result is
 * 32bit unfolded.
 */
template<typename __sum16 = uint16_t> inline __wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr, unsigned short len,
																	   unsigned short proto, __wsum sum)
{
#ifdef __arm__
	u32 lenprot = len | proto << 16;
	if (__builtin_constant_p(sum) && sum == 0) {
		__asm__(
			"adds	%0, %1, %2	@ csum_tcpudp_nofold0	\n\t"
#ifdef __ARMEB__
			"adcs	%0, %0, %3				\n\t"
#else // __ARMEL__
			"adcs	%0, %0, %3, ror #8			\n\t"
#endif
			"adc	%0, %0, #0"
			: "=&r" (sum)
			: "r" (daddr), "r" (saddr), "r" (lenprot)
			: "cc");
	} else {
		__asm__(
			"adds	%0, %1, %2	@ csum_tcpudp_nofold	\n\t"
			"adcs	%0, %0, %3				\n\t"
#ifdef __ARMEB__
			"adcs	%0, %0, %4				\n\t"
#else // __ARMEL__
			"adcs	%0, %0, %4, ror #8			\n\t"
#endif
			"adc	%0, %0, #0"
			: "=&r"(sum)
			: "r" (sum), "r" (daddr), "r" (saddr), "r" (lenprot)
			: "cc");
	}
	return sum;
#elif defined(__i386__)
	asm("addl %1, %0	;\n"
		"adcl %2, %0	;\n"
		"adcl %3, %0	;\n"
		"adcl $0, %0	;\n"
		: "=r" (sum)
		: "g" (daddr), "g"(saddr),
		"g" ((len + proto) << 8), "0" (sum));
	return sum;
#endif // __arm__
}
/*
 * computes the checksum of the TCP/UDP pseudo-header
 * returns a 16-bit checksum, already complemented
 *
 * csum_tcpup_magic - Compute an IPv4 pseudo header checksum.
 * @saddr: source address
 * @daddr: destination address
 * @len: length of packet
 * @proto: ip protocol of packet
 * @sum: initial sum to be added in (32bit unfolded)
 *
 * Returns the 16bit pseudo header checksum the input data already
 * complemented and ready to be filled in.
 */
template<typename __sum16 = uint16_t> inline __sum16 csum_tcpudp_magic(__be32 saddr, __be32 daddr,
																	   unsigned short len,
																	   unsigned short proto,
																	   __wsum sum)
{
	return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}
/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 32-bit boundary
 */
#ifdef __i386__
asmlinkage __wsum csum_partial(const void *buff, int len, __wsum sum);
#elif defined(__x86_64__)
static inline unsigned add32_with_carry(unsigned a, unsigned b)
{
	asm("addl %2,%0\n\t"
		"adcl $0,%0"
		: "=r" (a)
		: "0" (a), "rm" (b));
	return a;
}
static inline unsigned short from32to16(unsigned a)
{
	unsigned short b = a >> 16;
	asm("addw %w2,%w0\n\t"
		"adcw $0,%w0\n"
		: "=r" (b)
		: "0" (b), "r" (a));
	return b;
}
/*
 * Do a 64-bit checksum on an arbitrary memory area.
 * Returns a 32bit checksum.
 *
 * This isn't as time critical as it used to be because many NICs
 * do hardware checksumming these days.
 * 
 * Things tried and found to not make it faster:
 * Manual Prefetching
 * Unrolling to an 128 bytes inner loop.
 * Using interleaving with more registers to break the carry chains.
 */
static unsigned do_csum(const unsigned char *buff, unsigned len)
{
	unsigned odd, count;
	unsigned long result = 0;

	if (unlikely(len == 0))
		return result;
	odd = 1 & (unsigned long)buff;
	if (unlikely(odd)) {
		result = *buff << 8;
		len--;
		buff++;
	}
	count = len >> 1;		/* nr of 16-bit words.. */
	if (count) {
		if (2 & (unsigned long)buff) {
			result += *(unsigned short *)buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;		/* nr of 32-bit words.. */
		if (count) {
			unsigned long zero;
			unsigned count64;
			if (4 & (unsigned long)buff) {
				result += *(unsigned int *)buff;
				count--;
				len -= 4;
				buff += 4;
			}
			count >>= 1;	/* nr of 64-bit words.. */

							/* main loop using 64byte blocks */
			zero = 0;
			count64 = count >> 3;
			while (count64) {
				asm("addq 0*8(%[src]),%[res]\n\t"
					"adcq 1*8(%[src]),%[res]\n\t"
					"adcq 2*8(%[src]),%[res]\n\t"
					"adcq 3*8(%[src]),%[res]\n\t"
					"adcq 4*8(%[src]),%[res]\n\t"
					"adcq 5*8(%[src]),%[res]\n\t"
					"adcq 6*8(%[src]),%[res]\n\t"
					"adcq 7*8(%[src]),%[res]\n\t"
					"adcq %[zero],%[res]"
					: [res] "=r" (result)
					: [src] "r" (buff), [zero] "r" (zero),
					"[res]" (result));
				buff += 64;
				count64--;
			}

			/* last up to 7 8byte blocks */
			count %= 8;
			while (count) {
				asm("addq %1,%0\n\t"
					"adcq %2,%0\n"
					: "=r" (result)
					: "m" (*(unsigned long *)buff),
					"r" (zero), "0" (result));
				--count;
				buff += 8;
			}
			result = add32_with_carry(result >> 32,
									  result & 0xffffffff);

			if (len & 4) {
				result += *(unsigned int *)buff;
				buff += 4;
			}
		}
		if (len & 2) {
			result += *(unsigned short *)buff;
			buff += 2;
		}
	}
	if (len & 1)
		result += *buff;
	result = add32_with_carry(result >> 32, result & 0xffffffff);
	if (unlikely(odd)) {
		result = from32to16(result);
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
	}
	return result;
}
/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 64-bit boundary
 */
__wsum csum_partial(const void *buff, int len, __wsum sum)
{
	return (__force __wsum)add32_with_carry(do_csum(buff, len), (__force u32)sum);
}
#elif defined(__arm__)
/*
 * computes the checksum of a memory block at buff, length len,
 * and adds in "sum" (32-bit)
 *
 * returns a 32-bit number suitable for feeding into itself
 * or csum_tcpudp_magic
 *
 * this function must be called with even lengths, except
 * for the last fragment, which may be odd
 *
 * it's best to have buff aligned on a 32-bit boundary
 */
asmlinkage __wsum csum_partial(const void *buff, int len, __wsum sum);
#endif // __i386__
/*
 *	warpper
 */
template<typename hdr> inline void ip_checksum(hdr *ip)
{
	ip->checksum = 0;
#if defined(__i386__) || defined(__arm__)
	ip->checksum = ip_fast_csum(ip, ip->hdrlen);
#else
	auto ipseq   = reinterpret_cast<unsigned short *>(ip);
	uint32_t crc = ipseq[0] + ipseq[1] + ipseq[2] + ipseq[3] + ipseq[4] + ipseq[6] + ipseq[7] + ipseq[8] + ipseq[9];
	uint32_t crt = (crc >> 16) + (crc & 0xffffu);
	ipseq[5]     = ~static_cast<uint16_t>(crt);
#endif // !__i386__ && __arm__
}
template<typename hdr> inline void udp_checksum(hdr *udp)
{
	udp->checksum = 0; // disables UDP checksum
}
template<typename hdr> void tcp_checksum(hdr *tcp, ip_hdr *iph)
{
	uint16_t payload = intrin::byteswap(iph->len) - iph->hdrlen * 4;
	tcp->checksum    = 0;
	tcp->checksum    = csum_tcpudp_magic(iph->srcaddr, iph->dstaddr, payload, IPPROTO_TCP, 
										 csum_partial(tcp, payload, 0));
}