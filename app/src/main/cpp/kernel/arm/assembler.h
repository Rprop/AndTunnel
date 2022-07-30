/*
 * Endian independent macros for shifting bytes within registers.
 */
#ifndef __ARMEB__
#define lspull          lsr
#define lspush          lsl
#define get_byte_0      lsl #0
#define get_byte_1	lsr #8
#define get_byte_2	lsr #16
#define get_byte_3	lsr #24
#define put_byte_0      lsl #0
#define put_byte_1	lsl #8
#define put_byte_2	lsl #16
#define put_byte_3	lsl #24
#else
#define lspull          lsl
#define lspush          lsr
#define get_byte_0	lsr #24
#define get_byte_1	lsr #16
#define get_byte_2	lsr #8
#define get_byte_3      lsl #0
#define put_byte_0	lsl #24
#define put_byte_1	lsl #16
#define put_byte_2	lsl #8
#define put_byte_3      lsl #0
#endif


	.irp	c,,eq,ne,cs,cc,mi,pl,vs,vc,hi,ls,ge,lt,gt,le,hs,lo
	.macro	ret\c, reg
#if __LINUX_ARM_ARCH__ < 6
	mov\c	pc, \reg
#else
	.ifeqs	"\reg", "lr"
	bx\c	\reg
	.else
	mov\c	pc, \reg
	.endif
#endif
	.endm
	.endr