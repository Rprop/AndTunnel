/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		IP/TCP/UDP checksumming routines
 *
 * Authors:	Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Tom May, <ftom@netcom.com>
 *              Pentium Pro/II routines:
 *              Alexander Kjeldaas <astor@guardian.no>
 *              Finn Arne Gangstad <finnag@guardian.no>
 *		Lots of code moved from tcp.c and ip.c; see those files
 *		for more names.
 *
 * Changes:     Ingo Molnar, converted csum_partial_copy() to 2.1 exception
 *			     handling.
 *		Andi Kleen,  add zeroing on error
 *                   converted to pure assembler
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
	
/*
 * computes a partial checksum, e.g. for TCP/UDP fragments
 */

/*	
unsigned int csum_partial(const unsigned char * buff, int len, unsigned int sum)
 */
		

/*		
 * Experiments with Ethernet and SLIP connections show that buff
 * is aligned on either a 2-byte or 4-byte boundary.  We get at
 * least a twofold speedup on 486 and Pentium if it is 4-byte aligned.
 * Fortunately, it is easy to convert 2-byte alignment to 4-byte
 * alignment for the unrolled loop.
 */

	.text	
	.globl csum_partial
	.align 4,0x90
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_ALIGNMENT_16)
#	.p2align 4, 0x90
#endif
csum_partial:
	.cfi_startproc
	pushl %esi
	.cfi_adjust_cfa_offset 4
	.cfi_rel_offset esi, 0
	pushl %ebx
	.cfi_adjust_cfa_offset 4
	.cfi_rel_offset ebx, 0
	movl 20(%esp),%eax	# Function arg: unsigned int sum
	movl 16(%esp),%ecx	# Function arg: int len
	movl 12(%esp),%esi	# Function arg: unsigned char *buff
	testl $3, %esi		# Check alignment.
	jz 2f			# Jump if alignment is ok.
	testl $1, %esi		# Check alignment.
	jz 10f			# Jump if alignment is boundary of 2 bytes.

	# buf is odd
	dec %ecx
	jl 8f
	movzbl (%esi), %ebx
	adcl %ebx, %eax
	roll $8, %eax
	inc %esi
	testl $2, %esi
	jz 2f
10:
	subl $2, %ecx		# Alignment uses up two bytes.
	jae 1f			# Jump if we had at least two bytes.
	addl $2, %ecx		# ecx was < 2.  Deal with it.
	jmp 4f
1:	movw (%esi), %bx
	addl $2, %esi
	addw %bx, %ax
	adcl $0, %eax
2:
	movl %ecx, %edx
	shrl $5, %ecx
	jz 2f
	testl %esi, %esi
1:	movl (%esi), %ebx
	adcl %ebx, %eax
	movl 4(%esi), %ebx
	adcl %ebx, %eax
	movl 8(%esi), %ebx
	adcl %ebx, %eax
	movl 12(%esi), %ebx
	adcl %ebx, %eax
	movl 16(%esi), %ebx
	adcl %ebx, %eax
	movl 20(%esi), %ebx
	adcl %ebx, %eax
	movl 24(%esi), %ebx
	adcl %ebx, %eax
	movl 28(%esi), %ebx
	adcl %ebx, %eax
	lea 32(%esi), %esi
	dec %ecx
	jne 1b
	adcl $0, %eax
2:	movl %edx, %ecx
	andl $0x1c, %edx
	je 4f
	shrl $2, %edx		# This clears CF
3:	adcl (%esi), %eax
	lea 4(%esi), %esi
	dec %edx
	jne 3b
	adcl $0, %eax
4:	andl $3, %ecx
	jz 7f
	cmpl $2, %ecx
	jb 5f
	movw (%esi),%cx
	leal 2(%esi),%esi
	je 6f
	shll $16,%ecx
5:	movb (%esi),%cl
6:	addl %ecx,%eax
	adcl $0, %eax 
7:	
	testl $1, 12(%esp)
	jz 8f
	roll $8, %eax
8:
	popl %ebx
	.cfi_adjust_cfa_offset -4
	.cfi_restore ebx
	popl %esi
	.cfi_adjust_cfa_offset -4
	.cfi_restore esi
	ret
	.cfi_endproc
	.type csum_partial, @function
	.size csum_partial, .-csum_partial
