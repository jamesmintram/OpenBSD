#include <machine/asm.h>

ENTRY(vmm_call_hyp)
	hvc	#0
	ret
END(vmm_call_hyp)

.macro VECT_EMPTY
	.align 7
	1: b 	1b
.endm

.macro VECT name
	.align 7
	b 	handle_\name
.endm


	.align 11
	.globl	hyp_init_vectors
hyp_init_vectors:
	VECT_EMPTY		/* Synchronous EL2t */
	VECT_EMPTY		/* IRQ EL2t */
	VECT_EMPTY		/* FIQ EL2t */
	VECT_EMPTY		/* Error EL2t */

	VECT_EMPTY		/* Synchronous EL2h */
	VECT_EMPTY		/* IRQ EL2h */
	VECT_EMPTY		/* FIQ EL2h */
	VECT_EMPTY		/* Error EL2h */

	VECT hyp_init	/* Synchronous 64-bit EL1 */
	VECT_EMPTY		/* IRQ 64-bit EL1 */
	VECT_EMPTY		/* FIQ 64-bit EL1 */
	VECT_EMPTY		/* Error 64-bit EL1 */

	VECT_EMPTY		/* Synchronous 32-bit EL1 */
	VECT_EMPTY		/* IRQ 32-bit EL1 */
	VECT_EMPTY		/* FIQ 32-bit EL1 */
	VECT_EMPTY		/* Error 32-bit EL1 */

/*
 * Initialize the hypervisor mode with a new exception vector table, translation
 * table and stack.
 *
 * Expecting:
 * x0 - the hypervisor exception vectors
 * x1 - translation tables physical address
 * x2 - stack top virtual address
 * x3 - TCR_EL2 value
 * x4 - SCTLR_EL2 value
 * x5 - VTCR_EL2 value
 */
ENTRY(handle_hyp_init)
	/* Install the new exception vectors */
	# msr	vbar_el2, x0
	/* Set the stack top address */
	# mov	sp, x2
	/* Use the host VTTBR_EL2 to tell the host and the guests apart */
	mov	x9, 0 /* #VTTBR_HOST */
	msr	vttbr_el2, x9
	/* Load the base address for the translation tables */
	# msr	ttbr0_el2, x1
	/* Invalidate the TLB */
	tlbi	alle2
	/* Use the same memory attributes as EL1 */
	mrs	x9, mair_el1
	msr	mair_el2, x9
	/* Configure address translation */
	# msr	tcr_el2, x3
	isb
	/* Set the system control register for EL2 */
	# msr	sctlr_el2, x4
	/* Set the Stage 2 translation control register */
	# msr	vtcr_el2, x5
	/* Return success */
	mov	x0, #123
	/* MMU is up and running */
	eret
END(handle_hyp_init)