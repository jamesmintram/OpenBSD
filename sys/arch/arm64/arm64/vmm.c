/*	$OpenBSD: vmm.c,v 1.274 2020/09/10 17:03:03 mpi Exp $	*/
/*
 * Copyright (c) 2014 Mike Larkin <mlarkin@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signalvar.h>
#include <sys/malloc.h>
#include <sys/device.h>
#include <sys/pool.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/rwlock.h>
#include <sys/pledge.h>
#include <sys/memrange.h>

#include <uvm/uvm_extern.h>

#include <machine/cpu.h>
#include <machine/hypervisor.h>
#include <machine/vmmvar.h>

struct vm {
	struct vmspace		 *vm_vmspace;
	vm_map_t		 vm_map;
	uint32_t		 vm_id;
	pid_t			 vm_creator_pid;
	size_t			 vm_nmemranges;
	size_t			 vm_memory_size;
	char			 vm_name[VMM_MAX_NAME_LEN];
	struct vm_mem_range	 vm_memranges[VMM_MAX_MEM_RANGES];

	struct vcpu_head	 vm_vcpu_list;
	uint32_t		 vm_vcpu_ct;
	u_int			 vm_vcpus_running;
	struct rwlock		 vm_vcpu_lock;

	SLIST_ENTRY(vm)		 vm_link;
};

SLIST_HEAD(vmlist_head, vm);

struct vmm_softc {
	struct device		sc_dev;

	/* Capabilities */
	uint32_t		nr_vmx_cpus;
	uint32_t		nr_svm_cpus;
	uint32_t		nr_rvi_cpus;
	uint32_t		nr_ept_cpus;

	/* Managed VMs */
	struct vmlist_head	vm_list;

	int			mode;

	struct rwlock		vm_lock;
	size_t			vm_ct;		/* number of in-memory VMs */
	size_t			vm_idx;		/* next unique VM index */

	struct rwlock		vpid_lock;
	uint16_t		max_vpid;
	uint8_t			vpids[512];	/* bitmap of used VPID/ASIDs */
};

int vmm_probe(struct device *, void *, void *);
void vmm_attach(struct device *, struct device *, void *);

void hypmap_init(pmap_t map);
void hypmap_map(pmap_t map, vaddr_t va, size_t len, vm_prot_t prot);
void hypmap_map_identity(pmap_t map, vaddr_t va, size_t len, vm_prot_t prot);

extern uint64_t hypmode_enabled;
static __inline bool
virt_enabled()
{
	return (hypmode_enabled != 0);
}

extern char hyp_init_vectors[];
extern char hyp_vectors[];
extern char hyp_code_start[];
extern char hyp_code_end[];


char *hyp_stack;
pmap_t hyp_pmap;

uint64_t	vmm_call_hyp(void *hyp_func_addr, ...);

struct cfdriver vmm_cd = {
	NULL, "vmm", DV_DULL
};

const struct cfattach vmm_ca = {
	sizeof(struct vmm_softc), vmm_probe, vmm_attach, NULL, NULL
};

struct vmm_softc *vmm_softc;


paddr_t //FIXME(JAMES) Inline
vtophys(void *va) {
	paddr_t pa;
	pmap_extract(pmap_kernel(), (vaddr_t)va, &pa);
	return pa;
}

/*
 * vmm_enabled
 *
 * Checks if we have at least one CPU with either VMX or SVM.
 * Returns 1 if we have at least one of either type, but not both, 0 otherwise.
 */
int
vmm_enabled(void)
{
	//TODO: Implement this as well
	if (!virt_enabled())
	{
		panic("Virtualization not enabled\n");
	}

	return 1;
}

int
vmm_probe(struct device *parent, void *match, void *aux)
{
	const char **busname = (const char **)aux;
	
	// uint64_t ich_vtr_el2;
	// uint64_t cnthctl_el2;
	uint64_t tcr_el1, tcr_el2;
	uint64_t id_aa64mmfr0_el1;
	uint64_t pa_range_bits;
	uint32_t sctlr_el2;
	// uint32_t vtcr_el2;

	size_t hyp_code_len;

	paddr_t pa;
	u_long daif;
	char *stack_top;

	//TODO: Should move check in vmm_enabled - and make non panic
	if (!virt_enabled())
	{
		panic("Virtualization not enabled\n");
	}

	//TODO: Temporary living place
	//Disable interrupts
	daif = intr_disable();

	/*
	 * Install the temporary vectors which will be responsible for
	 * initializing the VMM when we next trap into EL2.
	 *
	 * x0: the exception vector table responsible for hypervisor
	 * initialization on the next call.
	 */
	pa = vtophys(hyp_init_vectors);
	vmm_call_hyp((void *)pa);

	// Build params

	// pmap for hypervisor source mapping 
	// TODO(JAMES): Add a reference to pmap? 
	hyp_pmap = pmap_create();

	hypmap_init(hyp_pmap);
	hyp_code_len = (size_t)hyp_code_end - (size_t)hyp_code_start;
	hypmap_map(hyp_pmap, (vaddr_t)hyp_code_start, hyp_code_len, PROT_READ | PROT_EXEC);

	/* We need an identity mapping for when we activate the MMU */
	hypmap_map_identity(hyp_pmap, (vaddr_t)hyp_code_start, hyp_code_len, PROT_READ | PROT_EXEC);

	/* Create and map the hypervisor stack */	
	//FIXME(JAMES): Should this use km_alloc?
	hyp_stack = malloc(PAGE_SIZE, M_DEVBUF, M_WAITOK | M_ZERO);
	stack_top = hyp_stack + PAGE_SIZE;
	hypmap_map(hyp_pmap, (vaddr_t)hyp_stack, PAGE_SIZE, PROT_READ | PROT_WRITE);

	/* Configure address translation at EL2 */
	tcr_el1 = READ_SPECIALREG(tcr_el1);
	tcr_el2 = TCR_EL2_RES1;

	/* Set physical address size */
	id_aa64mmfr0_el1 = READ_SPECIALREG(id_aa64mmfr0_el1);
	pa_range_bits = ID_AA64MMFR0_PA_RANGE(id_aa64mmfr0_el1);
	tcr_el2	|= (pa_range_bits & 0x7) << TCR_EL2_PS_SHIFT;

	/* Use the same address translation attributes as the host */
	tcr_el2 |= tcr_el1 & TCR_T0SZ_MASK;

	/*
	 * Configure the system control register for EL2:
	 *
	 * SCTLR_EL2_M: MMU on
	 * SCTLR_EL2_C: Data cacheability not affected
	 * SCTLR_EL2_I: Instruction cacheability not affected
	 * SCTLR_EL2_A: Instruction alignment check
	 * SCTLR_EL2_SA: Stack pointer alignment check
	 * SCTLR_EL2_WXN: Treat writable memory as execute never
	 * ~SCTLR_EL2_EE: Data accesses are little-endian
	 */
	sctlr_el2 = SCTLR_EL2_RES1;
	sctlr_el2 |= SCTLR_EL2_M | SCTLR_EL2_C | SCTLR_EL2_I;
	sctlr_el2 |= SCTLR_EL2_A | SCTLR_EL2_SA;
	sctlr_el2 |= SCTLR_EL2_WXN;
	sctlr_el2 &= ~SCTLR_EL2_EE;

	// /*
	//  * Configure the Stage 2 translation control register:
	//  *
	//  * VTCR_IRGN0_WBWA: Translation table walks access inner cacheable
	//  * normal memory
	//  * VTCR_ORGN0_WBWA: Translation table walks access outer cacheable
	//  * normal memory
	//  * VTCR_EL2_TG0_4K: Stage 2 uses 4K pages
	//  * VTCR_EL2_SL0_4K_LVL1: Stage 2 uses concatenated level 1 tables
	//  * VTCR_EL2_SH0_IS: Memory associated with Stage 2 walks is inner
	//  * shareable
	//  */
	// vtcr_el2 = VTCR_EL2_RES1;
	// vtcr_el2 = (pa_range_bits & 0x7) << VTCR_EL2_PS_SHIFT;
	// vtcr_el2 |= VTCR_EL2_IRGN0_WBWA | VTCR_EL2_ORGN0_WBWA;
	// vtcr_el2 |= VTCR_EL2_TG0_4K;
	// vtcr_el2 |= VTCR_EL2_SH0_IS;
	// if (pa_range_bits == ID_AA64MMFR0_PARange_1T) {
	// 	/*
	// 	 * 40 bits of physical addresses, use concatenated level 1
	// 	 * tables
	// 	 */
	// 	vtcr_el2 |= 24 & VTCR_EL2_T0SZ_MASK;
	// 	vtcr_el2 |= VTCR_EL2_SL0_4K_LVL1;
	// }

	// /* Special call to initialize EL2 */
	vmm_call_hyp(
		(void *)vtophys(hyp_vectors), 
		vtophys(hyp_pmap->pm_vp.l1), // FIXME(JAMES): Should we be using pm_vp.l1 or pted_va?
	    vtophys(hyp_pmap->pm_vp.l1), // FIXME Should be -> ktohyp(stack_top), 
		tcr_el2, 
		sctlr_el2, 
		sctlr_el2 // FIXME -> vtcr_el2
		);

	intr_restore(daif);

	panic("vmm_probe: AT THE DISCO");

    //TODO: Fix this mofo
	if (strcmp(*busname, vmm_cd.cd_name) != 0)
		return (0);
	return (1);
}

/*
 * vmm_attach
 *
 * Calculates how many of each type of CPU we have, prints this into dmesg
 * during attach. Initializes various locks, pools, and list structures for the
 * VMM.
 */
void
vmm_attach(struct device *parent, struct device *self, void *aux)
{
	struct vmm_softc *sc = (struct vmm_softc *)self;
	// struct cpu_info *ci;
	// CPU_INFO_ITERATOR cii;

	panic("vmm_attach: AT THE DISCO");

	sc->nr_vmx_cpus = 0;
	sc->nr_svm_cpus = 0;
	sc->nr_rvi_cpus = 0;
	sc->nr_ept_cpus = 0;
	sc->vm_ct = 0;
	sc->vm_idx = 0;

	vmm_softc = sc;
}

void
hypmap_init(pmap_t map)
{
	//TODO: Update pmap code to handle Stage 1 and Stage 2 (needs parameter)
	// FBSD mmu.c
	//map->have_4_level_pt = 1;
}

void
hypmap_map(pmap_t map, vaddr_t va, size_t len, vm_prot_t prot)
{
	vaddr_t va_end;
	paddr_t pa;

	va_end = va + len - 1;
	va = trunc_page(va);
	while (va < va_end) {
		pmap_extract(pmap_kernel(), va, &pa);
		
		//FIXME(JAMES) Reinstate when I understand why:
		// hypva = (va >= VM_MIN_KERNEL_ADDRESS) ? ktohyp(va) : va;

		pmap_enter(map, va, pa, prot, prot | PMAP_WIRED);
		va += PAGE_SIZE;
	}
}

void
hypmap_map_identity(pmap_t map, vaddr_t va, size_t len, vm_prot_t prot)
{
	vaddr_t va_end;
	paddr_t pa;

	va_end = va + len - 1;
	va = trunc_page(va);
	while (va < va_end) {
		pmap_extract(pmap_kernel(), va, &pa);
		
		//FIXME(JAMES) Reinstate when I understand why:
		// hypva = (va >= VM_MIN_KERNEL_ADDRESS) ? ktohyp(va) : va;

		pmap_enter(map, pa, pa, prot, prot | PMAP_WIRED);
		va += PAGE_SIZE;
	}
}