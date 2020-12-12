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

extern uint64_t hypmode_enabled;
static __inline bool
virt_enabled()
{
	return (hypmode_enabled != 0);
}

extern char hyp_init_vectors[];
extern char hyp_vectors[];

uint64_t	vmm_call_hyp(void *hyp_func_addr, ...);

struct cfdriver vmm_cd = {
	NULL, "vmm", DV_DULL
};

const struct cfattach vmm_ca = {
	sizeof(struct vmm_softc), vmm_probe, vmm_attach, NULL, NULL
};

struct vmm_softc *vmm_softc;

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
	
	paddr_t pa;

	//TODO: Should move check in vmm_enabled - and make non panic
	if (!virt_enabled())
	{
		panic("Virtualization not enabled\n");
	}

	//TODO: Temporary living place
	/*
	 * Install the temporary vectors which will be responsible for
	 * initializing the VMM when we next trap into EL2.
	 *
	 * x0: the exception vector table responsible for hypervisor
	 * initialization on the next call.
	 */
	pmap_extract(pmap_kernel(), (vaddr_t)hyp_init_vectors, &pa);
	vmm_call_hyp((void *)pa);

	uint64_t res = 
	vmm_call_hyp((void *)pa);

	panic("vmm_probe: AT THE DISCO %llu", res);

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