#ifndef _MACHINE_VMMVAR_H_
#define _MACHINE_VMMVAR_H_

#define VMM_HV_SIGNATURE 	"OpenBSDVMM58"

#define VMM_MAX_MEM_RANGES	16
#define VMM_MAX_DISKS_PER_VM	4
#define VMM_MAX_PATH_DISK	128
#define VMM_MAX_PATH_CDROM	128
#define VMM_MAX_NAME_LEN	64
#define VMM_MAX_KERNEL_PATH	128
#define VMM_MAX_VCPUS_PER_VM	64
#define VMM_MAX_VM_MEM_SIZE	32768
#define VMM_MAX_NICS_PER_VM	4

#define VMM_PCI_MMIO_BAR_BASE	0xF0000000ULL
#define VMM_PCI_MMIO_BAR_END	0xFFFFFFFFULL
#define VMM_PCI_MMIO_BAR_SIZE	0x00010000
#define VMM_PCI_IO_BAR_BASE	0x1000
#define VMM_PCI_IO_BAR_END	0xFFFF
#define VMM_PCI_IO_BAR_SIZE	0x1000

enum {
	VCPU_STATE_STOPPED,
	VCPU_STATE_RUNNING,
	VCPU_STATE_REQTERM,
	VCPU_STATE_TERMINATED,
	VCPU_STATE_UNKNOWN,
};


struct vcpu_reg_state {

};

/*
 * vm exit data
 *  vm_exit_inout		: describes an IN/OUT exit
 */
struct vm_exit_inout {
	
};
/*
 *  vm_exit_eptviolation	: describes an EPT VIOLATION exit
 */
struct vm_exit_eptviolation {
	
};


struct vm_mem_range {
	paddr_t	vmr_gpa;
	vaddr_t vmr_va;
	size_t	vmr_size;
};

/*
 * struct vm_exit
 *
 * Contains VM exit information communicated to vmd(8). This information is
 * gathered by vmm(4) from the CPU on each exit that requires help from vmd.
 */
struct vm_exit {
	union {
		struct vm_exit_inout		vei;	/* IN/OUT exit */
		struct vm_exit_eptviolation	vee;	/* EPT VIOLATION exit*/
	};

	struct vcpu_reg_state		vrs;
	int				cpl;
};

struct vm_create_params {
	/* Input parameters to VMM_IOC_CREATE */
	size_t			vcp_nmemranges;
	size_t			vcp_ncpus;
	size_t			vcp_ndisks;
	size_t			vcp_nnics;
	struct vm_mem_range	vcp_memranges[VMM_MAX_MEM_RANGES];
	char			vcp_disks[VMM_MAX_DISKS_PER_VM][VMM_MAX_PATH_DISK];
	char			vcp_cdrom[VMM_MAX_PATH_CDROM];
	char			vcp_name[VMM_MAX_NAME_LEN];
	char			vcp_kernel[VMM_MAX_KERNEL_PATH];
	uint8_t			vcp_macs[VMM_MAX_NICS_PER_VM][6];

	/* Output parameter from VMM_IOC_CREATE */
	uint32_t	vcp_id;
};

struct vm_run_params {
	/* Input parameters to VMM_IOC_RUN */
	uint32_t	vrp_vm_id;
	uint32_t	vrp_vcpu_id;
	uint8_t		vrp_continue;		/* Continuing from an exit */
	uint16_t	vrp_irq;		/* IRQ to inject */

	/* Input/output parameter to VMM_IOC_RUN */
	struct vm_exit	*vrp_exit;		/* updated exit data */

	/* Output parameter from VMM_IOC_RUN */
	uint16_t	vrp_exit_reason;	/* exit reason */
	uint8_t		vrp_irqready;		/* ready for IRQ on entry */
};

struct vm_info_result {
	/* Output parameters from VMM_IOC_INFO */
	size_t		vir_memory_size;
	size_t		vir_used_size;
	size_t		vir_ncpus;
	uint8_t		vir_vcpu_state[VMM_MAX_VCPUS_PER_VM];
	pid_t		vir_creator_pid;
	uint32_t	vir_id;
	char		vir_name[VMM_MAX_NAME_LEN];
};

#ifdef _KERNEL

SLIST_HEAD(vcpu_head, vcpu);

struct vcpu
{
	struct vm *vc_parent;
	uint32_t vc_id;
	uint16_t vc_vpid;
	u_int vc_state;
	SLIST_ENTRY(vcpu) vc_vcpu_link;

	uint8_t vc_virt_mode;
};

#endif /* _KERNEL */

#endif /* ! _MACHINE_VMMVAR_H_ */