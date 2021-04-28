#include <sys/param.h>

#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/systm.h>

#include <sys/proc.h>
#include <machine/vmmvar.h>

extern volatile int start_init_exec;

extern int vm_create(struct vm_create_params *, struct proc *);

extern struct	proc proc0;

void
start_vmm_init(void *arg)
{
	/*
	 * Wait for main() to tell us that it's safe to exec.
	 */
	while (start_init_exec == 0)
		tsleep_nsec(&start_init_exec, PWAIT, "initexec", INFSLP);

	// How does init load the first file? Can we do that? (load a kvm test blob)

	struct vm_create_params params = {
		.vcp_ncpus = 1,
	};

	// /* Output parameter from VMM_IOC_CREATE */
	// uint32_t	vcp_id;

	printf("STARTING VMM TEST\n");

	//TODO: Configure some memory ranges

	int create_result = vm_create(&params, &proc0);
	
	panic("vm_create result %d\n", create_result);
}