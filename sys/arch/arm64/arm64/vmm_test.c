#include <sys/param.h>

#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/systm.h>

#include <sys/malloc.h>

#include <sys/proc.h>
#include <machine/vmmvar.h>

extern volatile int start_init_exec;

extern int vm_create(struct vm_create_params *, struct proc *);
extern int vm_run(struct vm_run_params *vrp);

void start_vm();

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
	// Do we need to load out kernel into these memory segments before we "boot"

	struct vm_create_params params = {
		.vcp_ncpus = 1,
		// vm.c:create_memory_map used as "inspiration"
		.vcp_memranges = {
			{
				.vmr_gpa = 0x0,
				.vmr_va =  (vaddr_t)malloc(1024*1024*32, M_DEVBUF, M_WAITOK | M_ZERO),
				.vmr_size = 1024*1024*32,  //32MB should be enough!
			},
		},
		.vcp_nmemranges = 1,
	};

	// /* Output parameter from VMM_IOC_CREATE */
	// uint32_t	vcp_id;

	printf("CREATING A NEW VMM\n");

	//TODO: Configure some memory ranges

	int create_result = vm_create(&params, &proc0);

	printf("STARTING A NEW VMM\n");
	start_vm();

	// Now we run the VM...

	printf("vm_create result %d\n", create_result);

	panic("TEST COMPLETE - HALT HERE\n");
}


// from usr.sbin/vmd
//////////////////////

void
start_vm() {
	vm_run(NULL);
}

void
run_vm() {
	// Move this into user space before uncommenting
	// pthread_t *tid, evtid;
	// struct vm_run_params **vrp;

	// tid = calloc(vcp->vcp_ncpus, sizeof(pthread_t));
	// vrp = calloc(vcp->vcp_ncpus, sizeof(struct vm_run_params *));
	// if (tid == NULL || vrp == NULL) {
	// 	log_warn("%s: memory allocation error - exiting.",
	// 	    __progname);
	// 	return (ENOMEM);
	// }

	// Alloc vm_run_params
	// Alloc vm_exit

	// vcpu_reset();
	// vcpu_run_loop(vrp)
}

void *
vcpu_run_loop(void *arg)
{
	//struct vm_run_params *vrp = (struct vm_run_params *)arg;

	for(;;)
	{
		// Process locks + pauses
		// Process IRQs
		// Run CPU via IOCTL, block until we get a return code
	}
}