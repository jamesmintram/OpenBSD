#include <sys/param.h>

#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/systm.h>

#include <sys/proc.h>
#include <machine/vmmvar.h>

extern volatile int start_init_exec;

extern void vm_create(struct vm_create_params *, struct proc *);

void
start_vmm_init(void *arg)
{
	/*
	 * Wait for main() to tell us that it's safe to exec.
	 */
	while (start_init_exec == 0)
		tsleep_nsec(&start_init_exec, PWAIT, "initexec", INFSLP);

	// How does init load the first file? Can we do that? (load a kvm test blob)

	vm_create(NULL, NULL);
	
	panic("Lets do some stuff here - then we never leave the kernel binary\n");
}