/*	$OpenBSD: vmd.c,v 1.119 2020/09/23 19:18:18 martijn Exp $	*/

/*
 * Copyright (c) 2015 Reyk Floeter <reyk@openbsd.org>
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

// #include <sys/param.h>	/* nitems */
// #include <sys/queue.h>
// #include <sys/wait.h>
// #include <sys/cdefs.h>
// #include <sys/stat.h>
// #include <sys/sysctl.h>
// #include <sys/tty.h>
// #include <sys/ttycom.h>
// #include <sys/ioctl.h>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <termios.h>
// #include <errno.h>
// #include <event.h>
#include <fcntl.h>
#include <pwd.h>
// #include <signal.h>
#include <syslog.h>
#include <unistd.h>
// #include <util.h>
// #include <ctype.h>
// #include <pwd.h>
// #include <grp.h>

#include <machine/vmmvar.h>

#include "proc.h"
#include "vmd.h"

int	 main(int, char **);
int config_init(struct vmd *env);

struct vmd	*env;


int
main(int argc, char **argv)
{
    struct privsep		*ps;
    
    log_init(0, LOG_USER);
    

	if ((env = calloc(1, sizeof(*env))) == NULL)
		fatal("calloc: env");

    /* check for root privileges */
	if (env->vmd_noaction == 0) {
		if (geteuid())
			fatalx("need root privileges");
    }

	ps = &env->vmd_ps;
	ps->ps_env = env;
	env->vmd_fd = -1;

    if (config_init(env) == -1)
		fatal("failed to initialize configuration");

    if ((ps->ps_pw = getpwnam(VMD_USER)) == NULL)
		fatal("unknown user %s", VMD_USER);

    // /* First proc runs as root without pledge but in default chroot */
	// proc_priv->p_pw = &proc_privpw; /* initialized to all 0 */
	// proc_priv->p_chroot = ps->ps_pw->pw_dir; /* from VMD_USER */

	/* Open /dev/vmm */
	if (env->vmd_noaction == 0) {
		env->vmd_fd = open(VMM_NODE, O_RDWR);
		if (env->vmd_fd == -1)
			fatal("%s", VMM_NODE);
	}

    return 0;
}


struct vmd_vm *
vm_getbyvmid(uint32_t vmid)
{
	return (NULL);
}

void
vm_remove(struct vmd_vm *vm, const char *caller)
{
}


void
switch_remove(struct vmd_switch *vsw)
{
}

struct vmd_switch *
switch_getbyname(const char *name)
{
    return (NULL);
}

int
vm_opentty(struct vmd_vm *vm)
{
    return -1;
}
void
vm_stop(struct vmd_vm *vm, int keeptty, const char *caller)
{
}

int
vm_checkaccess(int fd, unsigned int uflag, uid_t uid, int amode)
{
    return -1;
}
int
vm_register(struct privsep *ps, struct vmop_create_params *vmc,
    struct vmd_vm **ret_vm, uint32_t id, uid_t uid)
{
    return -1;
}

struct vmd_user *
user_get(uid_t uid)
{
	return (NULL);
}

void
user_put(struct vmd_user *usr)
{
}

void
user_inc(struct vm_create_params *vcp, struct vmd_user *usr, int inc)
{
}

int
user_checklimit(struct vmd_user *usr, struct vm_create_params *vcp)
{
	return -1;
}

uint32_t
prefixlen2mask(uint8_t prefixlen)
{
	if (prefixlen == 0)
		return (0);

	if (prefixlen > 32)
		prefixlen = 32;

	return (htonl(0xffffffff << (32 - prefixlen)));
}

void
prefixlen2mask6(uint8_t prefixlen, struct in6_addr *mask)
{
	struct in6_addr	 s6;
	int		 i;

	if (prefixlen > 128)
		prefixlen = 128;

	memset(&s6, 0, sizeof(s6));
	for (i = 0; i < prefixlen / 8; i++)
		s6.s6_addr[i] = 0xff;
	i = prefixlen % 8;
	if (i)
		s6.s6_addr[prefixlen / 8] = 0xff00 >> i;

	memcpy(mask, &s6, sizeof(s6));
}

void
getmonotime(struct timeval *tv)
{
	struct timespec	 ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		fatal("clock_gettime");

	TIMESPEC_TO_TIMEVAL(tv, &ts);
}




// Belongs in vmm.c
int
opentap(char *ifname)
{
    return -1;
}