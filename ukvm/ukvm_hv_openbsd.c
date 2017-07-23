/*
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of ukvm, a unikernel monitor.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ukvm_hv_openbsd.c: Architecture-independent part of OpenBSD vmm(4) backend
 * implementation.
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _WITH_DPRINTF
#include <stdio.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <machine/vmmvar.h>
#include <sys/param.h>

#include "ukvm.h"
#include "ukvm_hv_openbsd.h"

struct ukvm_hv *ukvm_hv_init(size_t mem_size)
{
    struct ukvm_hv          *hv;
    struct ukvm_hvb         *hvb;
    struct vm_create_params *vcp;
	struct vm_mem_range *vmr;
	void *p;

	hv = calloc(1, sizeof (struct ukvm_hv));
    if (hv == NULL)
        err(1, "calloc hv");
    
    hvb = calloc(1, sizeof (struct ukvm_hvb));
    if (hvb == NULL)
        err(1, "calloc");
    
    hv->b = hvb;
    hvb->vmd_fd = -1;

    hvb->vmd_fd = open(VMM_NODE, O_RDWR);
    if (hvb->vmd_fd == -1)
        err(1, "VMM_NODE");

    vcp = calloc(1, sizeof (struct vm_create_params));
	vcp->vcp_ncpus = 1;
    strlcpy(vcp->vcp_name, "ukvm", VMM_MAX_NAME_LEN);
    
	vcp->vcp_nmemranges = 1;
	vcp->vcp_memranges[0].vmr_gpa = 0x0;
	vcp->vcp_memranges[0].vmr_size = mem_size;
	
    vmr = &vcp->vcp_memranges[0];
    p = mmap(NULL, vmr->vmr_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (p == MAP_FAILED)
        err(1, "mmap");

    vmr->vmr_va = (vaddr_t)p;
    hv->mem = p;
    hv->mem_size = mem_size;

    if (ioctl(hvb->vmd_fd, VMM_IOC_CREATE, vcp) < 0)
		err(errno, "create vmm ioctl failed - exiting");

    hvb->vcp_id = vcp->vcp_id;
    hvb->vcpu_id = 0;

    return hv;
}

