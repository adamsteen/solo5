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

void create_memory_map(int mem_size, struct vm_create_params *);
int alloc_guest_mem(struct vm_create_params *);

/*
 * create_memory_map
 *
 * Sets up the guest physical memory ranges that the VM can access.
 *
 * Parameters:
 *  vcp: VM create parameters describing the VM whose memory map
 *       is being created
 *
 * Return values:
 *  nothing
 */
void
create_memory_map(int mem_size, struct vm_create_params *vcp)
{
	size_t len, mem_bytes, mem_mb;

	mem_mb = mem_size;
	vcp->vcp_nmemranges = 0;
	if (mem_mb < 1 || mem_mb > VMM_MAX_VM_MEM_SIZE)
		return;

	mem_bytes = mem_mb * 1024 * 1024;

	/* First memory region: 0 - LOWMEM_KB (DOS low mem) */
	len = LOWMEM_KB * 1024;
	vcp->vcp_memranges[0].vmr_gpa = 0x0;
	vcp->vcp_memranges[0].vmr_size = len;
	mem_bytes -= len;

	/*
	 * Second memory region: LOWMEM_KB - 1MB.
	 *
	 * N.B. - Normally ROMs or parts of video RAM are mapped here.
	 * We have to add this region, because some systems
	 * unconditionally write to 0xb8000 (VGA RAM), and
	 * we need to make sure that vmm(4) permits accesses
	 * to it. So allocate guest memory for it.
	 */
	len = 0x100000 - LOWMEM_KB * 1024;
	vcp->vcp_memranges[1].vmr_gpa = LOWMEM_KB * 1024;
	vcp->vcp_memranges[1].vmr_size = len;
	mem_bytes -= len;

	/* Make sure that we do not place physical memory into MMIO ranges. */
	if (mem_bytes > VMM_PCI_MMIO_BAR_BASE - 0x100000)
		len = VMM_PCI_MMIO_BAR_BASE - 0x100000;
	else
		len = mem_bytes;

	/* Third memory region: 1MB - (1MB + len) */
	vcp->vcp_memranges[2].vmr_gpa = 0x100000;
	vcp->vcp_memranges[2].vmr_size = len;
	mem_bytes -= len;

	if (mem_bytes > 0) {
		/* Fourth memory region for the remaining memory (if any) */
		vcp->vcp_memranges[3].vmr_gpa = VMM_PCI_MMIO_BAR_END + 1;
		vcp->vcp_memranges[3].vmr_size = mem_bytes;
		vcp->vcp_nmemranges = 4;
	} else
		vcp->vcp_nmemranges = 3;
}

/*
 * alloc_guest_mem
 *
 * Allocates memory for the guest.
 * Instead of doing a single allocation with one mmap(), we allocate memory
 * separately for every range for the following reasons:
 * - ASLR for the individual ranges
 * - to reduce memory consumption in the UVM subsystem: if vmm(4) had to
 *   map the single mmap'd userspace memory to the individual guest physical
 *   memory ranges, the underlying amap of the single mmap'd range would have
 *   to allocate per-page reference counters. The reason is that the
 *   individual guest physical ranges would reference the single mmap'd region
 *   only partially. However, if every guest physical range has its own
 *   corresponding mmap'd userspace allocation, there are no partial
 *   references: every guest physical range fully references an mmap'd
 *   range => no per-page reference counters have to be allocated.
 *
 * Return values:
 *  0: success
 *  !0: failure - errno indicating the source of the failure
 */
int
alloc_guest_mem(struct vm_create_params *vcp)
{
	void *p;
	int ret;
	size_t i, j;
	struct vm_mem_range *vmr;

	for (i = 0; i < vcp->vcp_nmemranges; i++) {
		vmr = &vcp->vcp_memranges[i];
		p = mmap(NULL, vmr->vmr_size, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANON, -1, 0);
		if (p == MAP_FAILED) {
			ret = errno;
			for (j = 0; j < i; j++) {
				vmr = &vcp->vcp_memranges[j];
				munmap((void *)vmr->vmr_va, vmr->vmr_size);
			}

			return (ret);
		}

		vmr->vmr_va = (vaddr_t)p;
	}

	return (0);
}

struct ukvm_hv *ukvm_hv_init(size_t mem_size)
{
	int ret;
    struct ukvm_hv          *hv;
    struct ukvm_hvb         *hvb;
    struct vm_create_params *vcp;

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

    vcp = &hvb->vcp;
	vcp->vcp_ncpus = 1;
    vcp->vcp_ndisks = 0;
    vcp->vcp_nnics = 0;
    strlcpy(vcp->vcp_name, "ukvm", VMM_MAX_NAME_LEN);
    
    create_memory_map(mem_size, vcp);
	ret = alloc_guest_mem(vcp);
	if (ret) {
		err(ret, "could not allocate guest memory - exiting");
	}

	if (ioctl(hvb->vmd_fd, VMM_IOC_CREATE, vcp) < 0)
		err(errno, "create vmm ioctl failed - exiting");

    return hv;
}


