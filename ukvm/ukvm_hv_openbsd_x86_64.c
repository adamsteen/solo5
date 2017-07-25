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
 * ukvm_hv_openbsd_x86_64.c: x86_64 architecture-dependent part of FreeBSD
 * vmm(4) backend implementation.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <machine/vmmvar.h>
#include <machine/specialreg.h>
#include <sys/param.h>
#include <unistd.h>
#include <sys/time.h>

#include "ukvm.h"
#include "ukvm_hv_openbsd.h"
#include "ukvm_cpu_x86_64.h"

uint64_t rdtsc();
uint64_t rdtscp();
uint64_t get_tsc_freq();
static struct vcpu_segment_info sreg_to_vsi(const struct x86_sreg *);

uint64_t rdtscp()
{
    uint32_t lo, hi;
     __asm__ __volatile__ ("RDTSCP\n\t"
                           "mov %%edx, %0\n\t"
                           "mov %%eax, %1\n\t"
                           "CPUID\n\t": "=r" (hi), "=r" (lo):: "%rax", "%rbx", "%rcx", "%rdx");
    return (uint64_t)hi << 32 | lo;
}

uint64_t rdtsc()
{
    uint32_t lo, hi;
     __asm__ __volatile__ ("CPUID\n\t"
                           "RDTSC\n\t"
                           "mov %%edx, %0\n\t"
                           "mov %%eax, %1\n\t": "=r" (hi), "=r" (lo)::
                           "%rax", "%rbx", "%rcx", "%rdx");;
    return (uint64_t)hi << 32 | lo;
}

uint64_t get_tsc_freq() {
    useconds_t usec = 500000;
    uint64_t start_timestamp, end_timestamp;
    struct timeval tv_start, tv_end;

    gettimeofday(&tv_start, NULL);
    start_timestamp = rdtsc();
    usleep(usec);
    end_timestamp = rdtscp();
    gettimeofday(&tv_end, NULL);

    uint64_t cycles = end_timestamp - start_timestamp;
    useconds_t time = (tv_end.tv_sec - tv_start.tv_sec) * 1000000 + tv_end.tv_usec - tv_start.tv_usec;
    return cycles * 1000 / time;
}
static struct vcpu_segment_info sreg_to_vsi(const struct x86_sreg *sreg)
{
    struct vcpu_segment_info vsi = {
        .vsi_sel = sreg->selector * 8,
        .vsi_limit = sreg->limit,
        .vsi_ar = (sreg->type
            | (sreg->s << 4)
            | (sreg->dpl << 5)
            | (sreg->p << 7)
            | (sreg->l << 13)
            | (sreg->db << 14)
            | (sreg->g << 15)
            | (sreg->unusable << X86_SREG_UNUSABLE_BIT)),
        .vsi_base = sreg->base
    };
    return vsi;
}

void ukvm_hv_vcpu_init(struct ukvm_hv *hv, ukvm_gpa_t gpa_ep,
        ukvm_gpa_t gpa_kend, char **cmdline)
{
    struct ukvm_hvb *hvb = hv->b;

	struct vm_resetcpu_params vrp = {
        .vrp_vm_id = hvb->vcp_id,
        .vrp_vcpu_id = hvb->vcpu_id,
        .vrp_init_state = {
            .vrs_gprs[VCPU_REGS_RFLAGS] = X86_RFLAGS_INIT, // as per openbsd
            .vrs_gprs[VCPU_REGS_RIP] = gpa_ep, // check
            .vrs_gprs[VCPU_REGS_RSP] = hv->mem_size - 8, // check
            .vrs_gprs[VCPU_REGS_RDI] = X86_BOOT_INFO_BASE, //check
            .vrs_crs[VCPU_REGS_CR0] = X86_CR0_INIT,
            .vrs_crs[VCPU_REGS_CR3] = X86_CR3_INIT,
            .vrs_crs[VCPU_REGS_CR4] = X86_CR4_INIT,
            .vrs_sregs[VCPU_REGS_CS] = sreg_to_vsi(&ukvm_x86_sreg_code),
            .vrs_sregs[VCPU_REGS_DS] = sreg_to_vsi(&ukvm_x86_sreg_data),
            .vrs_sregs[VCPU_REGS_ES] = sreg_to_vsi(&ukvm_x86_sreg_data),
            .vrs_sregs[VCPU_REGS_FS] = sreg_to_vsi(&ukvm_x86_sreg_data),
            .vrs_sregs[VCPU_REGS_GS] = sreg_to_vsi(&ukvm_x86_sreg_data),
            .vrs_sregs[VCPU_REGS_SS] = sreg_to_vsi(&ukvm_x86_sreg_data),
            .vrs_gdtr = { 0x0, X86_GDTR_LIMIT, 0x0, X86_GDT_BASE},
            .vrs_idtr = { 0x0, 0xFFFF, 0x0, 0x0},
            .vrs_sregs[VCPU_REGS_LDTR] = sreg_to_vsi(&ukvm_x86_sreg_unusable),
            .vrs_sregs[VCPU_REGS_TR] = sreg_to_vsi(&ukvm_x86_sreg_tr),
            .vrs_msrs[VCPU_REGS_EFER] = X86_EFER_LME,
            .vrs_msrs[VCPU_REGS_STAR] = 0ULL,
            .vrs_msrs[VCPU_REGS_LSTAR] = 0ULL,
            .vrs_msrs[VCPU_REGS_CSTAR] = 0ULL,
            .vrs_msrs[VCPU_REGS_SFMASK] = 0ULL,
            .vrs_msrs[VCPU_REGS_KGSBASE] = 0ULL,
            .vrs_crs[VCPU_REGS_XCR0] = XCR0_X87
        }
    };

    ukvm_x86_setup_gdt(hv->mem);
    ukvm_x86_setup_pagetables(hv->mem, hv->mem_size);

    struct ukvm_boot_info *bi =
        (struct ukvm_boot_info *)(hv->mem + X86_BOOT_INFO_BASE);
    bi->mem_size = hv->mem_size;
    bi->kernel_end = gpa_kend;
    bi->cmdline = X86_CMDLINE_BASE; 
    bi->cpu.tsc_freq = get_tsc_freq();

	if (ioctl(hvb->vmd_fd, VMM_IOC_RESETCPU, &vrp) < 0)
        err(1, "Cannot reset VCPU - exiting.");

    *cmdline = (char *)(hv->mem + X86_CMDLINE_BASE);
}

void ukvm_hv_vcpu_loop(struct ukvm_hv *hv) {
    
    struct ukvm_hvb         *hvb = hv->b;
	struct vm_run_params    *vrp;
    uint8_t vcpu_hlt; // TODO do something when we halt

	vrp = malloc(sizeof(struct vm_run_params));
	if (vrp == NULL)
        err(1, "calloc vrp");

    vrp->vrp_exit = malloc(sizeof(union vm_exit));
	if (vrp == NULL)
        err(1, "calloc vrp_exit");

    vrp->vrp_vm_id = hvb->vcp_id;
    vrp->vrp_vcpu_id = hvb->vcpu_id;
	vrp->vrp_continue = 0;

	for (;;) {
        warnx("before VMM_IOC_RUN");
        vrp->vrp_irq = 0xFFFF;
		if (ioctl(hvb->vmd_fd, VMM_IOC_RUN, vrp) < 0) {
			/* If run ioctl failed, exit */
			err(errno, "ukvm_hv_vcpu_loop: vm / vcpu run ioctl failed");
		}
        warnx("after VMM_IOC_RUN");

		/* If the VM is terminating, exit normally */
		if (vrp->vrp_exit_reason == VM_EXIT_TERMINATED) {
            return;
		}
        
        union vm_exit *vei = vrp->vrp_exit;

		if (vrp->vrp_exit_reason != VM_EXIT_NONE) {
            switch (vrp->vrp_exit_reason) {
            case VMX_EXIT_INT_WINDOW:
            case VMX_EXIT_CPUID:
            case VMX_EXIT_EXTINT:
            case SVM_VMEXIT_INTR:
            case VMX_EXIT_EPT_VIOLATION:
            case SVM_VMEXIT_NPF:
            case SVM_VMEXIT_MSR:
            case SVM_VMEXIT_CPUID:
                // nothing to be done here, as per vmd
                break;
            case VMX_EXIT_IO:
            case SVM_VMEXIT_IOIO:
                if (vei->vei.vei_dir != VEI_DIR_OUT
                        || vei->vei.vei_size != 4)
                    errx(1, "Invalid guest port access: port=0x%x", vei->vei.vei_port);
                if (vei->vei.vei_port < UKVM_HYPERCALL_PIO_BASE ||
                        vei->vei.vei_port >= (UKVM_HYPERCALL_PIO_BASE + UKVM_HYPERCALL_MAX))
                    errx(1, "Invalid guest port access: port=0x%x", vei->vei.vei_port);

                int nr = vei->vei.vei_port - UKVM_HYPERCALL_PIO_BASE;
                ukvm_hypercall_fn_t fn = ukvm_core_hypercalls[nr];
                if (fn == NULL)
                    errx(1, "Invalid guest hypercall: num=%d", nr);

                ukvm_gpa_t gpa = vei->vei.vei_data;
                fn(hv, gpa);
                break;
            case VMX_EXIT_HLT:
            case SVM_VMEXIT_HLT:
                vcpu_hlt = 1;
                break;
            case VMX_EXIT_TRIPLE_FAULT:
            case SVM_VMEXIT_SHUTDOWN:
                /* reset VM */
                err(1, "Triple Fault");
            default:
                err(1, "unknown exit reason");
            }

            vrp->vrp_continue = 1;
		}
	}
}
