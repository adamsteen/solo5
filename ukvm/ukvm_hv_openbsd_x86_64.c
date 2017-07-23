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
#include <sys/param.h>

#include "ukvm.h"
#include "ukvm_hv_openbsd.h"
#include "ukvm_cpu_x86_64.h"

static void vmm_set_sreg(struct vcpu_segment_info *, const struct x86_sreg *);
int vcpu_exit(uint8_t *, struct vm_run_params *);
int vcpu_reset(int vmd_fd, uint32_t, uint32_t, struct vcpu_reg_state *);
void vcpu_exit_inout(struct vm_run_params *);

/*
 * vmm_set_sreg
 *
 */
static void vmm_set_sreg(struct vcpu_segment_info *vsi, const struct x86_sreg *sreg) {
    vsi->vsi_sel = sreg->selector * 8;
    vsi->vsi_limit = sreg->limit;
    vsi->vsi_ar = (sreg->type
            | (sreg->s << 4)
            | (sreg->dpl << 5)
            | (sreg->p << 7)
            | (sreg->l << 13)
            | (sreg->db << 14)
            | (sreg->g << 15)
            | (sreg->unusable << X86_SREG_UNUSABLE_BIT));
    vsi->vsi_base = sreg->base;
}
/*
 * vcpu_exit
 *
 * Handle a vcpu exit. This function is called when it is determined that
 * vmm(4) requires the assistance of vmd to support a particular guest
 * exit type (eg, accessing an I/O port or device). Guest state is contained
 * in 'vrp', and will be resent to vmm(4) on exit completion.
 *
 * Upon conclusion of handling the exit, the function determines if any
 * interrupts should be injected into the guest, and asserts the proper
 * IRQ line whose interrupt should be vectored.
 *
 * Parameters:
 *  vrp: vcpu run parameters containing guest state for this exit
 *
 * Return values:
 *  0: the exit was handled successfully
 *  1: an error occurred (eg, unknown exit reason passed in 'vrp')
 */
int
vcpu_exit(uint8_t *vcpu_hlt, struct vm_run_params *vrp)
{
	switch (vrp->vrp_exit_reason) {
	case VMX_EXIT_INT_WINDOW:
	case SVM_VMEXIT_VINTR:
	case VMX_EXIT_CPUID:
	case VMX_EXIT_EXTINT:
	case SVM_VMEXIT_INTR:
	case VMX_EXIT_EPT_VIOLATION:
	case SVM_VMEXIT_NPF:
	case SVM_VMEXIT_MSR:
	case SVM_VMEXIT_CPUID:
		/*
		 * We may be exiting to vmd to handle a pending interrupt but
		 * at the same time the last exit type may have been one of
		 * these. In this case, there's nothing extra to be done
		 * here (and falling through to the default case below results
		 * in more vmd log spam).
		 */
		break;
	case VMX_EXIT_IO:
	case SVM_VMEXIT_IOIO:
		vcpu_exit_inout(vrp);
		break;
	case VMX_EXIT_HLT:
	case SVM_VMEXIT_HLT:
		*vcpu_hlt = 1;
		break;
	case VMX_EXIT_TRIPLE_FAULT:
	case SVM_VMEXIT_SHUTDOWN:
		/* reset VM */
		return (EAGAIN);
	default:
		err(1, "unknown exit reason");
	}

	/* Process any pending traffic
     * TODO is this needed?
	vionet_process_rx(vrp->vrp_vm_id);
     * */

	vrp->vrp_continue = 1;

	return (0);
}

/*
 * vcpu_reset
 *
 * Requests vmm(4) to reset the VCPUs in the indicated VM to
 * the register state provided
 *
 * Parameters
 *  vmid: VM ID to reset
 *  vcpu_id: VCPU ID to reset
 *  vrs: the register state to initialize
 *
 * Return values:
 *  0: success
 *  !0 : ioctl to vmm(4) failed (eg, ENOENT if the supplied VM ID is not
 *      valid)
 */
int
vcpu_reset(int vmd_fd, uint32_t vmid, uint32_t vcpu_id, struct vcpu_reg_state *vrs)
{
	struct vm_resetcpu_params vrp;

	memset(&vrp, 0, sizeof(vrp));
	vrp.vrp_vm_id = vmid;
	vrp.vrp_vcpu_id = vcpu_id;
	memcpy(&vrp.vrp_init_state, vrs, sizeof(struct vcpu_reg_state));

	if (ioctl(vmd_fd, VMM_IOC_RESETCPU, &vrp) < 0)
		return (errno);

	return (0);
}

/*
 * vcpu_exit_inout
 *
 * Handle all I/O exits that need to be emulated in vmd. This includes the
 * i8253 PIT, the com1 ns8250 UART, and the MC146818 RTC/NVRAM device.
 *
 * Parameters:
 *  vrp: vcpu run parameters containing guest state for this exit
 */
void
vcpu_exit_inout(struct vm_run_params *vrp)
{
    err(1, "NOT YET IMPLEMENTED - vcpu_exit_inout: %u", vrp->vrp_exit_reason);
}

void ukvm_hv_vcpu_init(struct ukvm_hv *hv, ukvm_gpa_t gpa_ep,
        ukvm_gpa_t gpa_kend, char **cmdline)
{
    struct vcpu_reg_state	vrs;
    struct ukvm_hvb         *hvb = hv->b;

    ukvm_x86_setup_gdt(hv->mem);
    ukvm_x86_setup_pagetables(hv->mem, hv->mem_size);

    memcpy(&vrs, &vcpu_init_flat32, sizeof(vrs));
    vrs.vrs_crs[VCPU_REGS_CR0] = X86_CR0_INIT;
    vrs.vrs_crs[VCPU_REGS_CR3] = X86_CR3_INIT;
    vrs.vrs_crs[VCPU_REGS_CR4] = X86_CR4_INIT;
    vrs.vrs_msrs[VCPU_REGS_EFER] = X86_EFER_INIT;

    vmm_set_sreg(&vrs.vrs_sregs[VCPU_REGS_CS], &ukvm_x86_sreg_code);
    vmm_set_sreg(&vrs.vrs_sregs[VCPU_REGS_SS], &ukvm_x86_sreg_data);
    vmm_set_sreg(&vrs.vrs_sregs[VCPU_REGS_DS], &ukvm_x86_sreg_data);
    vmm_set_sreg(&vrs.vrs_sregs[VCPU_REGS_ES], &ukvm_x86_sreg_data);
    vmm_set_sreg(&vrs.vrs_sregs[VCPU_REGS_FS], &ukvm_x86_sreg_data);
    vmm_set_sreg(&vrs.vrs_sregs[VCPU_REGS_GS], &ukvm_x86_sreg_data);

    vrs.vrs_gdtr.vsi_limit = X86_GDTR_LIMIT;
    vrs.vrs_gdtr.vsi_base = X86_GDT_BASE;
    
    vmm_set_sreg(&vrs.vrs_sregs[VCPU_REGS_LDTR], &ukvm_x86_sreg_unusable);
    vmm_set_sreg(&vrs.vrs_sregs[VCPU_REGS_TR], &ukvm_x86_sreg_tr);

    vrs.vrs_gprs[VCPU_REGS_RIP] = gpa_ep;
    vrs.vrs_gprs[VCPU_REGS_RFLAGS] = X86_RFLAGS_INIT;
    vrs.vrs_gprs[VCPU_REGS_RSP] = hv->mem_size - 8;
    vrs.vrs_gprs[VCPU_REGS_RDI] = X86_BOOT_INFO_BASE;

    struct ukvm_boot_info *bi =
        (struct ukvm_boot_info *)(hv->mem + X86_BOOT_INFO_BASE);
    bi->mem_size = hv->mem_size;
    bi->kernel_end = gpa_kend;
    bi->cmdline = X86_CMDLINE_BASE;

    if (vcpu_reset(hvb->vmd_fd, hvb->vcp_id, 0, &vrs))
        err(1, "Cannot reset VCPU - exiting.");

    *cmdline = (char *)(hv->mem + X86_CMDLINE_BASE);
}

void ukvm_hv_vcpu_loop(struct ukvm_hv *hv) {
    
    struct ukvm_hvb         *hvb = hv->b;
	struct vm_run_params    *vrp;
    uint8_t vcpu_hlt;
	intptr_t ret = 0;

	vrp = malloc(sizeof(struct vm_run_params));
	if (vrp == NULL)
        err(1, "calloc vrp");

    vrp->vrp_exit = malloc(sizeof(union vm_exit));
	if (vrp == NULL)
        err(1, "calloc vrp_exit");


    vrp->vrp_vm_id = hvb->vcp_id;
    vrp->vrp_vcpu_id = 0;
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

		if (vrp->vrp_exit_reason != VM_EXIT_NONE) {
			/*
			 * vmm(4) needs help handling an exit, handle in
			 * vcpu_exit.
			 */
			ret = vcpu_exit(&vcpu_hlt, vrp);
			if (ret)
				break;
		}
	}
}
