/*
 * QEMU PCI device that shares the host vCPU threads' rseq.slice_ctrl with
 * the guest.
 *
 * BAR0 layout (all little-endian):
 *
 *   Page 0 (header):
 *     +0x000  u32 magic     = 'S','L','C','S'   ("SLCS" in memory)
 *     +0x004  u32 version
 *     +0x008  u32 nr_cpus
 *     +0x00C  u32 page_size
 *     +0x010  u32 slice_ctrl_offset[nr_cpus]
 *               byte offset, from the start of CPU N's data page, of the
 *               rseq_slice_ctrl field for that vCPU. ~0u means "not
 *               available" (e.g. the host thread did not have rseq
 *               registered when the device was probed).
 *
 *   Page 1 .. nr_cpus:
 *     The host page that contains vCPU (i-1)'s registered struct rseq.
 *     Reads observe whatever the host kernel writes to slice_ctrl.granted
 *     for that thread; writes from the guest land in the host page and
 *     are observed by the host kernel as the thread's slice_ctrl.request.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/units.h"
#include "qemu/module.h"
#include "qemu/host-utils.h"
#include "qemu/main-loop.h"
#include "qemu/memalign.h"
#include "qapi/error.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_device.h"
#include "hw/core/boards.h"
#include "hw/core/cpu.h"
#include "system/system.h"
#include "qom/object.h"

#include <linux/rseq.h>

/*
 * Offset of struct rseq_slice_ctrl within struct rseq, per
 * include/uapi/linux/rseq.h. Hard-coded so that this file builds against
 * older system headers that predate the slice extension.
 */
#define RSEQ_SLICE_CTRL_OFFSET 28u

/*
 * Glibc (>= 2.35) registers an rseq area in TLS for every pthread. The
 * symbol __rseq_abi itself is hidden in modern glibc, but __rseq_offset
 * and __rseq_size are exported, and the area lives at
 *
 *     (char *)__builtin_thread_pointer() + __rseq_offset
 *
 * for the current thread. Evaluating that inside a vCPU thread therefore
 * yields the rseq pointer the host kernel updates for it.
 */
extern ptrdiff_t __rseq_offset;
extern unsigned int __rseq_size;

#define TYPE_PCI_KVM_SLICE_CTRL "kvm-slice-ctrl"
typedef struct KvmSliceCtrlState KvmSliceCtrlState;
DECLARE_INSTANCE_CHECKER(KvmSliceCtrlState, KVM_SLICE_CTRL,
                         TYPE_PCI_KVM_SLICE_CTRL)

#define KSC_MAGIC   0x53434C53u   /* 'S','L','C','S' little-endian */
#define KSC_VERSION 1u

#define KSC_OFFSET_INVALID (~0u)

struct KvmSliceCtrlHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t nr_cpus;
    uint32_t page_size;
    uint32_t slice_ctrl_offset[];
};

struct KvmSliceCtrlState {
    PCIDevice pdev;
    Notifier machine_done;

    uint32_t nr_cpus;
    uintptr_t page_size;

    MemoryRegion bar;
    MemoryRegion header_mr;
    void *header_page;

    MemoryRegion *cpu_mr;       /* nr_cpus entries */
    void **cpu_pages;           /* host page-aligned pointers (or NULL) */
    uint32_t *cpu_offsets;      /* in-page offset of rseq, or KSC_OFFSET_INVALID */
};

struct KscThreadInfo {
    void *page;
    uint32_t offset;
};

static void ksc_collect_rseq(CPUState *cs, run_on_cpu_data data)
{
    struct KscThreadInfo *info = data.host_ptr;
    uintptr_t addr;
    uintptr_t page_size = qemu_real_host_page_size();

    if (__rseq_size == 0) {
        info->page = NULL;
        info->offset = 0;
        return;
    }
    addr = (uintptr_t)__builtin_thread_pointer() + __rseq_offset;
    info->page = (void *)(addr & ~(page_size - 1));
    info->offset = (uint32_t)(addr & (page_size - 1));
}

static void ksc_machine_done(Notifier *n, void *opaque)
{
    KvmSliceCtrlState *s = container_of(n, KvmSliceCtrlState, machine_done);
    struct KvmSliceCtrlHeader *hdr = s->header_page;
    CPUState *cs;

    CPU_FOREACH(cs) {
        unsigned idx = cs->cpu_index;
        struct KscThreadInfo info = { .offset = KSC_OFFSET_INVALID };
        g_autofree char *name = NULL;

        if (idx >= s->nr_cpus || !cs->created) {
            continue;
        }

        run_on_cpu(cs, ksc_collect_rseq, RUN_ON_CPU_HOST_PTR(&info));

        if (!info.page) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "kvm-slice-ctrl: vCPU %u has no rseq registered\n",
                          idx);
            continue;
        }

        s->cpu_pages[idx] = info.page;
        s->cpu_offsets[idx] = info.offset;

        name = g_strdup_printf("kvm-slice-ctrl-cpu%u", idx);
        memory_region_init_ram_device_ptr(&s->cpu_mr[idx], OBJECT(s), name,
                                          s->page_size, info.page);
        memory_region_add_subregion(&s->bar,
                                    (uint64_t)(idx + 1) * s->page_size,
                                    &s->cpu_mr[idx]);
    }

    /* Publish offsets atomically-enough: the guest probes after the BAR is
     * mapped, by which time these stores are committed. */
    for (uint32_t i = 0; i < s->nr_cpus; i++) {
        if (s->cpu_offsets[i] == KSC_OFFSET_INVALID) {
            hdr->slice_ctrl_offset[i] = KSC_OFFSET_INVALID;
        } else {
            hdr->slice_ctrl_offset[i] =
                s->cpu_offsets[i] + RSEQ_SLICE_CTRL_OFFSET;
        }
    }
}

static void pci_ksc_realize(PCIDevice *pdev, Error **errp)
{
    KvmSliceCtrlState *s = KVM_SLICE_CTRL(pdev);
    MachineState *ms = MACHINE(qdev_get_machine());
    struct KvmSliceCtrlHeader *hdr;
    uint64_t bar_size;

    s->page_size = qemu_real_host_page_size();
    s->nr_cpus = ms->smp.cpus;
    if (s->nr_cpus == 0) {
        error_setg(errp, "kvm-slice-ctrl: no vCPUs");
        return;
    }

    /* Header occupies one page; size must fit nr_cpus offset entries. */
    if (sizeof(*hdr) + s->nr_cpus * sizeof(uint32_t) > s->page_size) {
        error_setg(errp, "kvm-slice-ctrl: too many vCPUs (%u) for one header page",
                   s->nr_cpus);
        return;
    }

    s->cpu_mr = g_new0(MemoryRegion, s->nr_cpus);
    s->cpu_pages = g_new0(void *, s->nr_cpus);
    s->cpu_offsets = g_new(uint32_t, s->nr_cpus);
    for (uint32_t i = 0; i < s->nr_cpus; i++) {
        s->cpu_offsets[i] = KSC_OFFSET_INVALID;
    }

    s->header_page = qemu_memalign(s->page_size, s->page_size);
    memset(s->header_page, 0, s->page_size);
    hdr = s->header_page;
    hdr->magic = KSC_MAGIC;
    hdr->version = KSC_VERSION;
    hdr->nr_cpus = s->nr_cpus;
    hdr->page_size = (uint32_t)s->page_size;
    for (uint32_t i = 0; i < s->nr_cpus; i++) {
        hdr->slice_ctrl_offset[i] = KSC_OFFSET_INVALID;
    }

    /* PCI BARs must be a power-of-two in size; round up. */
    bar_size = pow2ceil((uint64_t)(1 + s->nr_cpus) * s->page_size);
    memory_region_init(&s->bar, OBJECT(s), "kvm-slice-ctrl", bar_size);
    memory_region_init_ram_ptr(&s->header_mr, OBJECT(s),
                               "kvm-slice-ctrl-hdr",
                               s->page_size, s->header_page);
    memory_region_add_subregion(&s->bar, 0, &s->header_mr);
    pci_register_bar(pdev, 0,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_TYPE_64,
                     &s->bar);

    /* The vCPU threads aren't necessarily running yet at realize. Wait
     * until the machine is up so run_on_cpu() can dispatch into them. */
    s->machine_done.notify = ksc_machine_done;
    qemu_add_machine_init_done_notifier(&s->machine_done);
}

static void pci_ksc_uninit(PCIDevice *pdev)
{
    KvmSliceCtrlState *s = KVM_SLICE_CTRL(pdev);

    qemu_remove_machine_init_done_notifier(&s->machine_done);
    g_free(s->cpu_mr);
    g_free(s->cpu_pages);
    g_free(s->cpu_offsets);
    qemu_vfree(s->header_page);
}

static void ksc_class_init(ObjectClass *class, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_ksc_realize;
    k->exit = pci_ksc_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x11ec;
    k->revision = 0x01;
    k->class_id = PCI_CLASS_OTHERS;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo ksc_types[] = {
    {
        .name          = TYPE_PCI_KVM_SLICE_CTRL,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(KvmSliceCtrlState),
        .class_init    = ksc_class_init,
        .interfaces    = (const InterfaceInfo[]) {
            { INTERFACE_CONVENTIONAL_PCI_DEVICE },
            { },
        },
    }
};

DEFINE_TYPES(ksc_types)
