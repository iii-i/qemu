/*
 * Virtio kcov coverage-advertisement device.
 *
 * The guest publishes its kcov coverage buffer (guest-physical pages) through
 * this device's config space; QEMU records the pages, maps them for
 * translation-free reads, and hands them to a registered consumer (e.g. the
 * sclp-fuzz coverage reader). Generic across transports -- nothing here is
 * s390-specific.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at your
 * option) any later version.
 */

#ifndef QEMU_VIRTIO_KCOV_H
#define QEMU_VIRTIO_KCOV_H

#include "hw/virtio/virtio.h"
#include "qom/object.h"

#define TYPE_VIRTIO_KCOV "virtio-kcov-device"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOKcov, VIRTIO_KCOV)

/* Caps the coverage buffer at 1 MiB (256 * 4 KiB) / 128K PCs. */
#define VIRTIO_KCOV_MAX_PAGES 256
#define VIRTIO_KCOV_PAGE      4096

/* Config space (little-endian on the wire); see include/uapi/linux/virtio_kcov.h. */
typedef struct QEMU_PACKED VirtIOKcovConfig {
    uint64_t desc_gpa;    /* guest-physical addr of the control block */
    uint32_t generation;  /* bumped by the guest last; QEMU latches here */
} VirtIOKcovConfig;

struct VirtIOKcov {
    VirtIODevice parent_obj;

    /* Unused: the advertise rides config space. Kept so the device has the
     * customary >=1 virtqueue that transports (virtio-ccw) expect. */
    VirtQueue *vq;

    VirtIOKcovConfig config;
    uint32_t latched;              /* last generation acted on */

    /* Current advertised coverage buffer, mapped for direct host access. */
    uint64_t words;                /* buffer size in longs (kcov area size) */
    unsigned npages;
    void *hva[VIRTIO_KCOV_MAX_PAGES];
    hwaddr maplen[VIRTIO_KCOV_MAX_PAGES];
};

/*
 * The current coverage buffer, mapped page by page (host pointers). Returns the
 * page count (0 if none is armed) and fills *words with the buffer's length in
 * longs. Word w lives at hva[w / (PAGE/8)] + (w % (PAGE/8)); page 0 word 0 is
 * the kcov position counter. Valid until the next advertise/reset.
 */
unsigned virtio_kcov_buffer(void ***hva, uint64_t *words);

/*
 * Register the single coverage consumer. @advertise fires when the guest
 * (re-)advertises a buffer (arm / re-arm); @reset fires on device reset
 * (disarm). Either may be NULL.
 */
void virtio_kcov_set_consumer(void (*advertise)(void *opaque),
                              void (*reset)(void *opaque), void *opaque);

#endif
