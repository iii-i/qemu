/*
 * Virtio kcov coverage-advertisement device.
 *
 * The guest driver publishes its kcov coverage buffer's guest-physical pages
 * into this device's config space (a control-block pointer plus a generation
 * counter written last). QEMU reads the control block, maps the pages for
 * translation-free host access, and hands them to a registered consumer -- the
 * sclp-fuzz coverage reader, or any other target. Nothing here is s390-specific.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at your
 * option) any later version.  See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-kcov.h"
#include "system/memory.h"
#include "system/address-spaces.h"
#include "standard-headers/linux/virtio_ids.h"

/*
 * A single coverage consumer and the currently-armed device. There is one
 * virtio-kcov device per campaign; keeping this module-global keeps the device
 * generic -- it knows nothing about who reads the coverage.
 */
static VirtIOKcov *virtio_kcov_active;
static struct {
    void (*advertise)(void *opaque);
    void (*reset)(void *opaque);
    void *opaque;
} virtio_kcov_consumer;

void virtio_kcov_set_consumer(void (*advertise)(void *opaque),
                              void (*reset)(void *opaque), void *opaque)
{
    virtio_kcov_consumer.advertise = advertise;
    virtio_kcov_consumer.reset = reset;
    virtio_kcov_consumer.opaque = opaque;
}

unsigned virtio_kcov_buffer(void ***hva, uint64_t *words)
{
    VirtIOKcov *k = virtio_kcov_active;

    if (!k || !k->npages) {
        *hva = NULL;
        *words = 0;
        return 0;
    }
    *hva = k->hva;
    *words = k->words;
    return k->npages;
}

static void virtio_kcov_unmap(VirtIOKcov *k)
{
    for (unsigned i = 0; i < k->npages; i++) {
        if (k->hva[i]) {
            address_space_unmap(&address_space_memory, k->hva[i],
                                k->maplen[i], true, k->maplen[i]);
            k->hva[i] = NULL;
        }
    }
    k->npages = 0;
    k->words = 0;
}

/*
 * Read the control block at desc_gpa ({npages, words, gpa[]}, little-endian) and
 * map each coverage page for direct host access. Returns false (and leaves the
 * device disarmed) on any malformed descriptor or unmappable page.
 */
static bool virtio_kcov_map(VirtIOKcov *k)
{
    uint64_t hdr[2];
    uint64_t gpa[VIRTIO_KCOV_MAX_PAGES];
    uint64_t desc = k->config.desc_gpa;
    unsigned n, i;

    if (!desc) {
        return false;
    }
    if (address_space_read(&address_space_memory, desc, MEMTXATTRS_UNSPECIFIED,
                           hdr, sizeof(hdr)) != MEMTX_OK) {
        return false;
    }
    n = le64_to_cpu(hdr[0]);
    if (n == 0 || n > VIRTIO_KCOV_MAX_PAGES) {
        return false;
    }
    if (address_space_read(&address_space_memory, desc + sizeof(hdr),
                           MEMTXATTRS_UNSPECIFIED, gpa,
                           (uint64_t)n * sizeof(uint64_t)) != MEMTX_OK) {
        return false;
    }
    k->words = le64_to_cpu(hdr[1]);
    for (i = 0; i < n; i++) {
        hwaddr len = VIRTIO_KCOV_PAGE;
        void *p = address_space_map(&address_space_memory, le64_to_cpu(gpa[i]),
                                    &len, true, MEMTXATTRS_UNSPECIFIED);

        if (!p || len < VIRTIO_KCOV_PAGE) {
            if (p) {
                address_space_unmap(&address_space_memory, p, len, true, 0);
            }
            virtio_kcov_unmap(k);
            return false;
        }
        k->hva[i] = p;
        k->maplen[i] = len;
    }
    k->npages = n;
    return true;
}

static void virtio_kcov_get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    VirtIOKcov *k = VIRTIO_KCOV(vdev);
    VirtIOKcovConfig c = {
        .desc_gpa = cpu_to_le64(k->config.desc_gpa),
        .generation = cpu_to_le32(k->config.generation),
    };

    memcpy(config_data, &c, sizeof(c));
}

/*
 * The guest wrote config space. It writes desc_gpa first, then bumps generation
 * last to commit; act only when generation advances (with desc_gpa in place),
 * re-mapping the new boot's pages and re-arming the consumer.
 */
static void virtio_kcov_set_config(VirtIODevice *vdev,
                                   const uint8_t *config_data)
{
    VirtIOKcov *k = VIRTIO_KCOV(vdev);
    VirtIOKcovConfig c;

    memcpy(&c, config_data, sizeof(c));
    k->config.desc_gpa = le64_to_cpu(c.desc_gpa);
    k->config.generation = le32_to_cpu(c.generation);

    if (k->config.generation == k->latched) {
        return;
    }
    virtio_kcov_unmap(k);
    if (!virtio_kcov_map(k)) {
        return;
    }
    k->latched = k->config.generation;
    virtio_kcov_active = k;
    if (virtio_kcov_consumer.advertise) {
        virtio_kcov_consumer.advertise(virtio_kcov_consumer.opaque);
    }
}

static void virtio_kcov_device_reset(VirtIODevice *vdev)
{
    VirtIOKcov *k = VIRTIO_KCOV(vdev);

    virtio_kcov_unmap(k);
    k->config.desc_gpa = 0;
    k->config.generation = 0;
    k->latched = 0;
    if (virtio_kcov_active == k) {
        virtio_kcov_active = NULL;
    }
    if (virtio_kcov_consumer.reset) {
        virtio_kcov_consumer.reset(virtio_kcov_consumer.opaque);
    }
}

static uint64_t virtio_kcov_get_features(VirtIODevice *vdev, uint64_t features,
                                         Error **errp)
{
    return features;
}

/* The guest advertises via config space; this queue is never used. */
static void virtio_kcov_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
}

static void virtio_kcov_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOKcov *k = VIRTIO_KCOV(dev);

    virtio_init(vdev, VIRTIO_ID_KCOV, sizeof(VirtIOKcovConfig));
    k->vq = virtio_add_queue(vdev, 4, virtio_kcov_handle_output);
}

static void virtio_kcov_device_unrealize(DeviceState *dev)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOKcov *k = VIRTIO_KCOV(dev);

    virtio_kcov_unmap(k);
    if (virtio_kcov_active == k) {
        virtio_kcov_active = NULL;
    }
    virtio_del_queue(vdev, 0);
    virtio_cleanup(vdev);
}

static void virtio_kcov_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    vdc->realize = virtio_kcov_device_realize;
    vdc->unrealize = virtio_kcov_device_unrealize;
    vdc->get_config = virtio_kcov_get_config;
    vdc->set_config = virtio_kcov_set_config;
    vdc->get_features = virtio_kcov_get_features;
    vdc->reset = virtio_kcov_device_reset;
}

static const TypeInfo virtio_kcov_info = {
    .name = TYPE_VIRTIO_KCOV,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOKcov),
    .class_init = virtio_kcov_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_kcov_info);
}

type_init(virtio_register_types)
