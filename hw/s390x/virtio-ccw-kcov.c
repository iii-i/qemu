/*
 * virtio ccw kcov coverage-advertisement implementation
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at
 * your option) any later version. See the COPYING file in the top-level
 * directory.
 */

#include "qemu/osdep.h"
#include "hw/core/qdev-properties.h"
#include "hw/virtio/virtio.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "virtio-ccw.h"
#include "hw/virtio/virtio-kcov.h"

#define TYPE_VIRTIO_KCOV_CCW "virtio-kcov-ccw"
OBJECT_DECLARE_SIMPLE_TYPE(VirtIOKcovCcw, VIRTIO_KCOV_CCW)

struct VirtIOKcovCcw {
    VirtioCcwDevice parent_obj;
    VirtIOKcov vdev;
};

static void virtio_ccw_kcov_realize(VirtioCcwDevice *ccw_dev, Error **errp)
{
    VirtIOKcovCcw *dev = VIRTIO_KCOV_CCW(ccw_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);

    if (!qdev_realize(vdev, BUS(&ccw_dev->bus), errp)) {
        return;
    }
}

static void virtio_ccw_kcov_instance_init(Object *obj)
{
    VirtIOKcovCcw *dev = VIRTIO_KCOV_CCW(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_KCOV);
}

static const Property virtio_ccw_kcov_properties[] = {
    DEFINE_PROP_BIT("ioeventfd", VirtioCcwDevice, flags,
                    VIRTIO_CCW_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_UINT32("max_revision", VirtioCcwDevice, max_rev,
                       VIRTIO_CCW_MAX_REV),
};

static void virtio_ccw_kcov_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtIOCCWDeviceClass *k = VIRTIO_CCW_DEVICE_CLASS(klass);

    k->realize = virtio_ccw_kcov_realize;
    device_class_set_props(dc, virtio_ccw_kcov_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo virtio_ccw_kcov = {
    .name          = TYPE_VIRTIO_KCOV_CCW,
    .parent        = TYPE_VIRTIO_CCW_DEVICE,
    .instance_size = sizeof(VirtIOKcovCcw),
    .instance_init = virtio_ccw_kcov_instance_init,
    .class_init    = virtio_ccw_kcov_class_init,
};

static void virtio_ccw_kcov_register(void)
{
    type_register_static(&virtio_ccw_kcov);
}

type_init(virtio_ccw_kcov_register)
