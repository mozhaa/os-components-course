#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_DESCRIPTION("kpipe");
MODULE_VERSION("0.1");

#define DEVICE_NAME "kpipe"
#define CLASS_NAME "kpipe"
#define LINE_WIDTH 16

static int major;
static unsigned long size = 4096;
static struct class *kpipe_class = NULL;
static struct device *kpipe_device = NULL;

static ssize_t kpipe_read(struct file *file, char __user *buf, size_t size, loff_t *ppos) { return 0; }

static ssize_t kpipe_write(struct file *file, const char __user *data, size_t size, loff_t *ppos) { return size; }

static char *kpipe_devnode(const struct device *dev, umode_t *mode) {
    if (mode) {
        *mode = 0666;
    }
    return NULL;
}

static struct file_operations kpipe_fops = {
    .owner = THIS_MODULE,
    .read = kpipe_read,
    .write = kpipe_write,
};

static int __init kpipe_start(void) {
    int ret;

    major = register_chrdev(0, DEVICE_NAME, &kpipe_fops);
    if (major < 0) {
        ret = major;
        pr_err("kpipe: failed to register device: %d\n", ret);
        goto fail_operations;
    }

    kpipe_class = class_create(CLASS_NAME);
    if (IS_ERR(kpipe_class)) {
        ret = PTR_ERR(kpipe_class);
        pr_err("kpipe: failed to create class: %d\n", ret);
        goto fail_class;
    }

    kpipe_class->devnode = kpipe_devnode;

    kpipe_device = device_create(kpipe_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(kpipe_device)) {
        ret = PTR_ERR(kpipe_device);
        pr_err("kpipe: failed to create device: %d\n", ret);
        goto fail_device;
    }

    pr_info("kpipe: created device at /dev/%s\n", DEVICE_NAME);
    return 0;

fail_device:
    class_destroy(kpipe_class);
fail_class:
    unregister_chrdev(major, DEVICE_NAME);
fail_operations:
    return ret;
}

static void __exit kpipe_end(void) {
    device_destroy(kpipe_class, MKDEV(major, 0));
    class_destroy(kpipe_class);
    unregister_chrdev(major, DEVICE_NAME);
    pr_info("kpipe: unregistered device\n");
}

module_param(size, ulong, 0644);
MODULE_PARM_DESC(size, "buffer size");

module_init(kpipe_start);
module_exit(kpipe_end);
