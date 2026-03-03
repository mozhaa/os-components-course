#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_DESCRIPTION("Character device driver which works like /dev/null but also dumps all written data into dmesg");
MODULE_VERSION("0.1");

#define DEVICE_NAME "nulldump"
#define CLASS_NAME "nulldump"
#define LINE_WIDTH 16

static int major;
static struct class *nulldump_class = NULL;
static struct device *nulldump_device = NULL;

static ssize_t nulldump_read(struct file *file, char __user *buf, size_t size, loff_t *ppos) {
    pr_info("nulldump: read of %lu bytes from pid=%d, comm=%s\n", size, current->pid, current->comm);
    return 0;
}

static ssize_t nulldump_write(struct file *file, const char __user *data, size_t size, loff_t *ppos) {
    size_t offset = 0;
    unsigned char linebuf[LINE_WIDTH];
    char outbuf[LINE_WIDTH * 4 + 20];

    pr_info("nulldump: write of %lu bytes from pid=%d, comm=%s\n", size, current->pid, current->comm);

    while (offset < size) {
        size_t chunk = size - offset;
        size_t i, bytes_this_line = (chunk < LINE_WIDTH) ? chunk : LINE_WIDTH;
        unsigned long uncopied;
        char *p = outbuf;

        uncopied = copy_from_user(linebuf, data + offset, bytes_this_line);
        if (uncopied) {
            return -EFAULT;
        }

        for (i = 0; i < bytes_this_line; i++) {
            p += sprintf(p, "%02x ", linebuf[i]);
        }

        for (i = bytes_this_line; i < LINE_WIDTH; i++) {
            p += sprintf(p, "   ");
        }

        p += sprintf(p, " |");

        for (i = 0; i < bytes_this_line; i++) {
            *p++ = isprint(linebuf[i]) ? linebuf[i] : '.';
        }

        p += sprintf(p, "|");
        *p = 0;

        pr_info("nulldump: %s\n", outbuf);
        offset += bytes_this_line;
    }

    return size;
}

static char *nulldump_devnode(const struct device *dev, umode_t *mode) {
    if (mode) {
        *mode = 0666;
    }
    return NULL;
}

static struct file_operations nulldump_fops = {
    .owner = THIS_MODULE,
    .read = nulldump_read,
    .write = nulldump_write,
};

static int __init nulldump_start(void) {
    int ret;

    major = register_chrdev(0, DEVICE_NAME, &nulldump_fops);
    if (major < 0) {
        ret = major;
        pr_err("nulldump: failed to register device: %d\n", ret);
        goto fail_operations;
    }

    nulldump_class = class_create(CLASS_NAME);
    if (IS_ERR(nulldump_class)) {
        ret = PTR_ERR(nulldump_class);
        pr_err("nulldump: failed to create class: %d\n", ret);
        goto fail_class;
    }

    nulldump_class->devnode = nulldump_devnode;

    nulldump_device = device_create(nulldump_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(nulldump_device)) {
        ret = PTR_ERR(nulldump_device);
        pr_err("nulldump: failed to create device: %d\n", ret);
        goto fail_device;
    }

    pr_info("nulldump: created device at /dev/%s\n", DEVICE_NAME);
    return 0;

fail_device:
    class_destroy(nulldump_class);
fail_class:
    unregister_chrdev(major, DEVICE_NAME);
fail_operations:
    return ret;
}

static void __exit nulldump_end(void) {
    device_destroy(nulldump_class, MKDEV(major, 0));
    class_destroy(nulldump_class);
    unregister_chrdev(major, DEVICE_NAME);
    pr_info("nulldump: unregistered device\n");
}

module_init(nulldump_start);
module_exit(nulldump_end);
