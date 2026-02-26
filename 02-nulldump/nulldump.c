#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_DESCRIPTION("Character device driver which works like /dev/null but also dumps all written data into dmesg");
MODULE_VERSION("0.1");

#define DEVICE_NAME "nulldump"
#define LINE_WIDTH 16
static int major;

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

static struct file_operations nulldump_fops = {
    .owner = THIS_MODULE,
    .read = nulldump_read,
    .write = nulldump_write,
};

static int __init nulldump_start(void) {
    major = register_chrdev(0, DEVICE_NAME, &nulldump_fops);
    if (major < 0) {
        pr_err("nulldump: failed to register device: %d\n", major);
        return major;
    }
    pr_info("nulldump: registered device with major number %d\n", major);
    return 0;
}

static void __exit nulldump_end(void) {
    unregister_chrdev(major, DEVICE_NAME);
    pr_info("nulldump: unregistered device\n");
}

module_init(nulldump_start);
module_exit(nulldump_end);
