#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_DESCRIPTION("Character device driver which works like /dev/null but also dumps all written data into dmesg");
MODULE_VERSION("0.1");

#define DEVICE_NAME "nulldump"
static int major;

static ssize_t nulldump_read(struct file *file, char __user *buf, size_t size, loff_t *ppos) { return 0; }

static ssize_t nulldump_write(struct file *file, const char __user *data, size_t len, loff_t *ppos) { return len; }

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
