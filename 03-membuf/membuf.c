#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_DESCRIPTION("Memory buffers with fixed sizes");
MODULE_VERSION("0.1");

static int num_devices = 1;
static int default_buf_size = 4096;

module_param(num_devices, int, 0644);
MODULE_PARM_DESC(num_devices, "number of membuf devices");

module_param(default_buf_size, int, 0644);
MODULE_PARM_DESC(default_buf_size, "default buffer size");

static struct class *membuf_class = NULL;
static dev_t membuf_dev_num;
static struct membuf_dev {
    struct cdev cdev;
} *membuf_devices = NULL;

static int membuf_open(struct inode *inode, struct file *file) {
    struct membuf_dev *dev = container_of(inode->i_cdev, struct membuf_dev, cdev);
    file->private_data = dev;
    pr_info("membuf: open device\n");
    return 0;
}

static int membuf_release(struct inode *inode, struct file *file) {
    pr_info("membuf: release device\n");
    return 0;
}

static ssize_t membuf_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    pr_info("membuf: read %zu bytes from offset %lld\n", count, *ppos);
    return 0;
}

static ssize_t membuf_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    pr_info("membuf: write %zu bytes at offset %lld\n", count, *ppos);
    return count;
}

static const struct file_operations membuf_fops = {
    .owner = THIS_MODULE,
    .open = membuf_open,
    .release = membuf_release,
    .read = membuf_read,
    .write = membuf_write,
};

static int __init membuf_init(void) {
    pr_info("membuf: loading module\n");
    pr_info("membuf: num_devices = %d\n", num_devices);
    pr_info("membuf: default_buf_size = %d\n", default_buf_size);

    if (num_devices <= 0) {
        pr_err("membuf: num_devices must be positive\n");
        return -EINVAL;
    }
    if (default_buf_size <= 0) {
        pr_err("membuf: default_buf_size must be positive\n");
        return -EINVAL;
    }

    membuf_devices = kmalloc_array(num_devices, sizeof(struct membuf_dev), GFP_KERNEL);
    if (!membuf_devices) {
        pr_err("membuf: failed to allocate device array\n");
        return -ENOMEM;
    }

    int ret = alloc_chrdev_region(&membuf_dev_num, 0, num_devices, "membuf");
    if (ret < 0) {
        pr_err("membuf: failed to allocate chrdev region\n");
        goto err_free_devices;
    }

    membuf_class = class_create("membuf");
    if (IS_ERR(membuf_class)) {
        ret = PTR_ERR(membuf_class);
        pr_err("membuf: failed to create class\n");
        goto err_unregister_region;
    }

    int i;
    for (i = 0; i < num_devices; i++) {
        dev_t devt = MKDEV(MAJOR(membuf_dev_num), i);

        cdev_init(&membuf_devices[i].cdev, &membuf_fops);
        membuf_devices[i].cdev.owner = THIS_MODULE;

        ret = cdev_add(&membuf_devices[i].cdev, devt, 1);
        if (ret < 0) {
            pr_err("membuf: failed to add cdev for device %d\n", i);
            goto err_remove_cdevs;
        }

        if (device_create(membuf_class, NULL, devt, NULL, "membuf%d", i) == NULL) {
            pr_err("membuf: failed to create device node membuf%d\n", i);
            ret = -ENOMEM;
            cdev_del(&membuf_devices[i].cdev);
            goto err_remove_cdevs;
        }
    }

    pr_info("membuf: successfully created %d devices\n", num_devices);
    return 0;

err_remove_cdevs:
    while (i--) {
        device_destroy(membuf_class, MKDEV(MAJOR(membuf_dev_num), i));
        cdev_del(&membuf_devices[i].cdev);
    }
    class_destroy(membuf_class);
err_unregister_region:
    unregister_chrdev_region(membuf_dev_num, num_devices);
err_free_devices:
    kfree(membuf_devices);
    return ret;
}

static void __exit membuf_exit(void) {
    pr_info("membuf: unloading module\n");

    for (int i = num_devices - 1; i >= 0; i--) {
        dev_t devt = MKDEV(MAJOR(membuf_dev_num), i);
        device_destroy(membuf_class, devt);
        cdev_del(&membuf_devices[i].cdev);
    }

    class_destroy(membuf_class);
    unregister_chrdev_region(membuf_dev_num, num_devices);
    kfree(membuf_devices);
}

module_init(membuf_init);
module_exit(membuf_exit);
