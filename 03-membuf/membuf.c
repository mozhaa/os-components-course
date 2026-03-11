#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

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
    char *buffer;
    size_t size;
    struct mutex lock;
    atomic_t open_count;
} *membuf_devices = NULL;

static int membuf_open(struct inode *inode, struct file *file) {
    struct membuf_dev *dev = container_of(inode->i_cdev, struct membuf_dev, cdev);
    atomic_inc(&dev->open_count);
    if (!try_module_get(THIS_MODULE)) {
        atomic_dec(&dev->open_count);
        return -ENODEV;
    }
    file->private_data = dev;
    pr_info("membuf: open device\n");
    return 0;
}

static int membuf_release(struct inode *inode, struct file *file) {
    struct membuf_dev *dev = file->private_data;
    atomic_dec(&dev->open_count);
    module_put(THIS_MODULE);
    pr_info("membuf: release device\n");
    return 0;
}

static ssize_t membuf_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    pr_info("membuf: read %zu bytes from offset %lld\n", count, *ppos);

    struct membuf_dev *dev = file->private_data;
    size_t available;
    ssize_t ret;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    if (*ppos >= dev->size) {
        mutex_unlock(&dev->lock);
        return 0;
    }

    available = min(count, dev->size - (size_t)*ppos);
    if (copy_to_user(buf, dev->buffer + *ppos, available)) {
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }

    *ppos += available;
    ret = available;

    mutex_unlock(&dev->lock);
    return ret;
}

static ssize_t membuf_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    pr_info("membuf: write %zu bytes at offset %lld\n", count, *ppos);

    struct membuf_dev *dev = file->private_data;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    if (*ppos >= dev->size) {
        mutex_unlock(&dev->lock);
        return 0;
    }

    size_t writable = min(count, dev->size - (size_t)*ppos);
    if (copy_from_user(dev->buffer + *ppos, buf, writable)) {
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }

    *ppos += writable;

    mutex_unlock(&dev->lock);
    return writable;
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
        struct membuf_dev *dev = &membuf_devices[i];

        dev->buffer = kzalloc(default_buf_size, GFP_KERNEL);
        if (!dev->buffer) {
            pr_err("membuf: failed to allocate buffer for device %d\n", i);
            ret = -ENOMEM;
            goto err_remove_cdevs;
        }
        dev->size = default_buf_size;
        mutex_init(&dev->lock);
        atomic_set(&dev->open_count, 0);

        cdev_init(&dev->cdev, &membuf_fops);
        dev->cdev.owner = THIS_MODULE;

        ret = cdev_add(&dev->cdev, devt, 1);
        if (ret < 0) {
            pr_err("membuf: failed to add cdev for device %d\n", i);
            kfree(dev->buffer);
            goto err_remove_cdevs;
        }

        if (IS_ERR(device_create(membuf_class, NULL, devt, NULL, "membuf%d", i))) {
            pr_err("membuf: failed to create device node membuf%d\n", i);
            cdev_del(&dev->cdev);
            kfree(dev->buffer);
            ret = -ENOMEM;
            goto err_remove_cdevs;
        }
    }

    pr_info("membuf: successfully created %d devices\n", num_devices);
    return 0;

err_remove_cdevs:
    while (i--) {
        dev_t devt = MKDEV(MAJOR(membuf_dev_num), i);
        struct membuf_dev *dev = &membuf_devices[i];
        device_destroy(membuf_class, devt);
        cdev_del(&dev->cdev);
        kfree(dev->buffer);
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
        struct membuf_dev *dev = &membuf_devices[i];
        device_destroy(membuf_class, devt);
        cdev_del(&dev->cdev);
        mutex_destroy(&dev->lock);
        kfree(dev->buffer);
    }

    class_destroy(membuf_class);
    unregister_chrdev_region(membuf_dev_num, num_devices);
    kfree(membuf_devices);
}

module_init(membuf_init);
module_exit(membuf_exit);
