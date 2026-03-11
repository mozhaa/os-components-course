#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_DESCRIPTION("Memory buffers with fixed sizes");
MODULE_VERSION("0.1");

#define MAX_DEVICES 8

static int num_devices = 1;
static int default_buf_size = 4096;

static struct class *membuf_class = NULL;
static dev_t membuf_dev_num;
static struct membuf_dev {
    struct cdev cdev;
    char *buffer;
    size_t size;
    struct rw_semaphore lock;
    atomic_t open_count;
    bool dying;
} *membuf_devices[MAX_DEVICES];
static int dev_count;
static DEFINE_MUTEX(list_lock);

static int create_membuf_device(int minor);
static void destroy_membuf_device(int minor);

static int set_num_devices(const char *val, const struct kernel_param *kp) {
    int new_count;
    int ret = kstrtoint(val, 0, &new_count);
    if (ret) {
        return ret;
    }
    if (new_count < 0 || new_count > MAX_DEVICES) {
        return -EINVAL;
    }

    mutex_lock(&list_lock);

    if (new_count == dev_count) {
        mutex_unlock(&list_lock);
        return 0;
    }

    if (new_count > dev_count) {
        for (int i = dev_count; i < new_count; i++) {
            ret = create_membuf_device(i);
            if (ret < 0) {
                pr_err("membuf: failed to create device %d\n", i);
                goto expand_fail;
            }
        }
        dev_count = new_count;
        *(int *)kp->arg = new_count;
        mutex_unlock(&list_lock);
        return 0;

    expand_fail:
        for (int i = new_count - 1; i >= dev_count; i--) {
            destroy_membuf_device(i);
        }
        mutex_unlock(&list_lock);
        return ret;
    }

    // if (new_count < dev_count)
    {
        for (int i = new_count; i < dev_count; i++) {
            struct membuf_dev *dev = membuf_devices[i];
            if (dev && atomic_read(&dev->open_count) > 0) {
                mutex_unlock(&list_lock);
                return -EBUSY;
            }
        }

        for (int i = new_count; i < dev_count; i++) {
            if (membuf_devices[i])
                membuf_devices[i]->dying = true;
        }

        for (int i = new_count; i < dev_count; i++) {
            destroy_membuf_device(i);
        }

        dev_count = new_count;
        *(int *)kp->arg = new_count;
        mutex_unlock(&list_lock);

        return 0;
    }
}

static struct kernel_param_ops num_devices_ops = {
    .set = set_num_devices,
    .get = param_get_int,
};

module_param_cb(num_devices, &num_devices_ops, &num_devices, 0644);
MODULE_PARM_DESC(num_devices, "number of membuf devices");

module_param(default_buf_size, int, 0644);
MODULE_PARM_DESC(default_buf_size, "default buffer size");

static ssize_t size_show(struct device *dev, struct device_attribute *attr, char *buf) {
    struct membuf_dev *mdev = dev_get_drvdata(dev);
    if (down_read_interruptible(&mdev->lock)) {
        return -ERESTARTSYS;
    }
    ssize_t ret = sprintf(buf, "%zu\n", mdev->size);
    up_read(&mdev->lock);
    return ret;
}

static ssize_t size_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    struct membuf_dev *mdev = dev_get_drvdata(dev);

    unsigned long new_size;
    int ret = kstrtoul(buf, 0, &new_size);
    if (ret) {
        return ret;
    }
    if (new_size == 0) {
        return -EINVAL;
    }

    if (down_write_killable(&mdev->lock)) {
        return -ERESTARTSYS;
    }

    if (atomic_read(&mdev->open_count) > 0) {
        up_write(&mdev->lock);
        return -EBUSY;
    }

    char *new_buf = kzalloc(new_size, GFP_KERNEL);
    if (!new_buf) {
        up_write(&mdev->lock);
        return -ENOMEM;
    }

    size_t copy_len = min(mdev->size, (size_t)new_size);
    memcpy(new_buf, mdev->buffer, copy_len);

    kfree(mdev->buffer);
    mdev->buffer = new_buf;
    mdev->size = new_size;

    up_write(&mdev->lock);
    return count;
}

static DEVICE_ATTR(size, 0644, size_show, size_store);

static int membuf_open(struct inode *inode, struct file *file) {
    struct membuf_dev *dev = container_of(inode->i_cdev, struct membuf_dev, cdev);
    mutex_lock(&list_lock);
    if (dev->dying) {
        mutex_unlock(&list_lock);
        return -ENXIO;
    }
    atomic_inc(&dev->open_count);
    mutex_unlock(&list_lock);
    file->private_data = dev;
    pr_info("membuf: open device\n");
    return 0;
}

static int membuf_release(struct inode *inode, struct file *file) {
    struct membuf_dev *dev = file->private_data;
    atomic_dec(&dev->open_count);
    pr_info("membuf: release device\n");
    return 0;
}

static ssize_t membuf_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    pr_info("membuf: read %zu bytes from offset %lld\n", count, *ppos);

    struct membuf_dev *dev = file->private_data;
    size_t available;
    ssize_t ret;

    if (down_read_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    if (*ppos >= dev->size) {
        up_read(&dev->lock);
        return 0;
    }

    available = min(count, dev->size - (size_t)*ppos);
    if (copy_to_user(buf, dev->buffer + *ppos, available)) {
        up_read(&dev->lock);
        return -EFAULT;
    }

    *ppos += available;
    ret = available;

    up_read(&dev->lock);
    return ret;
}

static ssize_t membuf_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    pr_info("membuf: write %zu bytes at offset %lld\n", count, *ppos);

    struct membuf_dev *dev = file->private_data;

    if (down_write_killable(&dev->lock)) {
        return -ERESTARTSYS;
    }

    if (*ppos >= dev->size) {
        up_write(&dev->lock);
        return count ? -ENOSPC : 0;
    }

    size_t writable = min(count, dev->size - (size_t)*ppos);
    if (copy_from_user(dev->buffer + *ppos, buf, writable)) {
        up_write(&dev->lock);
        return -EFAULT;
    }

    *ppos += writable;

    up_write(&dev->lock);
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

    if (num_devices <= 0 || num_devices > MAX_DEVICES) {
        pr_err("membuf: num_devices must be between 1 and %d\n", MAX_DEVICES);
        return -EINVAL;
    }
    if (default_buf_size <= 0) {
        pr_err("membuf: default_buf_size must be positive\n");
        return -EINVAL;
    }

    int ret = alloc_chrdev_region(&membuf_dev_num, 0, MAX_DEVICES, "membuf");
    if (ret < 0) {
        pr_err("membuf: failed to allocate chrdev region\n");
        return ret;
    }

    membuf_class = class_create("membuf");
    if (IS_ERR(membuf_class)) {
        ret = PTR_ERR(membuf_class);
        pr_err("membuf: failed to create class\n");
        goto err_unregister_region;
    }

    int i;
    for (i = 0; i < num_devices; i++) {
        ret = create_membuf_device(i);
        if (ret < 0) {
            pr_err("membuf: failed to create device %d\n", i);
            goto err_remove_cdevs;
        }
    }

    dev_count = num_devices;
    pr_info("membuf: successfully created %d devices\n", num_devices);
    return 0;

err_remove_cdevs:
    while (i--) {
        destroy_membuf_device(i);
    }
    class_destroy(membuf_class);
err_unregister_region:
    unregister_chrdev_region(membuf_dev_num, MAX_DEVICES);
    return ret;
}

static void __exit membuf_exit(void) {
    pr_info("membuf: unloading module\n");

    for (int i = 0; i < MAX_DEVICES; i++) {
        destroy_membuf_device(i);
    }

    class_destroy(membuf_class);
    unregister_chrdev_region(membuf_dev_num, MAX_DEVICES);
}

static int create_membuf_device(int minor) {
    dev_t devt = MKDEV(MAJOR(membuf_dev_num), minor);
    struct membuf_dev *dev = kzalloc(sizeof(struct membuf_dev), GFP_KERNEL);
    if (!dev) {
        return -ENOMEM;
    }

    dev->buffer = kzalloc(default_buf_size, GFP_KERNEL);
    if (!dev->buffer) {
        kfree(dev);
        return -ENOMEM;
    }
    dev->size = default_buf_size;
    init_rwsem(&dev->lock);
    atomic_set(&dev->open_count, 0);
    dev->dying = false;

    cdev_init(&dev->cdev, &membuf_fops);
    dev->cdev.owner = THIS_MODULE;

    int ret = cdev_add(&dev->cdev, devt, 1);
    if (ret < 0) {
        goto err_free_buffer;
    }

    struct device *class_dev = device_create(membuf_class, NULL, devt, dev, "membuf%d", minor);
    if (IS_ERR(class_dev)) {
        ret = PTR_ERR(class_dev);
        goto err_cdev_del;
    }

    ret = device_create_file(class_dev, &dev_attr_size);
    if (ret < 0) {
        device_destroy(membuf_class, devt);
        goto err_cdev_del;
    }

    membuf_devices[minor] = dev;
    return 0;

err_cdev_del:
    cdev_del(&dev->cdev);
err_free_buffer:
    kfree(dev->buffer);
    kfree(dev);
    return ret;
}

static void destroy_membuf_device(int minor) {
    struct membuf_dev *dev = membuf_devices[minor];
    if (!dev) {
        return;
    }

    dev_t devt = MKDEV(MAJOR(membuf_dev_num), minor);
    device_destroy(membuf_class, devt);
    cdev_del(&dev->cdev);
    kfree(dev->buffer);
    kfree(dev);
    membuf_devices[minor] = NULL;
}

module_init(membuf_init);
module_exit(membuf_exit);
