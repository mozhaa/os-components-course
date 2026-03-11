#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/wait.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_DESCRIPTION("kpipe");
MODULE_VERSION("0.1");

#define DEVICE_NAME "kpipe"
#define CLASS_NAME "kpipe"

static int major;
static unsigned long capacity = 4096;
static struct class *kpipe_class = NULL;
static struct device *kpipe_device = NULL;
static char *buffer;
static int cursor = 0;
static int cur_size = 0;

static DEFINE_MUTEX(kpipe_mutex);
static DECLARE_WAIT_QUEUE_HEAD(read_wait);
static DECLARE_WAIT_QUEUE_HEAD(write_wait);

static ssize_t kpipe_read(struct file *file, char __user *buf, size_t size, loff_t *ppos) {
    mutex_lock(&kpipe_mutex);

    while (cur_size == 0) {
        if (file->f_flags & O_NONBLOCK) {
            mutex_unlock(&kpipe_mutex);
            return -EAGAIN;
        }
        mutex_unlock(&kpipe_mutex);
        if (wait_event_interruptible(read_wait, cur_size > 0)) {
            return -ERESTARTSYS;
        }
        mutex_lock(&kpipe_mutex);
    }

    size = (size < cur_size) ? size : cur_size;
    if (size == 0) {
        return 0;
    }

    int read_cursor = (cursor + capacity - cur_size) % capacity;
    int l_size = (size < (capacity - read_cursor)) ? size : (capacity - read_cursor);
    int r_size = size - l_size;

    if (l_size > 0) {
        if (copy_to_user(buf, buffer + read_cursor, l_size)) {
            return -EFAULT;
        }
    }
    if (r_size > 0) {
        if (copy_to_user(buf + l_size, buffer, r_size)) {
            return -EFAULT;
        }
    }

    cur_size -= size;

    wake_up(&write_wait);
    mutex_unlock(&kpipe_mutex);
    return size;
}

static ssize_t kpipe_write(struct file *file, const char __user *data, size_t size, loff_t *ppos) {
    ssize_t total = 0;
    mutex_lock(&kpipe_mutex);

    while (total < size) {
        int available = capacity - cur_size;
        if (available == 0) {
            if (file->f_flags & O_NONBLOCK) {
                if (total == 0) {
                    mutex_unlock(&kpipe_mutex);
                    return -EAGAIN;
                }
                break;
            }
            mutex_unlock(&kpipe_mutex);
            if (wait_event_interruptible(write_wait, cur_size < capacity)) {
                if (total == 0) {
                    return -ERESTARTSYS;
                } else {
                    return total;
                }
            }
            mutex_lock(&kpipe_mutex);
            continue;
        }

        int chunk = (available < (size - total)) ? available : (size - total);
        int l_size = (chunk < (capacity - cursor)) ? chunk : (capacity - cursor);
        int r_size = chunk - l_size;

        if (l_size > 0) {
            if (copy_from_user(buffer + cursor, data + total, l_size)) {
                mutex_unlock(&kpipe_mutex);
                return -EFAULT;
            }
            cursor = (cursor + l_size) % capacity;
        }
        if (r_size > 0) {
            if (copy_from_user(buffer + cursor, data + total + l_size, r_size)) {
                mutex_unlock(&kpipe_mutex);
                return -EFAULT;
            }
            cursor = (cursor + r_size) % capacity;
        }

        cur_size += chunk;
        total += chunk;

        wake_up(&read_wait);
    }

    mutex_unlock(&kpipe_mutex);
    wake_up(&read_wait);
    return total;
}

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
        goto fail_chrdev;
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

    buffer = kzalloc(capacity, GFP_KERNEL);
    if (!buffer) {
        ret = -ENOMEM;
        goto fail_buffer;
    }

    return 0;

fail_buffer:
    device_destroy(kpipe_class, MKDEV(major, 0));
fail_device:
    class_destroy(kpipe_class);
fail_class:
    unregister_chrdev(major, DEVICE_NAME);
fail_chrdev:
    return ret;
}

static void __exit kpipe_end(void) {
    kfree(buffer);
    device_destroy(kpipe_class, MKDEV(major, 0));
    class_destroy(kpipe_class);
    unregister_chrdev(major, DEVICE_NAME);
}

module_param(capacity, ulong, 0644);
MODULE_PARM_DESC(capacity, "buffer size");

module_init(kpipe_start);
module_exit(kpipe_end);
