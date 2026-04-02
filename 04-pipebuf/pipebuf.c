#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/wait.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_DESCRIPTION("pipebuf");
MODULE_VERSION("0.1");

#define DEVICE_NAME "pipebuf"
#define CLASS_NAME "pipebuf"

static int major;
static unsigned long capacity = 4096;
static struct class *pipebuf_class = NULL;
static struct device *pipebuf_device = NULL;
static char *buffer;
static int cursor = 0;
static int cur_size = 0;

static DEFINE_MUTEX(pipebuf_mutex);
static DECLARE_WAIT_QUEUE_HEAD(read_wait);
static DECLARE_WAIT_QUEUE_HEAD(write_wait);

static int n_readers = 0;
static int n_writers = 0;

static int pipebuf_open(struct inode *inode, struct file *filp) {
    mutex_lock(&pipebuf_mutex);

    if (filp->f_mode & FMODE_READ) {
        if (n_readers) {
            mutex_unlock(&pipebuf_mutex);
            return -EBUSY;
        }
        ++n_readers;
    }
    if (filp->f_mode & FMODE_WRITE) {
        ++n_writers;
    }

    mutex_unlock(&pipebuf_mutex);
    return 0;
}

static int pipebuf_release(struct inode *inode, struct file *filp) {
    mutex_lock(&pipebuf_mutex);

    if (filp->f_mode & FMODE_READ) {
        --n_readers;
    }
    if (filp->f_mode & FMODE_WRITE) {
        --n_writers;
        if (n_writers == 0) {
            wake_up(&read_wait);
        }
    }

    mutex_unlock(&pipebuf_mutex);
    return 0;
}

static ssize_t pipebuf_read(struct file *file, char __user *buf, size_t size, loff_t *ppos) {
    mutex_lock(&pipebuf_mutex);

    while (cur_size == 0) {
        if (n_writers == 0) {
            mutex_unlock(&pipebuf_mutex);
            return 0;
        }
        if (file->f_flags & O_NONBLOCK) {
            mutex_unlock(&pipebuf_mutex);
            return -EAGAIN;
        }
        mutex_unlock(&pipebuf_mutex);
        if (wait_event_interruptible(read_wait, cur_size > 0 || n_writers == 0)) {
            return -ERESTARTSYS;
        }
        mutex_lock(&pipebuf_mutex);
    }

    size = (size < cur_size) ? size : cur_size;
    if (size == 0) {
        mutex_unlock(&pipebuf_mutex);
        return 0;
    }

    int read_cursor = (cursor + capacity - cur_size) % capacity;
    int l_size = (size < (capacity - read_cursor)) ? size : (capacity - read_cursor);
    int r_size = size - l_size;

    if (l_size > 0) {
        if (copy_to_user(buf, buffer + read_cursor, l_size)) {
            mutex_unlock(&pipebuf_mutex);
            return -EFAULT;
        }
    }
    if (r_size > 0) {
        if (copy_to_user(buf + l_size, buffer, r_size)) {
            mutex_unlock(&pipebuf_mutex);
            return -EFAULT;
        }
    }

    cur_size -= size;

    wake_up(&write_wait);
    mutex_unlock(&pipebuf_mutex);
    return size;
}

static ssize_t pipebuf_write(struct file *file, const char __user *data, size_t size, loff_t *ppos) {
    ssize_t total = 0;
    mutex_lock(&pipebuf_mutex);

    while (total < size) {
        int available = capacity - cur_size;
        if (available == 0) {
            if (file->f_flags & O_NONBLOCK) {
                if (total == 0) {
                    mutex_unlock(&pipebuf_mutex);
                    return -EAGAIN;
                }
                break;
            }
            mutex_unlock(&pipebuf_mutex);
            if (wait_event_interruptible(write_wait, cur_size < capacity)) {
                if (total == 0) {
                    return -ERESTARTSYS;
                } else {
                    return total;
                }
            }
            mutex_lock(&pipebuf_mutex);
            continue;
        }

        int chunk = (available < (size - total)) ? available : (size - total);
        int l_size = (chunk < (capacity - cursor)) ? chunk : (capacity - cursor);
        int r_size = chunk - l_size;

        if (l_size > 0) {
            if (copy_from_user(buffer + cursor, data + total, l_size)) {
                mutex_unlock(&pipebuf_mutex);
                return -EFAULT;
            }
            cursor = (cursor + l_size) % capacity;
        }
        if (r_size > 0) {
            if (copy_from_user(buffer + cursor, data + total + l_size, r_size)) {
                mutex_unlock(&pipebuf_mutex);
                return -EFAULT;
            }
            cursor = (cursor + r_size) % capacity;
        }

        cur_size += chunk;
        total += chunk;

        wake_up(&read_wait);
    }

    mutex_unlock(&pipebuf_mutex);
    return total;
}

static char *pipebuf_devnode(const struct device *dev, umode_t *mode) {
    if (mode) {
        *mode = 0666;
    }
    return NULL;
}

static struct file_operations pipebuf_fops = {
    .owner = THIS_MODULE,
    .open = pipebuf_open,
    .release = pipebuf_release,
    .read = pipebuf_read,
    .write = pipebuf_write,
};

static int __init pipebuf_start(void) {
    int ret;

    major = register_chrdev(0, DEVICE_NAME, &pipebuf_fops);
    if (major < 0) {
        ret = major;
        pr_err("pipebuf: failed to register device: %d\n", ret);
        goto fail_chrdev;
    }

    pipebuf_class = class_create(CLASS_NAME);
    if (IS_ERR(pipebuf_class)) {
        ret = PTR_ERR(pipebuf_class);
        pr_err("pipebuf: failed to create class: %d\n", ret);
        goto fail_class;
    }

    pipebuf_class->devnode = pipebuf_devnode;

    pipebuf_device = device_create(pipebuf_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(pipebuf_device)) {
        ret = PTR_ERR(pipebuf_device);
        pr_err("pipebuf: failed to create device: %d\n", ret);
        goto fail_device;
    }

    buffer = kzalloc(capacity, GFP_KERNEL);
    if (!buffer) {
        ret = -ENOMEM;
        goto fail_buffer;
    }

    return 0;

fail_buffer:
    device_destroy(pipebuf_class, MKDEV(major, 0));
fail_device:
    class_destroy(pipebuf_class);
fail_class:
    unregister_chrdev(major, DEVICE_NAME);
fail_chrdev:
    return ret;
}

static void __exit pipebuf_end(void) {
    kfree(buffer);
    device_destroy(pipebuf_class, MKDEV(major, 0));
    class_destroy(pipebuf_class);
    unregister_chrdev(major, DEVICE_NAME);
}

module_param(capacity, ulong, 0644);
MODULE_PARM_DESC(capacity, "buffer size");

module_init(pipebuf_start);
module_exit(pipebuf_end);
