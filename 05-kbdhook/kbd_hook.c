#include <asm/io.h>
#include <linux/interrupt.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_DESCRIPTION("keyboard hook");
MODULE_VERSION("0.1");

#define IRQ_KBD 1
#define I8042_DATA 0x60
#define KEYBUF_SIZE 8
#define SCANCODE_RELEASED_MASK 0x80
#define PROC_FILENAME "kbd_hook"
#define MODULE_NAME "kbd_hook"

static unsigned int buffer_size = 64;
module_param(buffer_size, uint, 0644);

static struct event {
    unsigned int scancode;
    u64 ns;
} *events;

static int head, cnt;

static DEFINE_SPINLOCK(lock);
static struct proc_dir_entry *proc_entry;

static void get_key_name(unsigned int scancode, char *buf) {
    static const char *row1 = "1234567890";
    static const char *row2 = "qwertyuiop";
    static const char *row3 = "asdfghjkl";
    static const char *row4 = "zxcvbnm";

    if (scancode >= 0x02 && scancode <= 0x0b)
        *buf = *(row1 + scancode - 0x02);
    else if (scancode >= 0x10 && scancode <= 0x19)
        *buf = *(row2 + scancode - 0x10);
    else if (scancode >= 0x1e && scancode <= 0x26)
        *buf = *(row3 + scancode - 0x1e);
    else if (scancode >= 0x2c && scancode <= 0x32)
        *buf = *(row4 + scancode - 0x2c);
    else {
        if (scancode == 0x39)
            snprintf(buf, KEYBUF_SIZE, "SPACE");
        else if (scancode == 0x1c)
            snprintf(buf, KEYBUF_SIZE, "ENTER");
        else
            snprintf(buf, KEYBUF_SIZE, "0x%02x", scancode);
        return;
    }
    *(buf + 1) = 0;
    return;
}

static ssize_t kbd_hook_read(struct file *f, char __user *ubuf, size_t len, loff_t *off) {
    if (*off) {
        return 0;
    }

    unsigned long flags;
    spin_lock_irqsave(&lock, flags);
    if (!cnt) {
        spin_unlock_irqrestore(&lock, flags);
        return 0;
    }

    char *kbuf = kmalloc(cnt * 64, GFP_ATOMIC);
    if (!kbuf) {
        spin_unlock_irqrestore(&lock, flags);
        return -ENOMEM;
    }

    char keybuf[KEYBUF_SIZE];
    size_t klen = 0;
    for (int i = 0; i < cnt; i++) {
        struct event *e = &events[(head - cnt + i + buffer_size) % buffer_size];
        unsigned long s = e->ns / NSEC_PER_SEC;
        unsigned long ns = e->ns % NSEC_PER_SEC;
        get_key_name(e->scancode, keybuf);
        klen += snprintf(kbuf + klen, 64, "%s at %lu.%09lu\n", keybuf, s, ns);
    }
    spin_unlock_irqrestore(&lock, flags);

    if (klen > len) {
        klen = len;
    }

    if (copy_to_user(ubuf, kbuf, klen)) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    *off = klen;
    return klen;
}

static const struct proc_ops kbd_hook_pops = {.proc_read = kbd_hook_read};

static irqreturn_t kbd_hook_interrupt_handle(int irq_no, void *dev_id) {
    unsigned long flags;
    u8 sc = inb(I8042_DATA);
    if (!(sc & 0x80)) {
        u64 now = ktime_get_ns();
        spin_lock_irqsave(&lock, flags);
        events[head].scancode = sc;
        events[head].ns = now;
        head = (head + 1) % buffer_size;
        if (cnt < buffer_size) {
            ++cnt;
        }
        spin_unlock_irqrestore(&lock, flags);
    }
    return IRQ_HANDLED;
}

static int __init kbd_hook_init(void) {
    if (buffer_size == 0) {
        pr_err("kbd_hook: buffer_size can't be zero\n");
        return -EINVAL;
    }

    events = kmalloc_array(buffer_size, sizeof(struct event), GFP_KERNEL);
    if (!events) {
        return -ENOMEM;
    }

    if (request_irq(IRQ_KBD, kbd_hook_interrupt_handle, IRQF_SHARED, MODULE_NAME, events)) {
        kfree(events);
        return -EBUSY;
    }

    proc_entry = proc_create(PROC_FILENAME, 0444, NULL, &kbd_hook_pops);
    if (!proc_entry) {
        free_irq(IRQ_KBD, events);
        kfree(events);
        return -ENOMEM;
    }

    return 0;
}

static void __exit kbd_hook_exit(void) {
    if (proc_entry) {
        proc_remove(proc_entry);
    }
    free_irq(IRQ_KBD, events);
    kfree(events);
}

module_init(kbd_hook_init);
module_exit(kbd_hook_exit);
