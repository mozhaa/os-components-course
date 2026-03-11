#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

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

static int __init membuf_init(void) {
    pr_info("membuf: loading module\n");
    pr_info("membuf: num_devices = %d\n", num_devices);
    pr_info("membuf: default_buf_size = %d\n", default_buf_size);
    return 0;
}

static void __exit membuf_exit(void) { pr_info("membuf: unloading module\n"); }

module_init(membuf_init);
module_exit(membuf_exit);
