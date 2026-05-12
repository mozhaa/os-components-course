#include <linux/input.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_DESCRIPTION("vkbd");
MODULE_VERSION("0.1");

static struct input_dev *vkbd_dev;

static void press_key(int code) {
    input_report_key(vkbd_dev, code, 1);
    input_report_key(vkbd_dev, code, 0);
}

static int __init vkbd_init(void) {
    vkbd_dev = input_allocate_device();
    if (!vkbd_dev)
        return -ENOMEM;

    vkbd_dev->name = "vkbd";
    vkbd_dev->id.bustype = BUS_VIRTUAL;
    vkbd_dev->id.vendor = 0xdead;
    vkbd_dev->id.product = 0xcafe;

    set_bit(EV_KEY, vkbd_dev->evbit);
    set_bit(KEY_S, vkbd_dev->keybit);
    set_bit(KEY_U, vkbd_dev->keybit);
    set_bit(KEY_D, vkbd_dev->keybit);
    set_bit(KEY_O, vkbd_dev->keybit);
    set_bit(KEY_SPACE, vkbd_dev->keybit);
    set_bit(KEY_P, vkbd_dev->keybit);
    set_bit(KEY_W, vkbd_dev->keybit);
    set_bit(KEY_E, vkbd_dev->keybit);
    set_bit(KEY_R, vkbd_dev->keybit);
    set_bit(KEY_F, vkbd_dev->keybit);
    set_bit(KEY_ENTER, vkbd_dev->keybit);

    int err = input_register_device(vkbd_dev);
    if (err) {
        input_free_device(vkbd_dev);
        return err;
    }

    press_key(KEY_S);
    press_key(KEY_U);
    press_key(KEY_D);
    press_key(KEY_O);
    press_key(KEY_SPACE);
    press_key(KEY_P);
    press_key(KEY_O);
    press_key(KEY_W);
    press_key(KEY_E);
    press_key(KEY_R);
    press_key(KEY_O);
    press_key(KEY_F);
    press_key(KEY_F);
    press_key(KEY_ENTER);
    input_sync(vkbd_dev);

    return 0;
}

static void __exit vkbd_exit(void) {
    input_unregister_device(vkbd_dev);
}

module_init(vkbd_init);
module_exit(vkbd_exit);
