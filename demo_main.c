#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "klookuper/lookuper.h"

static int demo_open(struct inode *inode, struct file *filp)
{
    return 0;
}

/* for test only now */
static ssize_t demo_write(struct file *filp,
                            const char __user *ubuf,
                            size_t count,
                            loff_t *pos)
{
    size_t addr;
    char *kbuf;
    ssize_t ret = 0;

    if (count >= PAGE_SIZE) {
        count = 0xFFF;
    }

    kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!kbuf) {
        ret = -ENOMEM;
        goto out_ret;
    }

    if (copy_from_user(kbuf, ubuf, count)) {
        ret = -EFAULT;
        goto out_free_buf;
    }

    if (kbuf[count - 1] == '\n') {
        kbuf[count - 1] = '\0';
    }

    kbuf[count] = '\0';
    printk(KERN_INFO "[demo:] Trying to seek for symbol [%s]\n", kbuf);

    ret = kallsyms_addr_lookup(kbuf, &addr, NULL, NULL);
    if (!ret) {
        printk(KERN_INFO"[demo:] Got address of symbol[%s]: %lx\n", kbuf, addr);
        ret = count;
    } else {
        printk(KERN_ERR
              "[demo:] Failed to get specific kernel symbol, error code: %ld\n",
              ret);
    }

out_free_buf:
    kfree(kbuf);
out_ret:
    return ret;
}

static int demo_release(struct inode *inode, struct file *file)
{
    return 0;
}

static const struct proc_ops demo_ops = {
    .proc_open      = demo_open,
    .proc_write     = demo_write,
    .proc_release   = demo_release,
};

static int __init demo_init(void)
{
    printk(KERN_INFO "[demo:] Hello to kernel space!\n");

    proc_create("demo", 0666, NULL, &demo_ops);

    return 0;
}

static void __exit demo_exit(void)
{
    printk(KERN_INFO "[demo:] Goodbye to kernel space!\n");
    remove_proc_entry("demo", NULL);
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("arttnba3");
