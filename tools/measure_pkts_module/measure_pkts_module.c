#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#define NUM_DEVICES 1
#define BUF_SIZE 64

static int minor = 1;
static int major = 0;
static struct cdev *ctl_cdev;
static struct class *ctl_class;

static struct nf_hook_ops nfho_prerouting_chain;
unsigned int recv_pkts;

unsigned int pr_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    recv_pkts++;
    return NF_ACCEPT;
}


static int ctl_dev_open(struct inode *in, struct file *filp)
{
//    printk(KERN_ALERT "mydev open\n");
    return 0;
}

static int ctl_dev_close(struct inode *in, struct file *filp)
{
  //  printk(KERN_ALERT "mydev close\n");
    return 0;
}

static ssize_t read_pkts(struct file *filp, char __user *user_buf, size_t count, loff_t *f_pos)
{
    char buf[BUF_SIZE];
    int i = 0;
    if(BUF_SIZE - *f_pos <= 0)
        return 0;

    for(;i<BUF_SIZE;++i){
        buf[i] = 0;
    }
    snprintf(buf,BUF_SIZE,"%u\n",recv_pkts);
    if(copy_to_user(user_buf,buf,BUF_SIZE))
        return -EFAULT;
    *f_pos += BUF_SIZE;
    return BUF_SIZE;
}

static ssize_t reset(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    printk("Reset\n");
    recv_pkts = 0;
    return count;
}

static struct file_operations ctl_dev_ops = {
        .owner = THIS_MODULE,
        .read = read_pkts,
        .write = reset,
        .llseek = NULL,
        .open = ctl_dev_open,
        .release = ctl_dev_close,
};

// to set permissions in /dev/
static int ctl_class_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    add_uevent_var(env, "DEVMODE=%#o", 0666);
    return 0;
}

static int __init init_measure_pkts(void){
    struct net *n;
    dev_t dev;
    int ret;
    static struct device *ldev;
    ret = 0;
    recv_pkts=0;
    printk("Register measure pkts module\n");
    nfho_prerouting_chain.hook = pr_hook_func;
    nfho_prerouting_chain.hooknum = NF_INET_PRE_ROUTING;
    nfho_prerouting_chain.pf = PF_INET;
    nfho_prerouting_chain.priority = NF_IP_PRI_LAST;
    for_each_net(n)
    {
        ret += nf_register_net_hook(n, &nfho_prerouting_chain);
    }
    if(ret != 0)
        return ret;

    ret = alloc_chrdev_region(&dev, minor, NUM_DEVICES, "measure_pkts_dev");
    major = MAJOR(dev);
    if(ret < 0){
        goto unregister;
    }

    ctl_class = class_create(THIS_MODULE, "measure_pkts_dev");
    if(IS_ERR(ctl_class)){
        printk("Error class\n");
        goto err_class;
    }
    ctl_class->dev_uevent = ctl_class_uevent;

    printk(KERN_WARNING "mydev: call cdev_init\n");
    ctl_cdev = kmalloc(sizeof(struct cdev), GFP_KERNEL);
    cdev_init(ctl_cdev, &ctl_dev_ops);
    ctl_cdev->owner = THIS_MODULE;
    ret = cdev_add(ctl_cdev, dev, 1);

    if(ret){
        printk(KERN_NOTICE "Error %d adding mydev\n", ret);
        goto err_chardev;
    }

    ldev = device_create(ctl_class, NULL, dev, NULL, "measure_pkts_%d", 0);
    if(IS_ERR(ldev)){
        printk("Err dev\n");
        goto err_dev;
    }

    return ret;
    err_dev:
    cdev_del(ctl_cdev);
    err_chardev:
    class_destroy(ctl_class);
    err_class:
    unregister_chrdev_region(MKDEV(major,minor), NUM_DEVICES);
    unregister:
    for_each_net(n){
        nf_unregister_net_hook(n,&nfho_prerouting_chain);
    }
    return ret;

}

static void __exit exit_measure_pkts(void ){
    struct net *n;
    dev_t dev = MKDEV(major, minor);
    printk("Unregister measure pkts module\n");
    printk("Received %u pkts \n", recv_pkts);
    for_each_net(n){
        nf_unregister_net_hook(n,&nfho_prerouting_chain);

    }
    unregister_chrdev_region(dev, NUM_DEVICES);
    device_destroy(ctl_class, dev);
    cdev_del(ctl_cdev);
    class_destroy(ctl_class);
    kfree(ctl_cdev);
    printk(KERN_ALERT "mydev released\n");
}

module_init(init_measure_pkts);
module_exit(exit_measure_pkts);
MODULE_LICENSE("GPL");
