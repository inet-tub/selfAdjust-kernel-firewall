//
// Created by Jonas Köppeler on 07.12.21.
// Kernel Module to test the self_adjusting_list data structure in kernel space
#include <linux/init.h>
#include <linux/module.h>
#include "self_adjusting_list.h"

MODULE_LICENSE("GPL");

static int __init sal_test_init(void) {
    printk(KERN_INFO "Starting SAL Test\n");
    return 0;
}

static void __exit sal_test_exit(void) {
    printk(KERN_INFO "Removing sal test module\n");
}

module_init(sal_test_init);
module_exit(sal_test_exit);

