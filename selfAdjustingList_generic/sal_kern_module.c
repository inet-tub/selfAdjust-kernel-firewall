//
// Created by Jonas Köppeler on 07.12.21.
// Kernel Module to test the self_adjusting_list data structure in kernel space
#include <linux/init.h>
#include <linux/module.h>
#include "self_adjusting_list.h"

MODULE_LICENSE("GPL");

struct my_struct {
    int idx;
    struct sal_head list;
};

//always need container_of macro to get access to the struct.
//It's not nice, but I don't see better way of doing this.
//Another idea would be to work with void *. A fixed type is needed, because of the function pointer in the
// entry_point struct

//But also if I could manage to pass the custom struct type using macros down to the sal_check_dependencies function
// (which calls this function), still, a cast from "void *" to "struct custom_struct *" is needed, so either
// way I cannot
// get rid of the cast => so it seems to be still easier to do it with container_of
bool depends(struct sal_head *a, struct sal_head*b){
    struct my_struct *item_a = container_of(a, struct my_struct, list);
    struct my_struct *item_b = container_of(b, struct my_struct, list);
    if(item_a->idx < item_b->idx)
        return 1;
    else
        return 0;
}

static int sal_test_init(void) {
    struct my_struct a;
    struct my_struct b;
    struct my_struct c;
    struct my_struct d;
    struct my_struct *entry;
    struct sal_dependency_node *tmp_dep;

    SAL_ACCESS(my_list, &depends);
    printk(KERN_INFO "Starting SAL Test\n");

    a.idx = 1;
    SAL_HEAD_INIT(&a, list);

    b.idx = 2;
    SAL_HEAD_INIT(&b, list);

    c.idx = 3;
    SAL_HEAD_INIT(&c, list);

    d.idx = 4;
    SAL_HEAD_INIT(&d,list);

    sal_add_last(&my_list, &a.list);
    sal_add_last(&my_list, &b.list);
    sal_add_last(&my_list, &c.list);
    sal_add_last(&my_list, &d.list);

    sal_for_each_entry(entry, &my_list, list){
        printk(KERN_INFO "sal_head %p entry->idx:%d\n",&entry->list, entry->idx);
        sal_for_each_dep_entry(tmp_dep, entry, list){
            printk(KERN_INFO "\t%p : %d\n", tmp_dep->dep, SAL_ENTRY(tmp_dep->dep, struct my_struct, list)->idx);
        }
    }
    printk("b is dependent on prev node %d\n",sal_dependent_prev(&b.list));
    printk("a %p next %p, a prev %p\n",&a.list, a.list.next, a.list.prev);
    printk("b %p next %p, b prev %p\n",&b.list, b.list.next, b.list.prev);
    printk("c %p next %p, c prev %p\n",&c.list, c.list.next, c.list.prev);
    printk("d %p next %p, d prev %p\n",&d.list, d.list.next, d.list.prev);
    sal_for_each_entry(entry, &my_list, list){
        printk(KERN_INFO "sal_head %p entry->idx:%d\n",&entry->list, entry->idx);
    }
    printk("------");
    sal_access_entry(&d.list, &my_list);
    sal_for_each_entry(entry, &my_list, list){
        printk(KERN_INFO "sal_head %p entry->idx:%d\n",&entry->list, entry->idx);
    }
    //sal_swap_prev(&d.list);
    sal_access_entry(&a.list, &my_list);
    printk("------");

    sal_for_each_entry(entry, &my_list, list){
        printk(KERN_INFO "sal_head %p entry->idx:%d\n",&entry->list, entry->idx);
    }

    sal_access_entry(&c.list, &my_list);
    printk("------");

    sal_for_each_entry(entry, &my_list, list){
        printk(KERN_INFO "sal_head %p entry->idx:%d\n",&entry->list, entry->idx);
    }



    printk(KERN_INFO "End of SAL Tests! Cleanup!\n");
    sal_cleanup(&my_list);
    printk(KERN_INFO "SAL cleanup done!\n");
    return 0;
}

static void __exit sal_test_exit(void) {
    printk(KERN_INFO "Removing SAL test module\n");
}

module_init(sal_test_init);
module_exit(sal_test_exit);

