//
// Created by Jonas Köppeler on 07.12.21.
// Kernel Module to test the self_adjusting_list data structure in kernel space
#include <linux/init.h>
#include <linux/module.h>
#include "self_adjusting_list.h"

MODULE_LICENSE("GPL");

struct my_struct {
    int priority;
    int src_port;
    int dst_port;
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
bool depends(struct sal_head *prev, struct sal_head*rule){
    struct my_struct *first= container_of(prev, struct my_struct, list);
    struct my_struct *second = container_of(rule, struct my_struct, list);
    int overlap = 0;

    if(first->src_port == second->src_port || first->dst_port == second->dst_port)
        overlap = 1;

    if(overlap && first->priority > second->priority)
        return 1;
    else
        return 0;

}

void print_list(struct sal_access *head) {
    struct my_struct *entry;
    struct sal_dependency_node *tmp_dep;
    sal_for_each_entry(entry, head, list){
        printk(KERN_INFO "prio: %d, src_port %d dst_port %d\n", entry->priority, entry->src_port, entry->dst_port);
        sal_for_each_dep_entry(tmp_dep, entry, list)
        {
            printk(KERN_INFO"\t\tdep to %d\n", SAL_ENTRY(tmp_dep->dep, struct my_struct, list)->priority);
        }
    }
    printk(KERN_INFO "----------------------------------------------------------------------------");
}

static int sal_test_init(void) {
    struct my_struct a;
    struct my_struct b;
    struct my_struct c;
    struct my_struct d;
    struct my_struct e;

    SAL_ACCESS(my_list, &depends);
    printk(KERN_INFO "Starting SAL with storage test\n");
    a.priority = 10;
    a.src_port = 5000;
    a.dst_port = 443;

    b.priority = 9;
    b.src_port = 4500;
    b.dst_port = 80;

    c.priority = 8;
    c.src_port = 4300;
    c.dst_port = 443;

    d.priority = 7;
    d.src_port = 4500;
    d.dst_port = 80;

    e.priority = 6;
    e.src_port = 8080;
    e.dst_port = 22;

    SAL_HEAD_INIT(&a, list);
    SAL_HEAD_INIT(&b, list);
    SAL_HEAD_INIT(&c, list);
    SAL_HEAD_INIT(&d,list);
    SAL_HEAD_INIT(&e,list);

    sal_add_last(&my_list, &a.list);
    sal_add_last(&my_list, &b.list);
    sal_add_last(&my_list, &c.list);
    sal_add_last(&my_list, &d.list);
    sal_add_last(&my_list, &e.list);

    print_list(&my_list);

    sal_access_entry(&e.list, &my_list);
    printk("Accessing prio: %d\n", e.priority);
    print_list(&my_list);


    sal_access_entry(&c.list, &my_list);
    printk("Accessing prio: %d\n", c.priority);
    print_list(&my_list);

    sal_access_entry(&d.list, &my_list);
    printk("Accessing prio: %d\n", d.priority);
    printk("Accessing d\n");
    print_list(&my_list);


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

