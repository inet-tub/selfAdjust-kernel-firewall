//
// Created by Jonas Köppeler on 21.01.22.
#include <linux/init.h>
#include <linux/module.h>
#include "list_mrf_extension.h"
MODULE_LICENSE("GPL");

struct my_struct {
    int priority;
    int src_port;
    int dst_port;
    struct list_head list;
};

//returns 1 if b is a dependency of a => a is not allowed to be in front of b
int depends(struct list_head *prev, struct list_head *rule){
    struct my_struct *first = list_entry(prev, struct my_struct, list);
    struct my_struct *second = list_entry(rule, struct my_struct, list);

    int overlap = 0;

    if(first->src_port == second->src_port || first->dst_port == second->dst_port){
        overlap = 1;
    }
    if(overlap && first->priority > second->priority)
        return 1;
    else
        return 0;

}

void print_list(struct list_head *head){
    struct my_struct *pos;
    list_for_each_entry(pos, head, list){
        printk(KERN_INFO "prio: %d, src_port %d, dst_port %d\n", pos->priority, pos->src_port, pos->dst_port);
    }
    printk(KERN_INFO "----------------------------------------------------------------------------");
}

static int sal_memless_init(void){
    struct my_struct a;
    struct my_struct b;
    struct my_struct c;
    struct my_struct d;
    struct my_struct e;
    LIST_HEAD(my_list);

    printk(KERN_INFO "Starting SAL memless test\n");

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
/*
    list_add_tail(&a.list, &my_list);
    list_add_tail(&b.list, &my_list);
    list_add_tail(&c.list, &my_list);
    list_add_tail(&d.list, &my_list);
    list_add_tail(&e.list, &my_list);
*/
    printk("%p %p %p %p\n", &a.list, &my_list, &depends, &list_sal_insert);
    list_sal_insert(&b.list, &my_list, &depends);
    print_list(&my_list);
    list_sal_insert(&c.list, &my_list, &depends);
    print_list(&my_list);
    list_sal_insert(&d.list, &my_list, &depends);
    print_list(&my_list);
    list_sal_insert(&e.list, &my_list, &depends);
    print_list(&my_list);
    list_sal_insert(&a.list, &my_list, &depends);
    print_list(&my_list);
    return 0;
    list_access(&e.list, &my_list, &depends);
    printk("Accessing prio: %d\n", e.priority);
    print_list(&my_list);

    list_access(&c.list, &my_list, &depends);
    printk("Accessing prio: %d\n", c.priority);
    print_list(&my_list);

    list_access(&d.list, &my_list, &depends);
    printk("Accessing prio: %d\n", d.priority);
    print_list(&my_list);

    printk(KERN_INFO "End of SAL memless test\n");

    return 0;
}

static void __exit sal_memless_exit(void){

}

module_init(sal_memless_init);
module_exit(sal_memless_exit);

//

