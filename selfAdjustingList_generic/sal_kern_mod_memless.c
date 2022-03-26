//
// Created by Jonas Köppeler on 21.01.22.
#include <linux/init.h>
#include <linux/module.h>
#include <net/netfilter/nf_tables.h>
#include "list_mrf_extension.h"
MODULE_LICENSE("GPL");
#define SADDR 0
#define DADDR 1
#define SPORT 2
#define DPORT 3
#define PROTO 4

#define LOWDIM 0
#define HIGHDIM 1

#define TCP 0x6
#define UDP 0x11

struct rule_struct {
    struct nft_ra_info info;
    struct list_head list;
};

//returns 1 if matched has a dependency to prev => matched is not allowed to be in front of a
static int depends(struct list_head *prev, struct list_head *matched){
    struct nft_ra_info *prev_rule;
    struct nft_ra_info *r;
    int i;

    prev_rule = &container_of(prev, struct rule_struct, list)->info;
    r = &container_of(matched, struct rule_struct, list)->info;

    for(i = 0; i < 5; ++i){
        if(r->range[i][HIGHDIM] < prev_rule->range[i][LOWDIM] || r->range[i][LOWDIM] > prev_rule->range[i][HIGHDIM])
            return 0;
    }

    // a low number in the priority field is a high priority
    if(prev_rule->priority < r->priority){
        printk("Rule %llu is a dependecy of Rule %llu\n", (long long unsigned int)prev_rule->priority, (long long unsigned int)r->priority);
        //print_rule_info(&prev_rule->cmp_data);
        //print_rule_info(&r->cmp_data);
        return 1;
    }
    return 0;
}


void print_list(struct list_head *head){
    struct rule_struct *pos;
    list_for_each_entry(pos, head, list){
        printk(KERN_INFO "prio: %lld\n", pos->info.priority);
    }
    printk(KERN_INFO "----------------------------------------------------------------------------");
}

static int sal_memless_init(void){

    unsigned int swaps;
    struct rule_struct a;
    struct rule_struct b;
    struct rule_struct c;
    struct rule_struct d;
    struct rule_struct e;
    struct rule_struct f;
    struct rule_struct g;
    struct rule_struct h;

    //According to Fig.1 of the Paper "Self-Adjusting Packet Classification"
    //Proto     saddr       daddr         sport       dport     struct
    //TCP   10.12.12.0/24   20.0.0.1/32    ANY          80      a
    //TCP   0.0.0.0/0       20.0.0.1/32    ANY          80      b
    //IP    0.0.0.0/0       20.0.0.1/32                         c
    //UDP   0.0.0.0/0       0.0.0.0/0     1000-2000 1000-2000   d
    //UDP   20.0.0.0/24     10.0.10.0/24   ANY          3306    e
    //TCP   10.12.12.0/24   0.0.0.0/0       21          21      f
    //IP    10.0.0.0/16     20.0.0.0/20                         g
    //IP    0.0.0.0/0       0.0.0.0/0                           h
    a.info.range[SADDR][0] = 0x0A0C0C01;
    a.info.range[SADDR][1] = 0x0A0C0Cff;
    a.info.range[DADDR][0] = 0x14000001;
    a.info.range[DADDR][1] = 0x14000001;
    a.info.range[SPORT][0] = 0;
    a.info.range[SPORT][1] = 0xffff;
    a.info.range[DPORT][0] = 80;
    a.info.range[DPORT][1] = 80;
    a.info.range[PROTO][0] = TCP;
    a.info.range[PROTO][1] = TCP;
    a.info.priority = 1;

    b.info.range[SADDR][0] = 0x00000001;
    b.info.range[SADDR][1] = 0xffffffff;
    b.info.range[DADDR][0] = 0x14000001;
    b.info.range[DADDR][1] = 0x14000001;
    b.info.range[SPORT][0] = 0;
    b.info.range[SPORT][1] = 0xffff;
    b.info.range[DPORT][0] = 80;
    b.info.range[DPORT][1] = 80;
    b.info.range[PROTO][0] = TCP;
    b.info.range[PROTO][1] = TCP;
    b.info.priority = 2;

    c.info.range[SADDR][0] = 0x00000001;
    c.info.range[SADDR][1] = 0xffffffff;
    c.info.range[DADDR][0] = 0x14000001;
    c.info.range[DADDR][1] = 0x14000001;
    c.info.range[SPORT][0] = 0;
    c.info.range[SPORT][1] = 0xffff;
    c.info.range[DPORT][0] = 0;
    c.info.range[DPORT][1] = 0xffff;
    c.info.range[PROTO][0] = 0;
    c.info.range[PROTO][1] = 0xff;
    c.info.priority = 3;


    d.info.range[SADDR][0] = 0x00000001;
    d.info.range[SADDR][1] = 0xffffffff;
    d.info.range[DADDR][0] = 0x00000001;
    d.info.range[DADDR][1] = 0xffffffff;
    d.info.range[SPORT][0] = 1000;
    d.info.range[SPORT][1] = 2000;
    d.info.range[DPORT][0] = 1000;
    d.info.range[DPORT][1] = 2000;
    d.info.range[PROTO][0] = UDP;
    d.info.range[PROTO][1] = UDP;
    d.info.priority = 4;


    e.info.range[SADDR][0] = 0x14000001;
    e.info.range[SADDR][1] = 0x140000ff;
    e.info.range[DADDR][0] = 0x0a000a01;
    e.info.range[DADDR][1] = 0x0a000aff;
    e.info.range[SPORT][0] = 0;
    e.info.range[SPORT][1] = 0xffff;
    e.info.range[DPORT][0] = 3306;
    e.info.range[DPORT][1] = 3306;
    e.info.range[PROTO][0] = UDP;
    e.info.range[PROTO][1] = UDP;
    e.info.priority = 5;


    f.info.range[SADDR][0] = 0x0a0c0c01;
    f.info.range[SADDR][1] = 0x0a0c0cff;
    f.info.range[DADDR][0] = 0x00000001;
    f.info.range[DADDR][1] = 0xffffffff;
    f.info.range[SPORT][0] = 21;
    f.info.range[SPORT][1] = 21;
    f.info.range[DPORT][0] = 21;
    f.info.range[DPORT][1] = 21;
    f.info.range[PROTO][0] = TCP;
    f.info.range[PROTO][1] = TCP;
    f.info.priority = 6;


    g.info.range[SADDR][0] = 0x0a000001;
    g.info.range[SADDR][1] = 0x0a00ffff;
    g.info.range[DADDR][0] = 0x14000001;
    g.info.range[DADDR][1] = 0x14000fff;
    g.info.range[SPORT][0] = 0;
    g.info.range[SPORT][1] = 0xffff;
    g.info.range[DPORT][0] = 0;
    g.info.range[DPORT][1] = 0xffff;
    g.info.range[PROTO][0] = 0;
    g.info.range[PROTO][1] = 0xff;
    g.info.priority = 7;


    h.info.range[SADDR][0] = 0x00000000;
    h.info.range[SADDR][1] = 0xffffffff;
    h.info.range[DADDR][0] = 0x00000001;
    h.info.range[DADDR][1] = 0xffffffff;
    h.info.range[SPORT][0] = 0;
    h.info.range[SPORT][1] = 0xffff;
    h.info.range[DPORT][0] = 0;
    h.info.range[DPORT][1] = 0xffff;
    h.info.range[PROTO][0] = 0;
    h.info.range[PROTO][1] = 0xff;
    h.info.priority = 8;


    LIST_HEAD(my_list);

    printk(KERN_INFO "Starting SAL memless test\n");


    list_add_tail(&a.list, &my_list);
    list_add_tail(&b.list, &my_list);
    list_add_tail(&c.list, &my_list);
    list_add_tail(&d.list, &my_list);
    list_add_tail(&e.list, &my_list);
    list_add_tail(&f.list, &my_list);
    list_add_tail(&g.list, &my_list);
    list_add_tail(&h.list, &my_list);

    print_list(&my_list);

    swaps = list_access(&e.list, &my_list, &depends);
    printk("Accessing prio: %lld swaps %u\n", e.info.priority, swaps);
    print_list(&my_list);

    swaps = list_access(&c.list, &my_list, &depends);
    printk("Accessing prio: %lld swaps: %u\n", c.info.priority, swaps);
    print_list(&my_list);

    swaps = list_access(&d.list, &my_list, &depends);
    printk("Accessing prio: %lld swaps %u\n", d.info.priority, swaps);
    print_list(&my_list);

    swaps =list_access(&f.list, &my_list, &depends);
    printk("Accessing prio: %lld swaps %u\n", f.info.priority, swaps);
    print_list(&my_list);

    swaps =list_access(&e.list, &my_list, &depends);
    printk("Accessing prio: %lld swaps %u\n", e.info.priority, swaps);
    print_list(&my_list);

    swaps =list_access(&h.list, &my_list, &depends);
    printk("Accessing prio: %lld swaps %u\n", h.info.priority, swaps);
    print_list(&my_list);
    printk(KERN_INFO "End of SAL memless test\n");

    return 0;
}

static void __exit sal_memless_exit(void){

}

module_init(sal_memless_init);
module_exit(sal_memless_exit);

//

