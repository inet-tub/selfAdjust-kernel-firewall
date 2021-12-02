//
// Created by Jonas Köppeler on 11.11.21.
//

#ifndef SELF_ADJUSTING_LIST_H
#define SELF_ADJUSTING_LIST_H
#include <linux/types.h>
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})


/*
 * struct sal_list_head - self adjusting list node element with dependencies
 * @list: the list that links the elements (other list_nodes)
 * @dependencies: list to store the dependencies of a list entry
 * @data: the data of the entry
 */
struct sal_list_head {
    struct sal_list_head *next;
    struct sal_list_head *prev;
    struct list_head dependencies;
};

/* struct sal_list_entry_point - entry point to the list
 * @list: points to the first and the last element of the list, small overhead because dependencies is never used for the entry_point
 * @is_dependent: Function to check whether 2 list entries are dependent on each other
 *
 */
struct sal_list_entry_point {
    struct sal_list_head list;
    bool (*is_dependent)(void *, void *);
};

/*
 * struct sal_dependency_node - structure to store dependencies
 * @id: identifier of another sa_list_node, which has a dependency with this sa_list_node
 * @list: list of dependencies
 */

struct sal_dependency_node {
    int id;
    struct list_head list;
};

// list head points to itself
#define SAL_LIST_HEAD_INIT(name, func) {&(name).list, &(name).list,&(name).list.dependencies, &(name).list.dependencies, func}

#define SAL_LIST_HEAD(name, func) \
    struct sal_list_entry_point name = SAL_LIST_HEAD_INIT(name, func)


int sal_add_last(struct sal_list_entry_point *head, struct sal_list_head *new_node) {
    struct sal_list_head *last = head->list.prev;
    last->next = new_node;
    new_node->next = &head->list;
    new_node->prev = last;
    head->list.prev = new_node;
    return 0;
}

//DEBUG SECTION
//void iterate_and_print_idx(struct sal_list_entry_point *head) {
//    struct list_head *next = head->list.next;
//    while (next != &head->list){
//        struct sal_list_head *item = container_of(next, struct sal_list_head, list);
//        printf("%u\n", item->index);
//        next = next->next;
//    }
//}

#define FOR_NODE_IN_SAL(list_head) for(struct sal_list_head *node = (list_head).list.next; node != &(list_head).list; node = node->next)

#endif //SELF_ADJUSTING_LIST_H
