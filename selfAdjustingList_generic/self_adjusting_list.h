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
 * @next: points to the next element in the list
 * @prev: points to the previous element in the list
 * @dependencies: list to store the dependencies of a list entry
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

/*
 * sal_add_last - inserts a new element at the end of the list
 * @head this is the entry point to the list
 * @new_node is the new item to insert
 * */
int sal_add_last(struct sal_list_entry_point *head, struct sal_list_head *new_node) {
    struct sal_list_head *last = head->list.prev;
    last->next = new_node;
    new_node->next = &head->list;
    new_node->prev = last;
    head->list.prev = new_node;
    return 0;
}

#define FOR_NODE_IN_SAL(x,list_head) for(struct sal_list_head *(x) = (list_head).list.next; (x) != &(list_head).list; (x) = (x)->next)

#endif //SELF_ADJUSTING_LIST_H
