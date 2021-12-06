//
// Created by Jonas Köppeler on 11.11.21.
//

#ifndef SELF_ADJUSTING_LIST_H
#define SELF_ADJUSTING_LIST_H
#include <linux/types.h>
// BEGIN #TODO remove this when move to kernel => replace malloc!!!
//#include <stdlib.h>
// END #TODO
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})   \

/* PART OF KERNEL list.h remove this when move to kernel space*/
static inline void __list_add(struct list_head *new, struct list_head *prev, struct list_head *next) {
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}
static inline void list_add_tail(struct list_head *new, struct list_head *head){
    __list_add(new, head->prev, head);
}

/*END OF KERNEL list.h*/

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
    bool (*is_dependent)(struct sal_list_head *, struct sal_list_head *);
};

/*
 * struct sal_dependency_node - structure to store dependencies
 * @id: identifier of another sa_list_node, which has a dependency with this sa_list_node
 * @list: list of dependencies
 */

struct sal_dependency_node {
    struct sal_list_head *dep;
    struct list_head list;
};

// initializes the entry point of the list
#define SAL_ENTRY_POINT_INIT(name, func) {&(name).list, &(name).list,&(name).list.dependencies, &(name).list.dependencies, func}

#define SAL_ENTRY_POINT(name, func) \
    struct sal_list_entry_point name = SAL_ENTRY_POINT_INIT(name, func)


//initializes the sal_list_head struct
#define SAL_HEAD_INIT(name, sal_head) \
    (name).sal_head.next = NULL; \
    (name).sal_head.prev = NULL;      \
    (name).sal_head.dependencies.next = &(name).sal_head.dependencies; \
    (name).sal_head.dependencies.prev = &(name).sal_head.dependencies


int sal_check_dependencies(struct sal_list_entry_point *head, struct sal_list_head *new_node);

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
    sal_check_dependencies(head, new_node);
    return 0;
}

//x is a pointer, but list_head is not...#TODO change list_head also to a pointer?
#define FOR_NODE_IN_SAL(x,list_head) for(struct sal_list_head *(x) = (list_head).list.next; (x) != &(list_head).list; (x) = (x)->next)


//searches the whole list, whether there is a dependency to the new_node
int sal_check_dependencies(struct sal_list_entry_point *head, struct sal_list_head *new_node){
    if(head->is_dependent == NULL){
        return 0;
    }
    FOR_NODE_IN_SAL(node, *head) {
        //TODO is it needed, to check both direction? i suppose yes, since the dependencies is not a symmetric relation
        if (head->is_dependent(node, new_node)) {
            printf("%d\n", head->is_dependent(node, new_node));
            // #TODO replace malloc and where is it freed?
            struct sal_dependency_node *dep = malloc(sizeof(struct sal_dependency_node));
            dep->dep = new_node;
            list_add_tail(&dep->list, &node->dependencies);
        }else if(head->is_dependent(new_node, node)) {
            printf("%d\n", head->is_dependent(new_node, node));
            // #TODO replace malloc and where is it freed?
            struct sal_dependency_node *dep = malloc(sizeof (struct sal_dependency_node));
            dep->dep = node;
            list_add_tail(&dep->list, &new_node->dependencies);
        }
    }
}

#endif //SELF_ADJUSTING_LIST_H
