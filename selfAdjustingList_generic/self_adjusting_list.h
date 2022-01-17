//
// Created by Jonas Köppeler on 11.11.21.
//

#ifndef SELF_ADJUSTING_LIST_H
#define SELF_ADJUSTING_LIST_H
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/list.h>

#define FALSE 0
#define TRUE 1

/**
 * struct sal_head - self adjusting list node element with dependencies
 * @next: points to the next element in the list
 * @prev: points to the previous element in the list
 * @dependencies: list to store the dependencies of a list entry
 */
struct sal_head {
    struct sal_head *next;
    struct sal_head *prev;
    struct list_head dependencies;
};

/**
 * struct sal_entry_point - entry point to the list
 * @list: points to the first and the last element of the list, small overhead because dependencies is never
 * used for the entry_point
 * @is_dependent: Function to check whether 2 list entries are dependent on each other
 *
 */
struct sal_access {
    struct sal_head list;
    bool (*is_dependent)(struct sal_head *, struct sal_head *);
};

/**
 * struct sal_dependency_node - structure to store dependencies
 * @dep: pointer to a another node, this node has a dependency to
 * @list: list of dependencies
 */
struct sal_dependency_node {
    struct sal_head *dep;
    struct list_head list;
};

// initializes the sal_access of the list
#define SAL_ACCESS_INIT(name, func) \
    {{&(name).list, &(name).list, { &(name).list.dependencies , &(name).list.dependencies }}, (func)}

#define SAL_ACCESS(name, func) \
    struct sal_access name = SAL_ACCESS_INIT(name, func)


//initializes the sal_head struct
#define SAL_HEAD_INIT(name, sal_head) \
    (name)->sal_head.next = NULL; \
    (name)->sal_head.prev = NULL;      \
    (name)->sal_head.dependencies.next = &(name)->sal_head.dependencies; \
    (name)->sal_head.dependencies.prev = &(name)->sal_head.dependencies


/**
 * iterate over all sal_head 's in the list
 * @pos: name of the variable
 * @access: pointer to the sal_entry_point
 */
#define FOR_NODE_IN_SAL(pos, access) \
    for(pos = (access)->list.next; (pos) != &(access)->list; (pos) = (pos)->next)

/**
 * @ptr: pointer to struct sal_head
 * @type: the name of the struct where sal_head is embedded
 * @member: the name of the sal_head in the struct
 */
#define SAL_ENTRY(ptr, type, member) \
    container_of(ptr,type,member)

/**
 * First/Last entry in the SAL
 * @access: pointer to struct sal_access
 * @type: the name of the struct where sal_head is embedded
 * @member: the name of the sal_head in the struct
 */
#define SAL_FIRST_ENTRY(access, type, member) \
    container_of((access)->list.next, type, member)

#define SAL_LAST_ENTRY(access, type, member) \
    container_of((access)->list.prev, type, member)

#define SAL_FIRST(access) \
    access->list.next

#define SAL_LAST(access) \
    access->list.prev


/**
 * @node: pointer to struct sal_head
 * @access: pointer to struct sal_access
 */
#define sal_is_first(node, access) \
    (access->list.next == node)

#define sal_is_last(node, access) \
    (access->list.prev == node)

#define sal_next_entry(pos, member) \
    SAL_ENTRY((pos)->member.next, typeof(*pos), member)

/**
 * sal_entry_is_head - checks if a given struct entry is the head of the list
 * @pos: pointer to the entry
 * @access: pointer to struct sal_access
 * @member: name of the struct sal_head in the entry
 */
#define sal_entry_is_head(pos, access, member) \
    (&pos->member == &(access)->list)

/**
 * sal_is_head - checks if struct sal_head is start of the list
 * @node: pointer to struct sal_head
 * @access: pointer to struct sal_access
 */
#define sal_is_head(node, access) \
    (node == &(access)->list)

/**
 * sal_for_each_entry - iterate over every entry in the list
 * @pos: iteration variable - type of custom struct
 * @access: pointer to struct sal_access
 * @member: name of struct sal_head in the custom struct
 */
#define sal_for_each_entry(pos, access, member) \
    for(pos=SAL_FIRST_ENTRY(access, typeof(*pos), member);\
        !sal_entry_is_head(pos, access, member); \
        pos = sal_next_entry(pos, member))


/**
 * @node: pointer to struct sal_head
 */
#define sal_prev(node) \
    node->prev

#define sal_next(node) \
    node->next


/**
 * FOR_NODE_IN_DEPS - wrapper around the macro from list.h
 * @pos: name of the struct list_head variable
 * @node: pointer to the struct sal_head
 */
#define FOR_NODE_IN_DEPS(pos, node) \
    list_for_each(pos, &((node)->dependencies))

/**
 * return a pointer to a sal_dependency_node
 * @ptr: pointer to list_head in the sal_dependency_node
 */
#define SAL_DEP_ENTRY(ptr) \
    container_of(ptr, struct sal_dependency_node, list)

/**
 * iterate over dependencies of an entry
 * @pos: iteration variable
 * @entry: pointer to an entry - the custom struct
 * @member: name of struct sal_head in the entry
 */
#define sal_for_each_dep_entry(pos, entry, member) \
    list_for_each_entry(pos, &(entry->member).dependencies, list)

/**
 * sal_empty - tests whether a list is empty
 * @head: the list to test
 */
static inline int sal_empty(struct sal_access *head){
    return head->list.next == &head->list;
}


/**
 * sal_swap - swaps two nodes
 * @a: node that changes place with b
 * @b: node that changes place with a
 */
static inline void sal_swap(struct sal_head *a, struct sal_head *b){
    struct sal_head *old_a_next;
    struct sal_head *old_b_prev;
    struct sal_head *tmp;

    //if b is before a in the list change pointers so that a is before b
    if(b->next == a) {
        tmp = b;
        b = a;
        a = tmp;
    }

    old_a_next = a->next;
    old_b_prev = b->prev;

    a->next = b->next;
    b->prev = a->prev;
    a->prev->next = b;
    b->next->prev = a;

    //if a and b are not neighbours
    if(old_a_next != b){
        b->next = old_a_next;
        a->prev = old_b_prev;
        old_b_prev->next = a;
        old_a_next->prev = b;
    }else { //if a and b are neighbours
        b->next = a;
        a->prev = b;
    }
}


/**
 * sal_swap_prev - swaps a node with its previous node
 * @a: a is swapped with a->prev
 */
static inline void sal_swap_prev(struct sal_head *a){
    sal_swap(a, a->prev);
}


/**
 * sal_dependent_prev - checks if a node has a dependency on its previous node
 * @pos: node
 * @return if pos->prev is a dependency of pos return TRUE
 */
static inline int sal_dependent_prev(struct sal_head *pos){
    struct sal_dependency_node *dep;
    struct sal_head *prev = pos->prev;
    list_for_each_entry(dep, &pos->dependencies, list){
        if(dep->dep == prev)
            return TRUE;
    }
    return FALSE;
}


/**
 * sal_move_front - move a node to the front of the list - node is removed from its current
 * position and inserted at front
 * @node: node that is moved to front
 * @access: list
 */
static inline void sal_move_front(struct sal_head *node, struct sal_access *access){
    if(sal_is_first(node, access)){
        return;
    }
    node->prev->next = node->next;
    node->next->prev = node->prev;
    node->next = access->list.next;
    node->prev = &access->list;
    access->list.next->prev = node;
    access->list.next = node;
}


/**
 * sal_access_entry - function that is called when an entry is accessed; rearrange the order of elements
 * @node: node that is accessed
 * @access: list
 */
static inline void sal_access_entry(struct sal_head *node, struct sal_access *access) {
    struct sal_head *pos;
    pos = node;
    if(sal_is_first(pos, access)){
        return;
    }

    if(list_empty(&pos->dependencies)){
        sal_move_front(pos, access);
        return;
    }

    while(!sal_is_first(pos, access)){
        if(!sal_dependent_prev(pos))
            sal_swap_prev(pos);
        else
            pos = pos->prev;
    }
}


/**
 * sal_check_dependencies - searches the whole list, whether there is a dependency between an existing node to
 * the new_node according to the is_dependent function
 * if no is_dependent function is provided, the list should behave like a normal linked list
 * @access: list
 * @new_node: the new node which is inserted
 * */
static inline int sal_check_dependencies(struct sal_access *access, struct sal_head *new_node){
    struct sal_dependency_node *dep;
    struct sal_head* node;

    if(access->is_dependent == NULL){
        return 0;
    }

    FOR_NODE_IN_SAL(node, access) {
        //TODO is it needed, to check both direction? i suppose yes, since the dependencies is not a symmetric relation
        if (access->is_dependent(node, new_node)) {
            dep = kzalloc(sizeof(struct sal_dependency_node), GFP_KERNEL);
            dep->dep = new_node;
            list_add_tail(&dep->list, &node->dependencies);
        }else if(access->is_dependent(new_node, node)) {
            dep = kzalloc(sizeof (struct sal_dependency_node), GFP_KERNEL);
            dep->dep = node;
            list_add_tail(&dep->list, &new_node->dependencies);
        }
    }
    return 0;
}


/**
 * sal_add_last - inserts a new element at the end of the list
 * @head: this is the entry point to the list
 * @new_node: is the new item to insert
 * */
static inline int sal_add_last(struct sal_access *access, struct sal_head *new_node) {
    struct sal_head *last;
    //Check first for dependencies so that the node does not check if it has a dependency to itself
    sal_check_dependencies(access, new_node);

    last = access->list.prev;
    last->next = new_node;
    new_node->next = &access->list;
    new_node->prev = last;
    access->list.prev = new_node;
    return 0;
}


/**
 * __sal_cleanup_dependencies - removes all the dependency entries from a sal_entry
 * @node: a sal_entry with a list of dependencies
 */
static inline void __sal_cleanup_dependencies(struct sal_head *node) {
    struct list_head *dep_list_head;
    struct sal_dependency_node *cur_dep_entry;
    struct list_head *cur;
    if(node == NULL) {
        printk(KERN_WARNING "%s: node is NULL! Try to deduct how you end up in this mess!\n", __FUNCTION__ );
        return;
    }
    dep_list_head = &node->dependencies;
    cur_dep_entry = NULL;
    while (!list_empty(dep_list_head)){
        cur = dep_list_head->next;
        list_del(cur); //sets the next and prev to LIST_POISON
        cur_dep_entry = list_entry(cur, struct sal_dependency_node, list);
        cur_dep_entry->dep = NULL;
        if(cur_dep_entry != NULL) //#TODO just here for safety
            kfree(cur_dep_entry);
        else
            printk(KERN_ALERT "%s: The cur_dep_entry is NULL. WHY???\n", __FUNCTION__ );
        cur_dep_entry = NULL;
    }
}


/**
 * sal_cleanup - iterates over all sal_entries and frees the allocated memory
 * @access: access point of the list
 */
static inline void sal_cleanup(struct sal_access *access) {
     struct sal_head *cur;

    FOR_NODE_IN_SAL(cur, access){
        __sal_cleanup_dependencies(cur);
    }
 }

#endif //SELF_ADJUSTING_LIST_H
