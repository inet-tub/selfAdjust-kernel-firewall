//
// Created by Jonas Köppeler on 11.11.21.
//

#ifndef SELF_ADJUSTING_LIST_H
#define SELF_ADJUSTING_LIST_H
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/list.h>

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
 //TODO maybe renaming to sal_access(_point)
struct sal_entry_point {
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

// initializes the entry point of the list
#define SAL_ENTRY_POINT_INIT(name, func) \
    {{&(name).list, &(name).list, { &(name).list.dependencies , &(name).list.dependencies }}, (func)}

#define SAL_ENTRY_POINT(name, func) \
    struct sal_entry_point name = SAL_ENTRY_POINT_INIT(name, func)


//initializes the sal_head struct
#define SAL_HEAD_INIT(name, sal_head) \
    (name).sal_head.next = NULL; \
    (name).sal_head.prev = NULL;      \
    (name).sal_head.dependencies.next = &(name).sal_head.dependencies; \
    (name).sal_head.dependencies.prev = &(name).sal_head.dependencies


/**
 * iterate over all sal_head 's in the list
 * @x: name of the variable
 * @entry_point: pointer to the sal_entry_point
 */
#define FOR_NODE_IN_SAL(x, entry_point) \
    for(x = (entry_point)->list.next; (x) != &(entry_point)->list; (x) = (x)->next)

/**
 * @ptr: pointer to struct sal_head
 * @type: the name of the struct where sal_head is embedded
 * @member: the name of the sal_head in the struct
 */
#define SAL_ENTRY(ptr, type, member) \
    container_of(ptr,type,member)

/**
 * FOR_NODE_IN_DEPS - wrapper around the macro from list.h
 * @x: name of the struct list_head variable
 * @sal_head: pointer to the struct sal_head
 */
#define FOR_NODE_IN_DEPS(x, sal_head) \
    list_for_each(x,&(sal_head->dependencies))

#define SAL_DEP_ENTRY(ptr) \
    container_of(ptr, struct sal_dependency_node, list)
/**
 * sal_empty - tests whether a list is empty
 * @head: the list to test
 */
int sal_empty(struct sal_entry_point *head){
    return head->list.next == &head->list;
}

/**
 * sal_check_dependencies - searches the whole list, whether there is a dependency between an existing node to
 * the new_node according to the is_dependent function
 * if no is_dependent function is provided, the list should behave like a normal linked list
 * @head: entry point to the list
 * @new_node: the new node which is inserted
 * */
int sal_check_dependencies(struct sal_entry_point *head, struct sal_head *new_node){
    struct sal_dependency_node *dep;
    struct sal_head* node;

    if(head->is_dependent == NULL){
        return 0;
    }
    FOR_NODE_IN_SAL(node, head) {
        //TODO is it needed, to check both direction? i suppose yes, since the dependencies is not a symmetric relation
        if (head->is_dependent(node, new_node)) {
            dep = kzalloc(sizeof(struct sal_dependency_node), GFP_KERNEL);
            dep->dep = new_node;
            list_add_tail(&dep->list, &node->dependencies);
        }else if(head->is_dependent(new_node, node)) {
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
int sal_add_last(struct sal_entry_point *head, struct sal_head *new_node) {
    struct sal_head *last;
    //Check first for dependencies so that the node does not check if it has a dependency to itself
    sal_check_dependencies(head, new_node);

    last = head->list.prev;
    last->next = new_node;
    new_node->next = &head->list;
    new_node->prev = last;
    head->list.prev = new_node;
    return 0;
}

/**
 *__sal_cleanup_dependencies - removes all the dependency entries from a sal_entry
 * @node: a sal_entry with a list of dependencies
 */
void __sal_cleanup_dependencies(struct sal_head *node) {
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
//        printk(KERN_INFO "%s: LIST_POISON1: %p LIST_POISON2: %p \n", __FUNCTION__ , cur->next, cur->prev);
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
 * @head: entry point of the list
 */
 void sal_cleanup(struct sal_entry_point *head) {
     struct sal_head *cur;

    FOR_NODE_IN_SAL(cur, head){
        __sal_cleanup_dependencies(cur);
    }
 }

#endif //SELF_ADJUSTING_LIST_H
