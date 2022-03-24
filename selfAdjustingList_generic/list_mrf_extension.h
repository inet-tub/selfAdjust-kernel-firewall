//
// Created by Jonas Köppeler on 21.01.22.
//

#ifndef SELFADJUSTINGLIST_GENERIC_LIST_MRF_EXTENSION_H
#define SELFADJUSTINGLIST_GENERIC_LIST_MRF_EXTENSION_H
#include <linux/list.h>
#include <linux/rculist.h>
/**
 * list_access - memoryless implementation of the mrf-algorithm,
 *               reorders elements in the list after an element has been accessed
 * @pos: the element that is accessed
 * @head: the head of the list
 * @is_dependent: function which decides if two elements are dependent on each other (a is a dependecy of b)
 */
static inline void
list_access(struct list_head *pos, struct list_head *head,
        int(*is_dependent)(struct list_head *a, struct list_head *b))
{
    struct list_head *cur;
    struct list_head *prev;
    cur = pos;

    while (!list_is_first(cur, head)){
        prev = cur->prev;
        //prev is a dependency of cur => cur is not allowed to be in front of prev
        if(is_dependent(prev, cur)) {
            cur = prev;
        }else{
            list_swap(cur, prev);
        }
    }
}

static inline void
list_access_rec(struct list_head *pos, struct list_head *head,
        int(*is_dependent)(struct list_head *a, struct list_head *b))
{
    struct list_head *cur;
    struct list_head *prev;
    cur = pos;
    if(list_is_first(cur, head)){
        return;
    }
    prev = cur->prev;
    if(is_dependent(prev, cur))
        list_access_rec(prev, head, is_dependent);
    else{
        list_swap(cur, prev);
        list_access_rec(cur, head, is_dependent);
    }
}

//This might require a lock in kernel
static inline void list_sal_insert(struct list_head *new, struct list_head *head,
        int(*is_dependent)(struct list_head *a, struct list_head *b))
{
    struct list_head *pos;
    struct list_head *last_dep = NULL;
    struct list_head *last_dep_next;
    struct list_head *last_dep_to_new;
    struct list_head *last;
    new->prev = new;
    new->next = new;
    list_for_each(pos, head){
            //an element in the list must come behind new
            if(is_dependent(new, pos)){
                last_dep_to_new = pos->prev;
                list_del_rcu(pos);
                list_add_tail(pos,new);
                pos = last_dep_to_new;
                continue;
            }
            //new must go behind and element which is already in the list
            if(is_dependent(pos, new)){
                last_dep = pos;
                continue;
            }
    }

    //we found an element where we need to insert new behind
    //
    // +- new -+- .. -+- last -+
    // |____________  _________|
    //             |  |
    // +- last_dep -+- last_dep_next -+
    //
    if(last_dep){
        last = new->prev;
        last->next = last_dep->next;
        new->prev = last_dep;
        last_dep_next = last_dep->next;
        rcu_assign_pointer(last_dep->next, new);
        last_dep_next->prev = new;
    }else { //We are free to insert new anywhere
        if(list_empty(new)){
            list_add_tail_rcu(new, head);
        }else{ // we insert it as much forward in the list as possible
            last = new->prev;
            last->next = last_dep_to_new->next;
            new->prev = last_dep_to_new;
            rcu_assign_pointer(last_dep_to_new->next, new);
            last_dep_to_new->prev = new;
        }
    }

}


#endif //SELFADJUSTINGLIST_GENERIC_LIST_MRF_EXTENSION_H
