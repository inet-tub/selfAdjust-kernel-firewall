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
/**
 * The basic idea is:
 * - We go through the whole list and check for every entry if there is a dependency between the new element and the existing one
 * - we need to consider 2 cases:
 *  - 1. we find an element that needs to be in front of the new element
 *      - we save a pointer to the last element we've found (last_dep) and after we finished searching the list we insert new behind this last
 *          dependency.
 *  - 2. we find an element that needs to be behind the new element
 *      - we remove that element from the list and add it to a sublist (list_add_tail(new)), this means we are collecting all elements that
 *          have a dependency to new ,and therefore need to be behind new.
 *      - after we have searched the whole list we insert the sublist in a suitable spot
 *          - if new needs to be behind a certain element (1.) insert the sublist behind that element
 *              - also every node in the sublist must be checked against every other node
 *                  - if another node has a dependency to a node in the sublist we also need to add this node
 *          - if the sublist is empty (no dependencies to new) insert new at the end
 *          - if the sublist is not empty, but new has no dependency to any other node, we can just insert new before
 *              the first node we find that has a dependency to new
 *
 *
 * Case 1: No deps at all, just add it at the back
 * new:        4
 *                          => 1    2   3   4
 * list: 1   2    3
 *
 * Case 2: new has a dependency to a node, new needs to go behind 2
 * new:     4
 *          |     => 1  2 <- 4   3
 * list: 1  2   3
 *
 * Case 3: nodes have dependency to new, but new has no dependency to another node => just add new in front of the first dependency found
 * new:     4
 *        +_^
 *       |  |       => 4 <- 1   2   3
 * list: 1  2   3      ^--------+
 *
 * Case 4: nodes have dependencies between them and a dependency to new => just add new in front of the first dependency found
 * new:     4
 *        +-^
 *       |              => 4 <- 1 <- 2  3
 * list: 1 <- 2     3
 *
 * Case 5: like Case 3 but new has also a dependency to another node => create the sublist and insert it behind last dependency
 * new:     4----+
 *       +--^    |
 *       |  |    |      => 3 <- 4 <- 1 <- 2
 * list: 1  2   3
 *
 * Case 6: like case 4 but new has also a dependency to another node => transitivity check is needed and indirect dependencies need to be added to the sublist
 * new:     4 -----+
 *       +--^      |    => 3 <- 4 <- 1 <- 2
 *       |         |
 * list: 1 <- 2   3
 */

static inline void list_sal_insert(struct list_head *new, struct list_head *head,
        int(*is_dependent)(struct list_head *a, struct list_head *b))
{
    struct list_head *pos;
    struct list_head *pos1;
    struct list_head *tmp;
    struct list_head *last_dep = NULL;
    struct list_head *last_dep_next;
    struct list_head *last_dep_to_new;
    struct list_head *last;
    new->prev = new;
    new->next = new;

    list_for_each(pos,head){
        //new must go behind and element which is already in the list
        if(is_dependent(pos, new)){
            last_dep = pos;
            continue;
        }

    }


    list_for_each(pos, head){
        //an element in the list must come behind new
        if(pos == last_dep)
            break;

        if(is_dependent(new, pos)){
            last_dep_to_new = pos->prev;
            list_del_rcu(pos);
            list_add_tail(pos,new);
            pos = last_dep_to_new;
            if(!last_dep){ // we can just insert new in front of pos, because new does not need to go behind another element
                           // we just have a 2 element sublist +- new -+- pos -+
                break;
            }

        }else{
            if(!list_empty(new)){ //search if we have an element in the sublist where pos has a dependency to and therefore needs also be added to the sublist
                list_for_each(pos1, new){
                    if(is_dependent(pos1, pos)){
                        tmp = pos1->prev;
                        list_del_rcu(pos1);
                        list_add_tail(pos1,new);
                        pos1 = tmp;
                    }
                }
            }
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
