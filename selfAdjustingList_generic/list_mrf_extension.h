//
// Created by Jonas Köppeler on 21.01.22.
//

#ifndef SELFADJUSTINGLIST_GENERIC_LIST_MRF_EXTENSION_H
#define SELFADJUSTINGLIST_GENERIC_LIST_MRF_EXTENSION_H
#include <linux/list.h>
/**
 * list_access - memoryless implementation of the mrf- algorithm,
 *               reorders elements in the list after an element has been accessed
 * @pos: the element that is accessed
 * @head: the head of the list
 * @is_dependent: function which decides if two elements are dependent on each other
 */
static inline void
list_access(struct list_head *pos, struct list_head *head, int(*is_dependent)(struct list_head *a, struct list_head *b))
{
    struct list_head *cur;
    struct list_head *prev;
    cur = pos;

    while (!list_is_first(cur, head)){
        prev = cur->prev;
        //prev is a dependency of cur => cur is not allowed to be in front of prev
        if(is_dependent(cur, prev)) {
            cur = prev;
        }else{
            list_swap(cur, prev);
        }
    }
}

#endif //SELFADJUSTINGLIST_GENERIC_LIST_MRF_EXTENSION_H
