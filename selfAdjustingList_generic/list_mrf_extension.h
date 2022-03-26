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
 * @is_dependent: function which decides if two elements are dependent on each other (a is a dependency of b)
 */
static inline unsigned int
list_access(struct list_head *pos, struct list_head *head, int(*is_dependent)(struct list_head *a, struct list_head *b)) {
    struct list_head *cur;
    unsigned int swap_count = 0;
    if (list_is_first(pos, head))
        return 0;
    cur = pos;

    while (!list_is_first(cur, head)) {
        cur = cur->prev;
        //cur is a dependency of pos => pos is not allowed to be in front of cur
        //move pos behind cur and set pos to cur
        if (is_dependent(cur, pos)) {
            if (cur != pos->prev) {
                list_move(pos, cur);
                swap_count++;
            }
            pos = cur;
        }
    }

    if (!list_is_first(pos, head)){
        list_move(pos, head);
        swap_count++;
    }

    return swap_count;
}

static inline void
list_access_rec(struct list_head *pos, struct list_head *head, int(*is_dependent)(struct list_head *a, struct list_head *b))
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

#endif //SELFADJUSTINGLIST_GENERIC_LIST_MRF_EXTENSION_H
