//
// Created by Jonas Köppeler on 21.01.22.
//

#ifndef SELFADJUSTINGLIST_GENERIC_LIST_MRF_EXTENSION_H
#define SELFADJUSTINGLIST_GENERIC_LIST_MRF_EXTENSION_H
#include <linux/list.h>
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
