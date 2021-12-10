#include <stdio.h>
#include "self_adjusting_list.h"
#include <linux/types.h>

struct my_struct {
    int idx;
    struct sal_head list;
};

//always need container_of macro to get access to the struct.
//It's not nice, but I don't see better way of doing this.
//Another idea would be to work with void *. A fixed type is needed, because of the function pointer in the entry_point struct
//But also if I could manage to pass the custom struct type using macros down to the sal_check_dependencies function
// (which calls this function), still, a cast from "void *" to "struct custom_struct *" is needed, so either way I cannot
// get rid of the cast => so it seems to be still easier to do it with container_of
bool depends(struct sal_head *a, struct sal_head*b){
    struct my_struct *item_a = container_of(a, struct my_struct, list);
    struct my_struct *item_b = container_of(b, struct my_struct, list);
    if(item_a->idx < item_b->idx)
        return 1;
    else
        return 0;
}


int main() {
    SAL_ENTRY_POINT(new_list, &depends);
    struct my_struct x = {1};
    SAL_HEAD_INIT(x, list);

    struct my_struct y = {2};
    SAL_HEAD_INIT(y, list);

    struct my_struct z = {3};
    SAL_HEAD_INIT(z, list);
    struct my_struct u = {4};
    SAL_HEAD_INIT(u, list);

    sal_add_last(&new_list, &x.list);
    sal_add_last(&new_list, &y.list);
    sal_add_last(&new_list, &z.list);
    sal_add_last(&new_list, &u.list);
    FOR_NODE_IN_SAL(node, new_list){
        struct my_struct *a = container_of(node, struct my_struct, list);
        printf("idx: %d\n", a->idx);
    }

    return 0;
}
