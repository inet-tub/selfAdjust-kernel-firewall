#include <stdio.h>
#include "self_adjusting_list.h"
#include <linux/types.h>

bool depends(void *a, void *b){
    return 1;
}

struct my_struct {
    int idx;
    struct sal_list_head list;
};

int main() {
    SAL_LIST_HEAD(new_list, &depends);
    struct my_struct x = {1, NULL,NULL, NULL,NULL};
    struct my_struct y = {2, NULL,NULL, NULL,NULL};
    struct my_struct z = {3, NULL,NULL, NULL,NULL};
    struct my_struct u = {4, NULL,NULL, NULL,NULL};
    sal_add_last(&new_list, &x.list);
    sal_add_last(&new_list, &y.list);
    sal_add_last(&new_list, &z.list);
    sal_add_last(&new_list, &u.list);
    FOR_NODE_IN_SAL(new_list){
        struct my_struct *a = container_of(node, struct my_struct, list);
        printf("idx: %d\n", a->idx);
    }

    return 0;
}
