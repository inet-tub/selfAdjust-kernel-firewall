#ifdef CONFIG_SAL_GENERAL
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nft_meta.h>
#include <net/netfilter/nf_tables_core.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/byteorder/generic.h>

#define RULE_CMP_SRC_ADDR 12
#define RULE_CMP_DST_ADDR 16
#define RULE_CMP_PROTOCOL 9
#define RULE_CMP_DPORT 2
#define RULE_CMP_SPORT 0

#define SADDR 0
#define DADDR 1
#define SPORT 2
#define DPORT 3
#define PROTO 4
#define SDPORT 5
#define UNKNOWN 255

#define LOWDIM 0
#define HIGHDIM 1

static void print_rule_info(struct nft_ra_info *data){
    printk("saddr %x : %x \n", data->range[SADDR][LOWDIM], data->range[SADDR][HIGHDIM]);
    printk("daddr %x : %x \n", data->range[DADDR][LOWDIM], data->range[DADDR][HIGHDIM]);
    printk("sport %u : %u \n", data->range[SPORT][LOWDIM], data->range[SPORT][HIGHDIM]);
    printk("dport %u : %u \n", data->range[DPORT][LOWDIM], data->range[DPORT][HIGHDIM]);
    printk("prtocol %x : %x \n", data->range[PROTO][LOWDIM], data->range[PROTO][HIGHDIM]);
    printk("priority: %llu\n", data->priority);
}

int rule_compare(struct list_head *prev, struct list_head *matched){
    struct nft_rule *prev_rule;
    struct nft_rule *r;
    struct nft_ra_info *prev_info;
    struct nft_ra_info *r_info;
    int i;
#ifndef CONFIG_SAL_MEMLESS_HELPER_STRUCT
    struct nft_ra_info prev_cmp_data;
    struct nft_ra_info r_cmp_data;
#endif

    prev_rule = container_of(prev, struct nft_rule, list);
    r = container_of(matched, struct nft_rule, list);

#ifdef CONFIG_SAL_MEMLESS_HELPER_STRUCT
    prev_info = &prev_rule->cmp_data;
    r_info = &r->cmp_data;
#else
    nft_construct_rule_data(&prev_cmp_data, prev_rule);
    nft_construct_rule_data(&r_cmp_data, r);
    prev_info = &prev_cmp_data;
    r_info = &r_cmp_data;
#endif

    for(i = 0; i < 5; ++i){
        if(r_info->range[i][HIGHDIM] < prev_info->range[i][LOWDIM] || r_info->range[i][LOWDIM] > prev_info->range[i][HIGHDIM])
            return 0;
    }

    // a low number in the priority field is a high priority
    if(prev_rule->priority < r->priority){
        printk("Rule %llu is a dependecy of Rule %llu\n", (long long unsigned int)prev_rule->handle, (long long unsigned int)r->handle);
        //print_rule_info(&prev_rule->cmp_data);
        //print_rule_info(&r->cmp_data);
       return 1;
    }
    else
        return 0;
}


enum ra_state {
    START = 0,
    NEXT_LOAD,
    PAYLOAD_LOADED,
    META_LOADED,
    FIELD_SET,
    END,
    UNEXPECTED,
};

static u8 nft_ra_payload(struct nft_expr *expr, u32 *prefix_mask, int *prefix_mask_set){
    struct nft_payload *payload;
    u8 ret;
    payload = nft_expr_priv(expr);
   
    switch (payload->base)
    {
    case NFT_PAYLOAD_LL_HEADER:
        BUG();
        break;
    case NFT_PAYLOAD_NETWORK_HEADER:
        switch (payload->offset)
        {
        case RULE_CMP_SRC_ADDR:
            ret = SADDR;
            break;
        case RULE_CMP_DST_ADDR:
            ret = DADDR;
            break;
        case RULE_CMP_PROTOCOL:
            ret = PROTO;
            break;
        default:
            BUG();
            ret = UNKNOWN;
            break;
        }
        //prefixes are in network byte order
        switch (payload->len){
            case 1:
                *prefix_mask = 0x000000ff;
                *prefix_mask_set = 1;
                break;
            case 2:
                *prefix_mask = 0x0000ffff;
                *prefix_mask_set = 1;
                break;
            case 3:
                *prefix_mask = 0x00ffffff;
                *prefix_mask_set = 1;
                break;
            case 4:
                break;
            default:
                BUG();
        }
        break;
    case NFT_PAYLOAD_TRANSPORT_HEADER:
        switch (payload->offset)
        {
        case RULE_CMP_DPORT:
            ret = DPORT;
            break;
        case RULE_CMP_SPORT:
            if(payload->len == 2){
                ret = SPORT;
            }else if(payload->len == 4){
                ret = SDPORT;
            }else{
                BUG();
                ret = UNKNOWN;
            }
            break;
        default:
            BUG();
            ret = UNKNOWN;
            break;
        }
        break; 
    default:
        BUG();
        break;
    }

    return ret;
}

static void nft_ra_cmp(struct nft_ra_info *data, struct nft_expr *expr, u8 f, u8 fast, u32 *prefix_mask, int *prefix_mask_set){
    u32 val = 0;
    enum nft_cmp_ops op= 0;
    if(fast){
        struct nft_cmp_fast_expr *cmp = nft_expr_priv(expr);
        val = cmp->data;
        op = NFT_CMP_EQ;
    }else{
        struct nft_cmp_expr *cmp = nft_expr_priv(expr);
        val = cmp->data.data[0];
        op = cmp->op;
    }

    val = ntohl(val);
    *prefix_mask = ntohl(*prefix_mask);
    //Source and Dest Port are set in the same instruction
    if(f == SDPORT){
        data->range[SPORT][LOWDIM] = (u32)*((u16 *)&val+1);
        data->range[SPORT][HIGHDIM] = (u32)*((u16 *)&val+1);
        data->range[DPORT][LOWDIM] = (u32)*(u16 *)&val;
        data->range[DPORT][HIGHDIM] = (u32)*(u16 *)&val;
        return;
    }
    //If a rule provded a subnet mask
    if((f == SADDR || f == DADDR)&& *prefix_mask_set != 0){
        data->range[f][LOWDIM] = val + 1;
        data->range[f][HIGHDIM] = val + ~(*prefix_mask);
        *prefix_mask = 0;
        *prefix_mask_set = 0;
        return;
    }
    if(f == SPORT || f == DPORT)
        val = val >> 16;

    switch (op)
    {
        case NFT_CMP_EQ:
            data->range[f][LOWDIM] = val;
            data->range[f][HIGHDIM] = val;
            break;
        case NFT_CMP_LT:
            data->range[f][HIGHDIM] = val - 1;
            break;
        case NFT_CMP_LTE:
            data->range[f][HIGHDIM] = val;
            break;
        case NFT_CMP_GT:
            data->range[f][LOWDIM] = val + 1;
            break;
        case NFT_CMP_GTE:
            data->range[f][LOWDIM] = val;
            break;            
        default:
            break;
    }
}

static inline u32 nft_ra_bitwise(struct nft_expr *expr){
    struct nft_bitwise_fast_expr *priv= nft_expr_priv(expr);
    return priv->mask;
}

static void nft_ra_meta_cmp(struct nft_ra_info *data, struct nft_meta *meta, struct nft_expr *expr){
     struct nft_cmp_fast_expr *cmp = nft_expr_priv(expr);
    switch (meta->key)
    {
    case NFT_META_L4PROTO:
        data->range[PROTO][LOWDIM] = cmp->data;
        data->range[PROTO][HIGHDIM] = cmp->data;
        break;
    default:
        printk("Meta value not supported\n");
        BUG();
        break;
    }
}



void nft_construct_rule_data(struct nft_ra_info *data, struct nft_rule *rule){
    struct nft_expr *expr, *last;
    unsigned long e;

    struct nft_immediate_expr *imm;
    struct nft_meta *meta;
    u8 range_field;
    u32 prefix_mask;
    enum ra_state state = START;
    int prefix_mask_set = 0;
    range_field = UNKNOWN;
    prefix_mask = 0;

    data->range[SADDR][LOWDIM] = 0;
    data->range[SADDR][HIGHDIM] = 0xffffffff;
    data->range[DADDR][LOWDIM] = 0;
    data->range[DADDR][HIGHDIM] = 0xffffffff;
    data->range[SPORT][LOWDIM] = 0;
    data->range[SPORT][HIGHDIM] = 0xffff;
    data->range[DPORT][LOWDIM] = 0;
    data->range[DPORT][HIGHDIM] = 0xffff;
    //Default is all L4 Protocols are accepted
    data->range[PROTO][LOWDIM] = 0;
    data->range[PROTO][HIGHDIM] = 0xff;
    data->priority = rule->priority;

  

    nft_rule_for_each_expr(expr, last, rule){
        e = (unsigned long)expr->ops->eval;
        switch (state)
        {
        case NEXT_LOAD:
            if(e == (unsigned long)nft_immediate_eval){
                imm = nft_expr_priv(expr);
                //printk("immediate verdict  %u\n", imm->data.verdict.code);
                state = END;
                break;
            }
            fallthrough;
        case START:
            if(e == (unsigned long)nft_payload_eval){
                range_field = nft_ra_payload(expr, &prefix_mask, &prefix_mask_set);
                state = PAYLOAD_LOADED;
            }
            else if(e == (unsigned long)nft_meta_get_eval){
                meta = nft_expr_priv(expr);
                state = META_LOADED;
            }else{
                state = UNEXPECTED;
            }
            break;
        case PAYLOAD_LOADED:
            if(e == (unsigned long)nft_cmp_eval){
                /*for more complicated comparisons*/
                nft_ra_cmp(data, expr, range_field, 0, &prefix_mask, &prefix_mask_set);
                state = PAYLOAD_LOADED;
            }else if(expr->ops == &nft_cmp_fast_ops){
                nft_ra_cmp(data, expr, range_field, 1, &prefix_mask, &prefix_mask_set);
                state = NEXT_LOAD;
            }else if(expr->ops == &nft_bitwise_fast_ops){
                prefix_mask = nft_ra_bitwise(expr);
                prefix_mask_set = 1;
                state = PAYLOAD_LOADED;
            }else if(e == (unsigned long)nft_payload_eval){
                range_field = nft_ra_payload(expr, &prefix_mask, &prefix_mask_set);
                state = PAYLOAD_LOADED;
            }else if(e == (unsigned long)nft_meta_get_eval){
                meta = nft_expr_priv(expr);
                state = META_LOADED;
            }else{
                state = UNEXPECTED;
            }
            break;
        case META_LOADED:
            if(e == (unsigned long)nft_cmp_eval){
                state=UNEXPECTED;
            }else if(expr->ops == &nft_cmp_fast_ops){
                nft_ra_meta_cmp(data, meta, expr); //set protocol
                state = NEXT_LOAD;
            }else{
                state = UNEXPECTED;
            }
            break;

        case END:
            break;
        default:
            BUG();
            break;
        }
    }
    print_rule_info(data);

}
#endif
