// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2008 Patrick McHardy <kaber@trash.net>
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com/)
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/static_key.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_core.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_log.h>
#include <net/netfilter/nft_meta.h>
#include <linux/workqueue.h>

#ifdef CONFIG_SAL_GENERAL
#include <linux/list_mrf_extension.h>
#endif

#include <linux/preempt.h>

static noinline void __nft_trace_packet(struct nft_traceinfo *info,
					const struct nft_chain *chain,
					enum nft_trace_types type)
{
	const struct nft_pktinfo *pkt = info->pkt;
	if (!info->trace || !pkt->skb->nf_trace)
		return;

	info->chain = chain;
	info->type = type;

	nft_trace_notify(info);
}

//MyCode
//Made this noinline to hook into it via bpf
static noinline void nft_trace_packet(struct nft_traceinfo *info,
                                      const struct nft_chain *chain,
                                      const struct nft_rule *rule,
                                      enum nft_trace_types type)
{
#ifdef CONFIG_SAL_DEBUG
    if(info->enabled)
        info->enabled = false;
#endif
    if (static_branch_unlikely(&nft_trace_enabled)) {
        info->rule = rule;
        __nft_trace_packet(info, chain, type);
    }
}

static void nft_bitwise_fast_eval(const struct nft_expr *expr,
				  struct nft_regs *regs)
{
	const struct nft_bitwise_fast_expr *priv = nft_expr_priv(expr);
	u32 *src = &regs->data[priv->sreg];
	u32 *dst = &regs->data[priv->dreg];

	*dst = (*src & priv->mask) ^ priv->xor;
}

//removed static
#ifdef CONFIG_SAL_GENERAL
void nft_cmp_fast_eval(const struct nft_expr *expr,
			      struct nft_regs *regs)
#else //Normal
static void nft_cmp_fast_eval(const struct nft_expr *expr,
                       struct nft_regs *regs)
#endif
{
	const struct nft_cmp_fast_expr *priv = nft_expr_priv(expr);

	if (((regs->data[priv->sreg] & priv->mask) == priv->data) ^ priv->inv)
		return;
	regs->verdict.code = NFT_BREAK;
}

static bool nft_payload_fast_eval(const struct nft_expr *expr,
				  struct nft_regs *regs,
				  const struct nft_pktinfo *pkt)
{
	const struct nft_payload *priv = nft_expr_priv(expr);
	const struct sk_buff *skb = pkt->skb;
	u32 *dest = &regs->data[priv->dreg];
	unsigned char *ptr;

	if (priv->base == NFT_PAYLOAD_NETWORK_HEADER)
		ptr = skb_network_header(skb);
	else {
		if (!pkt->tprot_set)
			return false;
		ptr = skb_network_header(skb) + pkt->xt.thoff;
	}

	ptr += priv->offset;

	if (unlikely(ptr + priv->len > skb_tail_pointer(skb)))
		return false;

	*dest = 0;
	if (priv->len == 2)
		*(u16 *)dest = *(u16 *)ptr;
	else if (priv->len == 4)
		*(u32 *)dest = *(u32 *)ptr;
	else
		*(u8 *)dest = *(u8 *)ptr;
	return true;
}

DEFINE_STATIC_KEY_FALSE(nft_counters_enabled);

static noinline void nft_update_chain_stats(const struct nft_chain *chain,
					    const struct nft_pktinfo *pkt)
{
	struct nft_base_chain *base_chain;
	struct nft_stats __percpu *pstats;
	struct nft_stats *stats;

	base_chain = nft_base_chain(chain);

	rcu_read_lock();
	pstats = READ_ONCE(base_chain->stats);
	if (pstats) {
		local_bh_disable();
		stats = this_cpu_ptr(pstats);
		u64_stats_update_begin(&stats->syncp);
		stats->pkts++;
		stats->bytes += pkt->skb->len;
		u64_stats_update_end(&stats->syncp);
		local_bh_enable();
	}
	rcu_read_unlock();
}

struct nft_jumpstack {
	const struct nft_chain	*chain;
	struct nft_rule	*const *rules;
};

static void expr_call_ops_eval(const struct nft_expr *expr,
			       struct nft_regs *regs,
			       struct nft_pktinfo *pkt)
{
#ifdef CONFIG_RETPOLINE
	unsigned long e = (unsigned long)expr->ops->eval;
#define X(e, fun) \
	do { if ((e) == (unsigned long)(fun)) \
		return fun(expr, regs, pkt); } while (0)

	X(e, nft_payload_eval);
	X(e, nft_cmp_eval);
	X(e, nft_meta_get_eval);
	X(e, nft_lookup_eval);
	X(e, nft_range_eval);
	X(e, nft_immediate_eval);
	X(e, nft_byteorder_eval);
	X(e, nft_dynset_eval);
	X(e, nft_rt_get_eval);
	X(e, nft_bitwise_eval);
#undef  X
#endif /* CONFIG_RETPOLINE */
	expr->ops->eval(expr, regs, pkt);
}
#ifdef CONFIG_SAL_GENERAL
#ifdef CONFIG_SAL_DEFER_UPDATE
static unsigned int nft_access_rule(struct nft_chain *chain, struct nft_rule *matched_rule, bool genbit);
static void nft_sched_work(struct work_struct *work){
    struct nft_my_work_data *my_data;
    my_data = container_of(work, struct nft_my_work_data, my_work);
#ifdef CONFIG_SAL_LOCKING_ENABLE
        spin_lock(&my_data->chain->rules_lock);
#endif
    nft_access_rule(my_data->chain, my_data->rule, my_data->genbit);
#ifdef CONFIG_SAL_LOCKING_ENABLE
        spin_unlock(&my_data->chain->rules_lock);
#endif

    kfree(my_data);
}

static void nft_sched_access(struct nft_chain *chain, struct nft_rule *rule, bool genbit){
    struct nft_my_work_data *work;

    if(list_is_first(&rule->list, &chain->rules)){
       // printk("Matched rule is first - not scheduled\n");
        return;
    }
    work = kzalloc(sizeof(struct nft_my_work_data), GFP_KERNEL);
    work->chain = chain;
    work->rule = rule;
    work->genbit = genbit;

    INIT_WORK(&(work->my_work), nft_sched_work);
    if(!schedule_work(&(work->my_work))){
        printk(KERN_ALERT "nft: Rule access could not be scheduled\n");
    }
}

#endif // CONFIG_SAL_DEFER_WORK


static unsigned int nft_access_rule(struct nft_chain *chain, struct nft_rule *matched_rule, bool genbit){
	struct nft_rule *rule;
	struct nft_rule **rules;
	int i;
    unsigned int swaps;

	rule = list_entry(&chain->rules, struct nft_rule, list);
	if(list_is_first(&matched_rule->list, &rule->list)){
		return 0;
	}
	if (genbit)
		rules = rcu_dereference(chain->rules_gen_1);
	else
		rules = rcu_dereference(chain->rules_gen_0);

	swaps = list_access(&matched_rule->list, &chain->rules, &rule_compare);

	i=0;
	list_for_each_entry_continue(rule, &chain->rules, list) {
		rules[i++] = rule;
	}
    return swaps;
}
#endif

unsigned int
nft_do_chain(struct nft_pktinfo *pkt, void *priv)
{
    //MyCode - remove const
	struct nft_chain *chain = priv, *basechain = chain;
	const struct net *net = nft_net(pkt);
	struct nft_rule *const *rules;
    //MyCode - removed const
	struct nft_rule *rule;
	const struct nft_expr *expr, *last;
	struct nft_regs regs;
	unsigned int stackptr = 0;
	struct nft_jumpstack jumpstack[NFT_JUMP_STACK_SIZE];
	bool genbit = READ_ONCE(net->nft.gencursor);
	struct nft_traceinfo info;
#ifdef CONFIG_SAL_DEBUG
    unsigned int swaps;
    unsigned int trav_nodes = 0;
    info.enabled = false;
#endif
#ifdef CONFIG_SAL_LOCKING_ENABLE
    spin_lock(&chain->rules_lock);
#endif

	info.trace = false;
	if (static_branch_unlikely(&nft_trace_enabled))
		nft_trace_init(&info, pkt, &regs.verdict, basechain);
do_chain:
	if (genbit)
		rules = rcu_dereference(chain->rules_gen_1);
	else
		rules = rcu_dereference(chain->rules_gen_0);

next_rule:
	rule = *rules;
	regs.verdict.code = NFT_CONTINUE;
	for (; *rules ; rules++) {
	//MyCode
#ifdef CONFIG_SAL_DEBUG
		atomic_inc(&chain->traversed_rules);
        trav_nodes++;
#endif
		rule = *rules;
		nft_rule_for_each_expr(expr, last, rule) {
			if (expr->ops == &nft_cmp_fast_ops)
				nft_cmp_fast_eval(expr, &regs);
			else if (expr->ops == &nft_bitwise_fast_ops)
				nft_bitwise_fast_eval(expr, &regs);
			else if (expr->ops != &nft_payload_fast_ops ||
				 !nft_payload_fast_eval(expr, &regs, pkt))
				expr_call_ops_eval(expr, &regs, pkt);

			if (regs.verdict.code != NFT_CONTINUE)
				break;
		}

		switch (regs.verdict.code) {
		case NFT_BREAK:
			regs.verdict.code = NFT_CONTINUE;
			continue;
		case NFT_CONTINUE:
			nft_trace_packet(&info, chain, rule,
					 NFT_TRACETYPE_RULE);
			continue;
		}
		break;
	}

	switch (regs.verdict.code & NF_VERDICT_MASK) {
	case NF_ACCEPT:
	case NF_DROP:
	case NF_QUEUE:
	case NF_STOLEN:
#ifdef CONFIG_SAL_GENERAL
#ifdef CONFIG_SAL_DEBUG
		swaps = nft_access_rule(chain, rule, genbit);
        info.enabled = true;
        info.trav_nodes = trav_nodes;
        info.swaps = swaps;
        info.rule_handle = rule->handle;
        info.cpu = smp_processor_id();
#else
        nft_access_rule(chain, rule, genbit);
#endif
#else
#ifdef CONFIG_SAL_DEBUG
        info.enabled = true;
        info.trav_nodes = trav_nodes;
        info.swaps = 0;
        info.rule_handle = rule->handle;
        info.cpu = smp_processor_id();
#endif
#endif
		nft_trace_packet(&info, chain, rule,
				 NFT_TRACETYPE_RULE);
#ifdef CONFIG_SAL_LOCKING_ENABLE
            spin_unlock(&chain->rules_lock);
#endif
		return regs.verdict.code;
	}

	switch (regs.verdict.code) {
	case NFT_JUMP:
		if (WARN_ON_ONCE(stackptr >= NFT_JUMP_STACK_SIZE)){
#ifdef CONFIG_SAL_LOCKING_ENABLE
            spin_unlock(&chain->rules_lock);
#endif
            return NF_DROP;
        }
		jumpstack[stackptr].chain = chain;
		jumpstack[stackptr].rules = rules + 1;
		stackptr++;
		fallthrough;
	case NFT_GOTO:
		nft_trace_packet(&info, chain, rule,
				 NFT_TRACETYPE_RULE);

		chain = regs.verdict.chain;
		goto do_chain;
	case NFT_CONTINUE:
	case NFT_RETURN:
		nft_trace_packet(&info, chain, rule,
				 NFT_TRACETYPE_RETURN);
		break;
	default:
		WARN_ON(1);
	}

	if (stackptr > 0) {
		stackptr--;
		chain = jumpstack[stackptr].chain;
		rules = jumpstack[stackptr].rules;
		goto next_rule;
	}

#ifdef CONFIG_SAL_DEBUG
    info.enabled = true;
    info.swaps = 0;
    info.trav_nodes = trav_nodes;
    info.rule_handle = 0;
#endif

	nft_trace_packet(&info, basechain, NULL, NFT_TRACETYPE_POLICY);

	if (static_branch_unlikely(&nft_counters_enabled))
		nft_update_chain_stats(basechain, pkt);

#ifdef CONFIG_SAL_LOCKING_ENABLE
    spin_unlock(&chain->rules_lock);
#endif
	return nft_base_chain(basechain)->policy;
}
EXPORT_SYMBOL_GPL(nft_do_chain);

static struct nft_expr_type *nft_basic_types[] = {
	&nft_imm_type,
	&nft_cmp_type,
	&nft_lookup_type,
	&nft_bitwise_type,
	&nft_byteorder_type,
	&nft_payload_type,
	&nft_dynset_type,
	&nft_range_type,
	&nft_meta_type,
	&nft_rt_type,
	&nft_exthdr_type,
};

static struct nft_object_type *nft_basic_objects[] = {
#ifdef CONFIG_NETWORK_SECMARK
	&nft_secmark_obj_type,
#endif
};

int __init nf_tables_core_module_init(void)
{
	int err, i, j = 0;

	for (i = 0; i < ARRAY_SIZE(nft_basic_objects); i++) {
		err = nft_register_obj(nft_basic_objects[i]);
		if (err)
			goto err;
	}

	for (j = 0; j < ARRAY_SIZE(nft_basic_types); j++) {
		err = nft_register_expr(nft_basic_types[j]);
		if (err)
			goto err;
	}

	return 0;

err:
	while (j-- > 0)
		nft_unregister_expr(nft_basic_types[j]);

	while (i-- > 0)
		nft_unregister_obj(nft_basic_objects[i]);

	return err;
}

void nf_tables_core_module_exit(void)
{
	int i;

	i = ARRAY_SIZE(nft_basic_types);
	while (i-- > 0)
		nft_unregister_expr(nft_basic_types[i]);

	i = ARRAY_SIZE(nft_basic_objects);
	while (i-- > 0)
		nft_unregister_obj(nft_basic_objects[i]);
}
