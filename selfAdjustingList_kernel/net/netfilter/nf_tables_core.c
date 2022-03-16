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
#include <linux/smp.h>
#include <linux/workqueue.h>
#include <linux/list_mrf_extension.h>


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

static inline void nft_trace_packet(struct nft_traceinfo *info,
				    const struct nft_chain *chain,
				    const struct nft_rule *rule,
				    enum nft_trace_types type)
{
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

	//printk("In: %s\n", __FUNCTION__);
	*dst = (*src & priv->mask) ^ priv->xor;
}

//MyCode
//removed static
void nft_cmp_fast_eval(const struct nft_expr *expr,
			      struct nft_regs *regs)
{

	const struct nft_cmp_fast_expr *priv = nft_expr_priv(expr);
	//printk("In: %s\n", __FUNCTION__);
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
	//printk("In: %s\n", __FUNCTION__);

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
void raise_counter(){
        volatile int i;

        for(i = 0; i < 10000000;){
		++i;
        }
	printk(KERN_INFO "Not important %d\n", i);
	printk("in raise counter sched_held %d lock_held %d\n", rcu_read_lock_sched_held(), rcu_read_lock_held());
}

void swap_in_place(struct nft_chain *chain, struct nft_rule *matched_rule, bool genbit){
	struct nft_rule *rule;
	struct nft_rule **old_rules;
	unsigned int num_of_rules;
	int i;
	num_of_rules = 0;
	printk("In: START %s\n",__FUNCTION__);
	spin_lock(&chain->rules_lock);
	rule = list_entry(&chain->rules, struct nft_rule, list);
	if(list_is_first(&matched_rule->list, &rule->list)){
		printk("Matched rule is first\n");
		spin_unlock(&chain->rules_lock);
		return;
	}
	list_for_each_entry_continue(rule, &chain->rules, list) {
		num_of_rules++;
	}
	list_access(&matched_rule->list, &chain->rules, &rule_compare);
	
	chain->rules_next = nf_tables_chain_alloc_rules(chain, num_of_rules);
	if(!chain->rules_next){
		printk("Memalloc failed\n");
		spin_unlock(&chain->rules_lock);
		return;
	}

	i=0;
	list_for_each_entry_continue(rule, &chain->rules, list) {
		chain->rules_next[i++] = rule;
	}
	chain->rules_next[i] = NULL;


	if(genbit){
		old_rules = rcu_dereference(chain->rules_gen_1);
		rcu_assign_pointer(chain->rules_gen_1, chain->rules_next);
	}else{
		old_rules = rcu_dereference(chain->rules_gen_0);
		rcu_assign_pointer(chain->rules_gen_0, chain->rules_next);
	}
    nf_tables_commit_chain_free_rules_old(old_rules);
	chain->rules_next = NULL;
	spin_unlock(&chain->rules_lock);
}

void schedule_swap(struct nft_chain *chain, struct nft_rule *rule, bool genbit){
	struct nft_my_work_data *work;
	
	spin_lock(&chain->rules_lock);
	if(list_is_first(&rule->list, &chain->rules)){
		printk("Matched rule is first - not scheduled\n");
		spin_unlock(&chain->rules_lock);
		return;
	}
	spin_unlock(&chain->rules_lock);
	work = kzalloc(sizeof(struct nft_my_work_data), GFP_KERNEL);
	work->chain = chain;
	work->rule = rule;
	work->genbit = genbit;

	INIT_WORK(&(work->my_work), swap_front_scheduled);
	if(!schedule_work(&(work->my_work))){
        printk("dropped\n");
		//printk("scheduled %u\n", work_scheduled);
	}
}

void swap_front_scheduled(struct work_struct *work){
	struct nft_my_work_data *my_data;
	my_data = container_of(work, struct nft_my_work_data, my_work);
	swap_in_place(my_data->chain, my_data->rule, my_data->genbit);

	kfree(my_data);
}

unsigned int
nft_do_chain(struct nft_pktinfo *pkt, void *priv)
{
	struct nft_chain *chain = priv, *basechain = chain;
	const struct net *net = nft_net(pkt);
	struct nft_rule *const *rules;
	const struct nft_rule *rule;
	const struct nft_expr *expr, *last;
	struct nft_regs regs;
	unsigned int stackptr = 0;
	struct nft_jumpstack jumpstack[NFT_JUMP_STACK_SIZE];
	bool genbit = READ_ONCE(net->nft.gencursor);
	struct nft_traceinfo info;

	//int cpu = smp_processor_id();
	//int my_counter = nf_tables_counter;
	//printk(KERN_INFO "start with coutner: %d cpu: %d\n", my_counter, cpu);
	//if(nf_tables_counter % 4 == 0)
	//	raise_counter();
	//printk(KERN_INFO "end of coutner: %d cpu: %d\n", my_counter, cpu);
	//nf_tables_counter += 1;
	//printk("in start nft_do_chain sched_held %d lock_held %d\n", rcu_read_lock_sched_held(), rcu_read_lock_held());
	
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
		atomic_inc(&chain->traversed_rules);
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
		//printk(KERN_INFO "Rule taken handle %lu\n", rule->handle);
		//schedule_swap(chain, rule, genbit);
		swap_in_place(chain, rule, genbit);
		nft_trace_packet(&info, chain, rule,
				 NFT_TRACETYPE_RULE);
		//printk("Returning from nft_do_chain %u\n", ++packet_counter);
		return regs.verdict.code;
	}

	switch (regs.verdict.code) {
	case NFT_JUMP:
		if (WARN_ON_ONCE(stackptr >= NFT_JUMP_STACK_SIZE))
			return NF_DROP;
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

	nft_trace_packet(&info, basechain, NULL, NFT_TRACETYPE_POLICY);

	if (static_branch_unlikely(&nft_counters_enabled))
		nft_update_chain_stats(basechain, pkt);
	//printk(KERN_INFO "No Rule matched\n");
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
