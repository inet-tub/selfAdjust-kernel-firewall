from bcc import BPF
from bcc.utils import printb
prog = """
#include <net/netfilter/nf_tables.h>
#include <linux/types.h>
    unsigned int kprobe__nft_do_chain(struct pt_regs *ctx, struct nft_pktinfo *pkt, void *priv) {
        const struct nft_chain *chain = priv;
        const struct net *net = pkt->xt.state->net;
        struct nft_rule *const *rules;
        const struct nft_rule *rule;
        unsigned long *prio;
        int genbit = net->nft.gencursor;
        int i = 0;
        bpf_trace_printk("Hello World %u \\n", chain->traversed_rules);
       	if(genbit){
       		bpf_trace_printk("genbit on\\n");
       		rules = chain->rules_gen_1;
       	}else{
       		bpf_trace_printk("genbit off\\n");
       		rules = chain->rules_gen_0;
       	}
       	rule = *rules;
       	for(i = 0; i < 2048 ;++i, ++rules){
       		rule = *rules;
       		if(!rule)
       			break; 
       		
       		bpf_trace_printk("%lu \\n", rule->cmp_data.priority);
       	}
       	       	
        return 0;
    }
"""
b = BPF(text=prog)
b.trace_print()
# prio = (unsigned long *)(((char *)rule) + sizeof(struct list_head));
# bpf_trace_printk("%p %d", (prio), i);
