from bcc import BPF
from bcc.utils import printb
prog = """
#include <net/netfilter/nf_tables.h>
#include <linux/types.h>
struct rule_handle_t{
	char ctrl;
	u64 handle;
};

BPF_PERF_OUTPUT(trav_rules);

    unsigned int kprobe__nft_do_chain(struct pt_regs *ctx, struct nft_pktinfo *pkt, void *priv) {
        const struct nft_chain *chain = priv;
        const struct net *net = pkt->xt.state->net;
        struct nft_rule *const *rules;
        const struct nft_rule *rule;
        unsigned long *prio;
        int genbit = net->nft.gencursor;
        int i = 0;
        struct rule_handle_t data;
        data.ctrl = 's';
        data.handle = 0;
        trav_rules.perf_submit(ctx, &data, sizeof(data));
         
        //bpf_trace_printk("Hello World %u \\n", chain->traversed_rules);
       	if(genbit){
       		//bpf_trace_printk("genbit on\\n");
       		rules = chain->rules_gen_1;
       	}else{
       		//bpf_trace_printk("genbit off\\n");
       		rules = chain->rules_gen_0;
       	}
       	
       	data.ctrl = 'r';
       	
       	rule = *rules;
       	for(i = 0; i < 2048 ;++i, ++rules){
       		rule = *rules;
       		if(!rule)
       			break; 
       		data.handle = rule->cmp_data.priority;
       		trav_rules.perf_submit(ctx, &data, sizeof(data));
       		//bpf_trace_printk("%lu \\n", rule->cmp_data.priority);
       	}
       	
       	data.ctrl = 'e';
       	bpf_probe_read_kernel(&data.handle, sizeof(int), &chain->traversed_rules); 
       	trav_rules.perf_submit(ctx, &data, sizeof(data));       	
       	
        return 0;
    }
"""
b = BPF(text=prog)

def print_trav_rules(cpu, data, size):
	out = ""
	rule_data = b["trav_rules"].event(data)
	if rule_data.ctrl == b's':
		out = "BEGIN "
	elif rule_data.ctrl == b'r':
		out += str(rule_data.handle) + " "
	elif rule_data.ctrl == b'e':
		out += "END\nTraversed Nodes: " + str(rule_data.handle)
	print(out.strip())

b["trav_rules"].open_perf_buffer(print_trav_rules)
while 1:
	b.perf_buffer_poll()

# b.trace_print()
# prio = (unsigned long *)(((char *)rule) + sizeof(struct list_head));
# bpf_trace_printk("%p %d", (prio), i);
