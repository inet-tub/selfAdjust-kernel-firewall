from bcc import BPF
from bcc.utils import printb
import sys

prog = """
#include <net/netfilter/nf_tables.h>
#include <linux/types.h>
struct rule_handle_t{
	char ctrl;
	int a;
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
        atomic_t a;
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
       		data.handle = rule->priority;
       		trav_rules.perf_submit(ctx, &data, sizeof(data));
       		//bpf_trace_printk("%lu \\n", rule->cmp_data.priority);
       	}
       	
       	data.ctrl = 'e';
       	bpf_trace_printk("trav_rules %d \\n", chain->traversed_rules);
       	bpf_probe_read_kernel(&a, sizeof(int), &chain->traversed_rules);
       	data.a = atomic_read(&a); 
       	trav_rules.perf_submit(ctx, &data, sizeof(data));       	
       	
        return 0;
    }
"""


get_statistics = """
	#include <net/netfilter/nf_tables.h>
	struct rule_statistic {
		unsigned int handle;
		unsigned int swaps;
		unsigned int trav_nodes;
	};
	BPF_PERF_OUTPUT(statistics);
	
	void kprobe__nft_trace_packet(struct pt_regs *ctx, struct nft_traceinfo *info, const struct nft_chain *chain, const struct nft_rule *rule, enum nft_trace_types type){
		struct rule_statistic stats;
		if(info->enabled){
			bpf_trace_printk("Access: %u ,Swaps: %u trav_nodes %u\\n",info->rule_handle, info->swaps, info->trav_nodes);
			stats.handle = info->rule_handle;
			stats.swaps = info->swaps;
			stats.trav_nodes = info->trav_nodes;
			statistics.perf_submit(ctx, &stats,sizeof(stats)); 
		}
	}

"""




def print_trav_rules(cpu, data, size):
	out = ""
	rule_data = b["trav_rules"].event(data)
	if rule_data.ctrl == b's':
		out = "BEGIN "
	elif rule_data.ctrl == b'r':
		out += str(rule_data.handle) + " "
	elif rule_data.ctrl == b'e':
		out += "END\nTraversed Nodes: " + str(rule_data.a)
	print(out.strip())
	
def log(cpu, data, size):
	rule_stats = b["statistics"].event(data)
	out = f"{rule_stats.handle}	{rule_stats.swaps}	{rule_stats.trav_nodes}\n"
	f.write(out)
	f.flush()
	

def main():
	global b
	global f
	args = sys.argv
	if len(args) != 2:
		return
	if args[1] == "1":
		b = BPF(text=prog)
		b["trav_rules"].open_perf_buffer(print_trav_rules)
	elif args[1] == '2':
		f = open("stats.log", "a")
		f.write("ACCESS\tSWAPS\tTRAVERSED NODES\n")
		b = BPF(text=get_statistics)
		b["statistics"].open_perf_buffer(log)
	while 1:
		b.perf_buffer_poll()
		
if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		if(f):
			f.close()
	


# b.trace_print()
# prio = (unsigned long *)(((char *)rule) + sizeof(struct list_head));
# bpf_trace_printk("%p %d", (prio), i);
