#! /usr/bin/env python3
from bcc import BPF
from bcc.utils import printb
import sys
import time

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


    struct time_t {
        u64 time_ns;
        u64 pid;
    };


    struct rule_statistic {
        unsigned int handle;
        unsigned int swaps;
        unsigned int trav_nodes;
        unsigned int cpu;
        u64 time_ns;
        u64 time_ns_reorder;
    };

    BPF_PERF_OUTPUT(statistics);
    BPF_HASH(cache,u64,struct time_t);
    BPF_HASH(reorder,u64,struct time_t);

//to take the pid as a key should be okay, because measuring the evaluation time of a packet can be done with the one core configuration

    void start_time_measure(struct pt_regs *ctx){
        struct time_t tns;

        u64 cpu = bpf_get_smp_processor_id();
        tns.time_ns = bpf_ktime_get_ns();
        tns.pid=bpf_get_current_pid_tgid();
        cache.update(&cpu, &tns);
        //cache.update(&tns.pid, &tns);
    }

    void start_time_measure_reorder(struct pt_regs *ctx){
        struct time_t tns;
        u64 cpu = bpf_get_smp_processor_id();
        tns.time_ns = bpf_ktime_get_ns();
        tns.pid=bpf_get_current_pid_tgid();
        reorder.update(&cpu, &tns);
    }

    void stop_time_measure_reorder(struct pt_regs *ctx){
        struct time_t tns;
        struct time_t *start;
        u64 cpu = bpf_get_smp_processor_id();
        start = reorder.lookup(&cpu);
        tns.pid=0;
        tns.time_ns=0;
        if(start == NULL){
            tns.time_ns = 0;
            //bpf_trace_printk("NUL L\\n");
        }else{
            //bpf_trace_printk("NOT NUL L\\n");
            tns.time_ns = bpf_ktime_get_ns() - start->time_ns;
        }
        reorder.update(&cpu, &tns);
    }

    void trace_packet(struct pt_regs *ctx, struct nft_traceinfo *info, const struct nft_chain *chain, const struct nft_rule *rule, enum nft_trace_types type){
        struct rule_statistic stats;
        struct time_t tns;
        struct time_t *start;
        u64 cpu = bpf_get_smp_processor_id();
        tns.time_ns = bpf_ktime_get_ns(); 
        tns.pid = bpf_get_current_pid_tgid();
        if(info->enabled){
            //bpf_trace_printk("Access: %u ,Swaps: %u trav_nodes %u\\n",info->rule_handle, info->swaps, info->trav_nodes);
            stats.handle = info->rule_handle;
            stats.swaps = info->swaps;
            stats.trav_nodes = info->trav_nodes;
            stats.cpu = info->cpu;
            //start=cache.lookup(&tns.pid);
            start = cache.lookup(&cpu);
            if(start == NULL){
                stats.time_ns=0;
            }else{
                stats.time_ns = tns.time_ns - start->time_ns;
            }
            start = reorder.lookup(&cpu);
            if(start == NULL){
                stats.time_ns_reorder = 99;
            }else{
                stats.time_ns_reorder = start->time_ns;
            }
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
    out = f"{rule_stats.handle},{rule_stats.swaps},{rule_stats.trav_nodes},{rule_stats.cpu},{rule_stats.time_ns}\n"
    f.write(out)
    f.flush()

def log2(cpu, data, size):
    rule_stats = b["statistics"].event(data)
    out = f"{rule_stats.handle},{rule_stats.swaps},{rule_stats.trav_nodes},{rule_stats.cpu},{rule_stats.time_ns},{rule_stats.time_ns_reorder}\n"
    f.write(out)
    f.flush()


def print_usage():
    print("Usage: bpf_observer PROG\n"
          "PROG can be 1, 2 or 3\n"
          "1: hooks into nft_do_chain\n"
          "2: creates a csv file <name of .csv file> and records the rule-ID, swaps, traversed-nodes, cpu, classification time\n"
          "3: Like 2 but also records the reordering time")


def main():
    global b
    global f
    # TODO change this to argparse
    args = sys.argv
    if len(args) != 3:
        print_usage()
        return
    if args[1] == "1":
        b = BPF(text=prog)
        b["trav_rules"].open_perf_buffer(print_trav_rules)
    elif args[1] == '2':
        f = open(args[2]+".csv", "w")
        f.write("ACCESS,SWAPS,TRAVERSED-NODES,CPU,TIME(ns)\n")
        b = BPF(text=get_statistics)
        b.attach_kprobe(event="nft_do_chain", fn_name="start_time_measure")
        b.attach_kprobe(event="nft_trace_packet", fn_name="trace_packet")
        b["statistics"].open_perf_buffer(log)
    elif args[1] == '3':
        f = open(args[2]+".csv", "w")
        f.write("ACCESS,SWAPS,TRAVERSED-NODES,CPU,TIME(ns),REORDER(ns)\n")
        b = BPF(text=get_statistics)
        b.attach_kprobe(event="nft_do_chain", fn_name="start_time_measure")
        b.attach_kprobe(event="nft_trace_packet", fn_name="trace_packet")
        b.attach_kprobe(event="nft_access_rule", fn_name="start_time_measure_reorder")
        b.attach_kretprobe(event="nft_access_rule", fn_name="stop_time_measure_reorder")
        b["statistics"].open_perf_buffer(log2)
    else:
        print_usage()
        sys.exit(-1)
    while 1:
        b.perf_buffer_poll()
        #b.trace_print()
        

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        if(f):
            f.flush()
            time.sleep(3)
            f.close()
    


# b.trace_print()
# prio = (unsigned long *)(((char *)rule) + sizeof(struct list_head));
