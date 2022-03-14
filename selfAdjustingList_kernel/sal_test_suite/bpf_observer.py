from bcc import BPF
from bcc.utils import printb
prog = """
#include <net/netfilter/nf_tables.h>
    unsigned int kprobe__nft_do_chain(struct pt_regs *ctx, struct nft_pktinfo *pkt, void *priv) {
        const struct nft_chain *chain = priv;
        bpf_trace_printk("Hello World %u \\n", chain->traversed_rules);
        return 0;
    }
"""

b = BPF(text=prog)
b.trace_print()
