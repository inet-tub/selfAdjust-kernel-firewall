# selfAdjust-kernel-firewall
# Current State
## Generic implementations
- implemented versions
	- memoryless
	- storing dependency graph
		- *todo detect and remove transitivity in graph*
- Only inserting rules at the end is supported

## Kernel Code
### Analysis of the bytecode
- implementation of the memory-less version
- Memless V1
  - analysis is stored in a custom struct that is easier and faster to compare(struct nft_ra_info in include/net/netfilter/nf_tables.h)
  - analysis is done when a rule gets inserted
  - more memory is needed (sizeof(struct nft_ra_info) = 48 bytes per rule)
- Memless V2
  - does not store the extra `struct nft_ra_info` per rule
  - analysis of the bytecode is done during the rule_access => higher computation time
  
- current restrictions of the analysis:
  - using sets in a rule is not supported
  - examples of unsupported field entries:
      - ip (s/d)addr {127.0.0.2, 127.0.0.125}
      - (tcp/udp) {80, 1337, 443}
    
- dependency check function is implemented (nf_tables_rule_compare.c)
    - the rule handle (id of the rule) is used as priority, because adding a priority field to a rule would require changing the nft frontend
    - the priority is stored as an u64 which makes it possible to print the values in the bpf program. This is used to observe which swaps are performed.
      - bitfiels are not supported by bpf(see [Evaluation](#evaluation))

### implementation in kernel with locking
- locking and updating during rule evaluation(swap_in_place() in nf_tables_core.c)
- defer work (schedule_swap() in nf_tables_core.c)
    - time of list update is not happening at the same the rule is evaluated
        
### Evaluation:
- generating rules and pcap traffic using [classbench](https://github.com/sebymiano/classbench-generators)
  - generated packets are turned into .pcap file with `classbench-to-pcap.py`
  - generated packets are turned into rules using `classbench-to-iptables.py` which creates a set of iptable rules
  - these rules are then converted to nft rules using `iptables-to-nft.py` (find this in the tools dir)
    - the output comes in the form that can be used for a .nf script
- replay the traffic with tcpreplay => machines need to be connected on the same link/over the same bridge
  - for my setup(host and virtual box connected over vboxnet) the rate should not be higher than 10Mbps
- every chain holds a traversed_rules counter, which is an atomic_t
  - every time a rule is evaluated, the counter is increased
  - the counter and the order of rules can be reset using the sal_test_control.c program
    - to realize this a new message type was created for the nf_tables_api
    - the exchange of data is happening over netlink
    - the reset function will set the counter to 0 and put the order of the rules in the initial state
  - the value of the counter and the order of the elements can be observed using the bpf_observer.py program
    - everytime before a packet is evaluated it prints the current traversed_rule counter and the state of the list
      - the handles of the rules are printed to identify the position of a rule
