# selfAdjust-kernel-firewall
# Current State
## Generic implementations
- implemented versions
    - memoryless
    - storing dependency graph
      - *todo redesign* 
      - *todo detect and remove transitivity in graph*
- Only inserting rules at the end is supported
    - inserting algorithm with complexity O(n/2^2) can be found in the *sal_insert_algorithm* branch

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
  - in 5.10 version the variants can be chosen via menuconfig under Kernel Hacking => Self Adjusting List Configuration
  
- current restrictions of the analysis:
  - using sets in a rule is not supported
  - examples of **unsupported** field entries:
      - ip (s/d)addr {127.0.0.2, 127.0.0.125}
      - (tcp/udp) {80, 1337, 443}
    
- dependency check function is implemented (nf_tables_rule_compare.c)
  - priority field is added to `nft_rule` if the self-adjusting list is enabled in the config (V1 and V2)  
    - setting priorities manually:
      - a patched version of the front end is needed => see tools/nftables_patches
      - new rule syntax `nft add rule <table> <chain> <rule expressions> priority <number>`
    - setting priorities automatically
      - the rule handle (id of the rule) is used as priority
      - the priority is stored as an u64 which makes it possible to print the values in the bpf program. This is used to observe which rules were accessed.
        - bitfiels are not supported by bpf(see [Evaluation](#evaluation))

### Implementations
There are 3 Versions of the update mechanism:
- updating during rule evaluation(nft_access_rule() in nf_tables_core.c)
  - one global rule set => only one CPU can manipulate the rule set
  - one lock per chain, to ensure mutual exclusion
  - changes the order of rules in the global rule set
- defer work (schedule_swap() in nf_tables_core.c)
  - list update is not happening at the same the rule is evaluated
  - making use of work queues, the task of the list update is scheduled on a work queue
  - seems to have a big overhead
- One rule set per CPU
  - every CPU holds an array with pointer to the rule set and only updates the order of pointers in that array, when a rule is accessed
  - No locks required
  - Does not change the global rule set
- the different versions can be found in the branches main, defer work and multi-processor respectively.

### Evaluation
- generating rules and pcap traffic using [classbench](https://github.com/sebymiano/classbench-generators)
  - generated packets are turned into .pcap file with `classbench-to-pcap.py`
  - generated packets are turned into rules using `classbench-to-iptables.py` which creates a set of iptable rules
    - the classbench repository can be found as a submodule in `./tools`
  - these rules are then converted to nft rules using `iptables-to-nft.py` (find this in the tools dir)
    - writes the nft rules to a file
    
#### Setup
- two virtual machines are connected back to back
- traffic is replayed with tcpreplay and send from VM1 to VM2
- VM2 holds the rule set
- all rules accept the arrived packets
- the packets are sent back to VM1
- On VM1 the packets/second are measured using pktgen

#### BPF observer
- the value of the traversed nodes counter and the order of the elements can be observed using the bpf_observer.py program
  - everytime before a packet is evaluated it prints the current traversed_rule counter and the state of the list
    - the handles of the rules are printed to identify the position of a rule
  - `sudo python3 bpf_observer 1` 

- to record the accessed rule, the number of swaps, the number of traversed nodes, cpu_id, and the time spent for classification use `sudo python3 bpf_observer 2`
  - this stores these informations in a .csv file
  - a 0 in the *accessed rule* column indicates that no rule was accessed


