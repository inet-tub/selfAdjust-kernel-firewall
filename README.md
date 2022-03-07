# selfAdjust-kernel-firewall
# Current State
## Generic implementations
- implemented versions
	- memoryless
	- storing dependecy graph
		- #todo detect and remove transitivity in graph
- Only inserting rules at the end is supported

## Kernel Code
### Analysis of the bytecode
- analysis is stored in a custom struct that is easier and faster to compare
- analysis is done when a rule gets inserted
- current restrictions:
	- only rules are supported that check for a specific port or ip address, but not ranges
	- examples of unsupported field entries:
		-  ip (s/d)addr 127.0.0.0/24
		- ip (s/d)addr 127.0.0.1 - 127.0.0.5 or {127.0.0.2, 127.0.0.125}
		- (tcp/udp) (s/d)port 80-85 or {80, 1337, 443}
- a first version of dependecy check function is implemented
	- the rule handle (id of the rule) is used as priority, because adding a priority field to a rule would require chaning the nft frontend
	- Is the ACTION of a rule relevant for dependency checks?
		- Can I assume if two rules have the same ACTION they can not be dependent?

- Proof of Concept implementation in kernel with locking
	- locking and updating during rule evaluation(current state)
	- Single core(?)
	- defer work ( #todo )
		- time of list update is not happening at the same the the rule is evaluated

- Evaluation:
	- generating rules and pcap traffic using [classbench](https://github.com/sebymiano/classbench-generators)
	- replay the traffic with tcpreplay => machines need to be connected on the same link
	- which metrics should be used? how to compare approaches? how to measure?
