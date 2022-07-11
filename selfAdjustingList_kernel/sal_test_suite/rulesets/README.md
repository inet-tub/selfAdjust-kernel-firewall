# Test Rule Sets
## filters20
- contains 20 rules
- created using
``` bash
db_generator -bc acl1_seed 20 2 0.5 -0.1 testFilter20
python3 classbench-to-iptables.py -i testFilter20 -o ipt_rules_20 -n iptables -c INPUT -j ACCEPT
python3 iptables-to-nft.py ipt_rules_20 > nft_rules_20.nf
```