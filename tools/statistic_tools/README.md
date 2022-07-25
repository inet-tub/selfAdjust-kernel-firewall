# sal_test_control
Requirements:
- libmnl `apt install libmnl-dev libmnl0`
- libnftnl `apt install libnftnl-dev libnftnl11`

To run sal_test_conrol:
`sudo ./sal_test_control <GET/RESET> <Table name> <chain name>`

# bpf_observer.py
Requirements:

`sudo apt install linux-headers-$(uname -r)`

`sudo apt install python3-bpfcc`

To run bpf_observer.py
`sudo python3 bpf_observer.py 1` to print all rules that are traversed during rule evaluation<br>
`sudo python3 bpf_observer.py 2 <file name>` to record rule-ID, swaps, traversed nodes, cpu, time in a .csv file<br>
`sudo python3 bpf_observer.py 3 <file name>` like the previous but in addition records the classification time<br>
