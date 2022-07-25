# sal_test_control
install these libraries

- libmnl `apt install libmnl-dev libmnl0`
- libnftnl `apt install libnftnl-dev libnftnl11`

# bpf_observer.py
to run bpf_observer:

`sudo apt install linux-headers-$(uname -r)`

`sudo apt install python3-bpfcc`

`sudo python3 bpf_observer.py`