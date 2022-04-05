add table filter
add chain filter INPUT {type filter hook prerouting priority 0;}
add rule ip filter INPUT ip saddr 5.251.93.61 ip daddr 252.139.31.220 tcp dport 1724  accept
add rule ip filter INPUT ip saddr 5.251.27.33 ip daddr 156.132.255.97 udp dport 32201  accept
add rule ip filter INPUT ip saddr 5.251.27.26 ip daddr 189.35.144.0/31 tcp dport 1526  accept
add rule ip filter INPUT ip saddr 5.251.27.24/31 ip daddr 151.96.179.97 tcp dport 20  accept
add rule ip filter INPUT ip saddr 5.251.27.92/31 ip daddr 215.223.99.176/31 tcp dport 1526  accept
add rule ip filter INPUT ip saddr 5.251.27.30/30 ip daddr 156.132.255.97 udp dport 32210-32219  accept
add rule ip filter INPUT ip saddr 5.251.26.0/23 ip daddr 79.184.122.234 tcp dport 27400  accept
add rule ip filter INPUT ip saddr 5.251.27.58/31 ip daddr 149.62.168.0/22 tcp dport 20  accept
add rule ip filter INPUT ip saddr 157.223.248.248/31 ip daddr 157.223.252.0/22 tcp dport 80  accept
add rule ip filter INPUT ip protocol tcp ip saddr 5.251.27.65 ip daddr 222.107.175.94  accept
add rule ip filter INPUT ip protocol tcp ip saddr 5.251.27.45 ip daddr 158.200.19.245  accept
add rule ip filter INPUT ip protocol tcp ip saddr 5.251.27.24-5.251.27.65 accept
add rule ip filter INPUT ip saddr 5.251.27.73 ip daddr 207.141.167.220  accept
add rule ip filter INPUT ip saddr 5.251.27.42 ip daddr 156.157.96.12  accept
add rule ip filter INPUT ip protocol tcp ip saddr 5.251.24.0/22 ip daddr 0.117.237.158  accept
add rule ip filter INPUT ip protocol tcp ip saddr 5.251.24.0/22 ip daddr 5.251.28.182  accept
add rule ip filter INPUT ip protocol tcp ip saddr 5.251.26.0/23 ip daddr 158.200.117.186/31  accept
add rule ip filter INPUT ip saddr 5.251.27.26 ip daddr 189.35.144.0/22  accept
add rule ip filter INPUT ip protocol tcp ip saddr 5.251.27.0/24 ip daddr 5.248.0.0/14  accept

