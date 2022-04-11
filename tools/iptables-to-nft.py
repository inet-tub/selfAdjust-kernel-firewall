import os
import subprocess
import sys

def main():
    if len(sys.argv) != 3:
        print("iptables_to_nft <file from classbench_to_iptables> <outputfile>")
        sys.exit(1)

    nft_str = "add table filter\nadd chain filter INPUT {type filter hook prerouting priority 0;}\n"
    with open(sys.argv[1], "r") as f:
        for line in f.readlines():
            line = line.replace("iptables", "")
            line = line.strip()
            cmd = line.split()
            cmd = ['iptables-translate'] + cmd
            line = subprocess.check_output(cmd).decode("utf-8")            
            line = line.replace("nft", "").replace("counter","").lstrip()
            nft_str += line
# print(nft_str)
    with open(sys.argv[2], "w") as f:
        f.write(nft_str)


if __name__ == '__main__':
    main()
