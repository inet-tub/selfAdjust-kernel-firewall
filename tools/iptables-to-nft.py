import os
import subprocess
import sys

def main():
    if len(sys.argv) != 2:
        print("iptables_to_nft <file from classbench_to_iptables>")
        sys.exit(1)

    nft_str = ""
    with open(sys.argv[1], "r") as f:
        for line in f.readlines():
            line = line.replace("iptables", "")
            line = line.strip()
            cmd = line.split()
            cmd = ['iptables-translate'] + cmd
            line = subprocess.check_output(cmd).decode("utf-8")            
            line = line.replace("nft", "").replace("counter","").lstrip()
            nft_str += line
    print(nft_str)


if __name__ == '__main__':
    main()
