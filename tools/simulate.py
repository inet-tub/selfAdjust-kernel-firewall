import paramiko
import time
import multiprocessing
import os
import subprocess

remote_base_path="/home/kernel/firewall/rules_and_traces"
rule_sets = ["acl1", "acl2", "acl3", "acl4", "acl5", "fw1", "fw2", "fw3", "fw4", "fw5", "ipc1", "ipc2"]
rule_sizes = ["64", "128", "256", "512", "1024", "2048", "4096", "8192"]
#rule_sizes = ["4096", "8192"]
#rule_sizes = ["64", "128", "256", "512", "1024", "2048"]
locality = ["0","10", "1000", "10000"]
pktgen = "/opt/pktgen-21.11.0/Builddir/app/pktgen"
lua_script="/home/client/firewall/tools/measure_rx_pkts.lua"
pcap_file="/home/client/firewall/rules_and_traces/acl1/acl1_4096/acl1_seed-4096-10-0-100.trace.pcap"
exec_str=pktgen+' -- -T -P -m "2.[0], 3.[1]" -f '+lua_script+" -s 1:"

def exec_bpf_observer():
    print("Start Process");
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('192.168.122.13', username='root', password='a')
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo /home/kernel/firewall/selfAdjustingList_kernel/sal_test_suite/bpf_observer.py 2')# > /dev/null 2>&1')
    print(ssh_stdout.read().decode('UTF-8'))
    print(ssh_stderr.read().decode('UTF-8'))

def get_pcap_filename(rule_set, size, locality):
    base = "/home/client/firewall/rules_and_traces/"
    return base+rule_set+"/"+rule_set+"_"+size+"/"+rule_set+"_seed-"+size+"-10-"+locality+"-100.trace.pcap"


def run_ruleset_and_trace(ssh, rule, size, loc):

    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft -f '+remote_base_path+'/'+rule+'/'+rule+'_'+size+'/*.nf')
    print(ssh_stdout.read().decode('UTF-8'))
    print(ssh_stderr.read().decode('UTF-8'))
    time.sleep(0.5)

    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft -a list ruleset')
    sout=ssh_stdout.read().splitlines()
    sout=sout[len(sout)-3].split()
    rule_set_size = int(sout[len(sout)-1])-1 # -1 because the chain gets handle 1 rules start with handle num 2
    print(rule+" "+size)
    #input("Send data?")
    cmd=exec_str+get_pcap_filename(rule, size, loc)
    os.system(cmd)
    time.sleep(0.5)

    out_stats=open("stats.txt","r")
    pkts=out_stats.read()
    pkts_num = float(pkts)/10.0
    print(pkts_num)
    time.sleep(0.5)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft flush ruleset')
    #ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft list ruleset')
    return rule_set_size, pkts_num


def main():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('192.168.122.13', username='root', password='a')
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('/home/kernel/firewall/vm_setup_scripts/kernel/setup.sh')
    print("Execute Setup Script..")
    print(ssh_stdout.read())
    print(ssh_stderr.read())
#    sftp = ssh.open_sftp()
    fail_count = 0
    for run in range(0,1):
        for loc in locality:
            outfile="nf_tables_glob_lock-"+loc+"_"+str(run)+".csv"
            of=open(outfile,"w")
            #of.write("size,acl1,acl2,acl3,acl4,acl5,fw1,fw2,fw3,fw4,fw5,ipc1,ipc2\n")
            of.write("acl1_s,acl1,acl2_s,acl2,acl3_s,acl3,acl4_s,acl4,acl5_s,acl5,fw1_s,fw1,fw2_s,fw2,fw3_s,fw3,fw4_s,fw4,fw5_s,fw5,ipc1_s,ipc1,ipc2_s,ipc2\n")
            for size in rule_sizes:
                for rule in rule_sets:
                   
                    # sometimes pktgen does not send or capture traffic - in that case try to run it again
                    rule_set_size, pkts_num=run_ruleset_and_trace(ssh,rule,size,loc)
                    while pkts_num < 500 and fail_count < 3:
                        rule_set_size, pkts_num=run_ruleset_and_trace(ssh,rule,size,loc)
                        fail_count += 1
                    fail_count = 0

                    of.write(str(rule_set_size))
                    of.write(","+str(pkts_num))
                    if rule not in "ipc2":
                        of.write(",")
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft flush ruleset')
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft list ruleset')
                    print(ssh_stdout.read().decode('UTF-8'))
                      #  input("Continue")
                of.write("\n")
            of.close()


if __name__=='__main__':
    main()

