import paramiko
import sys
import time
import multiprocessing
import os
import subprocess

remote_base_path="/home/kernel/firewall/rules_and_traces"
# rule_sets = ["acl1", "acl2", "acl3", "acl4", "acl5", "fw1", "fw2", "fw3", "fw4", "fw5", "ipc1", "ipc2"]
rule_sets = ["acl1", "acl2"]
# rule_sets = ["acl1"]
# rule_sizes = ["64", "128", "256", "512", "1024", "2048", "4096","6144", "8192"]
#rule_sizes = ["8192"]
rule_sizes = ["64", "128", "256", "512", "1024", "2048","4096", "8192"]
locality = ["0","10000"]
# locality = ["0"]
pktgen = "/opt/pktgen-21.11.0/Builddir/app/pktgen"
lua_script="/home/client/firewall/tools/measure_rx_pkts.lua"
measure_trav_nodes="/home/client/firewall/tools/tx_trav_nodes.lua"
pcap_file="/home/client/firewall/rules_and_traces/acl1/acl1_4096/acl1_seed-4096-10-0-100.trace.pcap"
exec_str=pktgen+' -- -T -P -m "2.[0], 3.[1]" -f '+lua_script+" -s 1:"
measure_trav_nodes_cmd=pktgen+' -- -T -P -m "2.[0], 3.[1]" -f '+measure_trav_nodes+" -s 1:"

def exec_bpf_observer(filename):
    print("Start Process "+filename);
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('192.168.122.13', username='root', password='a')
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo python3 /home/kernel/firewall/selfAdjustingList_kernel/sal_test_suite/bpf_observer.py 2 '+filename)# > /dev/null 2>&1')
    print(ssh_stdout.read().decode('UTF-8'))
    print(ssh_stderr.read().decode('UTF-8'))


def get_pcap_filename(rule_set, size, locality,run):
    base = "/home/client/firewall/rules_and_traces/"
    #return base+"acl1_only"+"/"+rule_set+"_seed-"+size+"-10-"+locality+"-100-"+str(run)+".trace.pcap"
    #return base+rule_set+"/"+rule_set+"_"+size+"/"+rule_set+"_seed-"+size+"-10-"+locality+"-100.trace.pcap"
    return base+"/traces/"+rule_set+"_seed-"+size+"-10-"+locality+"-100.trace.pcap"


def install_ruleset(ssh, rule, size, loc,run):
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft -f '+remote_base_path+'/'+rule+'/'+rule+'_'+size+'/*.nf')
    #ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft -f '+remote_base_path+'/acl1_only/nf/'+rule+'_seed-'+size+'-'+str(run)+'.rules.nf')
    print(ssh_stdout.read().decode('UTF-8'))
    print(ssh_stderr.read().decode('UTF-8'))
    time.sleep(1)

def remove_ruleset(ssh):
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft flush ruleset')
    time.sleep(2)


def run_ruleset_and_trace(ssh, rule, size, loc,run):
    
    install_ruleset(ssh, rule, size, loc,run)
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft -a list ruleset')
    sout=ssh_stdout.read().splitlines()
    sout=sout[len(sout)-3].split()
    rule_set_size = int(sout[len(sout)-1])-1 # -1 because the chain gets handle 1 rules start with handle num 2
    print(rule+" "+size)
    #input("Send data?")
    cmd=exec_str+get_pcap_filename(rule, size, loc,run)
    os.system(cmd)
    time.sleep(0.5)

    out_stats=open("stats.txt","r")
    pkts=out_stats.read()
    pkts_num = float(pkts)/10.0
    print(pkts_num)
    time.sleep(1)
    #input("Flush ruleset")
    remove_ruleset(ssh)
    #ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft list ruleset')
    return rule_set_size, pkts_num


def measure_pkts(ssh):
    for run in range(0,10):
        for loc in locality:
            fail_count=0
            outfile="nf_tables_per_cpu-"+loc+"_"+str(run)+"_small_rulesets.csv"
            of=open(outfile,"w")
            #of.write("size,acl1,acl2,acl3,acl4,acl5,fw1,fw2,fw3,fw4,fw5,ipc1,ipc2\n")
            #of.write("acl1_s,acl1,acl2_s,acl2,acl3_s,acl3,acl4_s,acl4,acl5_s,acl5,fw1_s,fw1,fw2_s,fw2,fw3_s,fw3,fw4_s,fw4,fw5_s,fw5,ipc1_s,ipc1,ipc2_s,ipc2\n")
            of.write("acl1_s,acl1\n")
            for size in rule_sizes:
                for rule in rule_sets:
                   
                    # sometimes pktgen does not send or capture traffic - in that case try to run it again
                    rule_set_size, pkts_num=run_ruleset_and_trace(ssh,rule,size,loc,run)
                    while pkts_num < 500 and fail_count < 3:
                        rule_set_size, pkts_num=run_ruleset_and_trace(ssh,rule,size,loc,run)
                        fail_count += 1	
                    fail_count = 0

                    of.write(str(rule_set_size))
                    of.write(","+str(pkts_num))
                    if rule not in "ipc2":
                        of.write(",")
                    
                    #input("Flush ruleset!")
                    #ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft flush ruleset')
                    #ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('nft list ruleset')
                    remove_ruleset(ssh)
                of.write("\n")
            of.close()


def measure_traversed_nodes(ssh):
    for run in range(0,4):
        for loc in locality:
            for size in rule_sizes:
                for rule in rule_sets:
                    bpf = multiprocessing.Process(target=exec_bpf_observer, args=("per_cpu-"+rule+"-"+size+"-"+loc+"_"+str(run),))
                    bpf.start()
                    time.sleep(2)
                    install_ruleset(ssh, rule, size, loc,run)
                    cmd=measure_trav_nodes_cmd+get_pcap_filename(rule,size,loc,run)
                    os.system(cmd)
                    time.sleep(2)
                    bpf.terminate()
                    ssh.exec_command("sudo pkill python3")
                    time.sleep(3)
                    remove_ruleset(ssh)
    
                




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
    if sys.argv[1] == "1":
        measure_pkts(ssh)
    elif sys.argv[1] == "2":
        measure_traversed_nodes(ssh)


if __name__=='__main__':
    main()

