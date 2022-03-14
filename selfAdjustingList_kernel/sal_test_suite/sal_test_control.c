#include <linux/netlink.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netfilter/nfnetlink.h>


#define NETLINK_NETFILTER 12
#define PAYLOAD 32
#define NFT_MSG_GETTRAVNODES 25
#define NFNL_SUBSYS_NFTABLES 10

    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;
    struct nfgenmsg genmsg;
    char * table_name = "my_tab";
    struct nlattr tab_n;
    
int main(){
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if(sock_fd < 0)
        return -1;

    memset(&src_addr, 0 , sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;

    memset(&genmsg, 0, sizeof(genmsg));
    genmsg.nfgen_family = AF_INET;

    memset(&tab_n, 0, sizeof(tab_n));
    tab_n.nla_type = 5;
    tab_n.nla_len = strlen(table_name);

    unsigned int payload = sizeof(struct nfgenmsg) + sizeof(struct nlattr) + tab_n.nla_len;
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(payload));
    memset(nlh, 0, NLMSG_SPACE(payload));
    nlh->nlmsg_len = NLMSG_SPACE(payload);
    nlh->nlmsg_flags |= NLM_F_REQUEST;
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES<<8) | NFT_MSG_GETTRAVNODES;
    nlh->nlmsg_pid = getpid();
    memcpy(NLMSG_DATA(nlh), &genmsg, sizeof(genmsg));
    memcpy(NLMSG_DATA(nlh)+sizeof(genmsg), &tab_n, sizeof(tab_n));
    strncpy(NLMSG_DATA(nlh)+ sizeof(genmsg)+ sizeof(tab_n), table_name, strlen(table_name));


    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    sendmsg(sock_fd, &msg, 0);
    close(sock_fd);


}