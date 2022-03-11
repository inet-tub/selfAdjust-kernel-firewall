#include <linux/netlink.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define NETLINK_NETFILTER 12
#define PAYLOAD 32
#define NFT_MSG_GETTRAVNODES 25
#define NFNL_SUBSYS_NFTABLES 10

    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    int sock_fd;
    struct msghdr msg;
    
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
    
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(PAYLOAD);
    nlh->nlmsg_flags |= NLM_F_REQUEST;
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES<<8) | NFT_MSG_GETTRAVNODES;
    nlh->nlmsg_pid = getpid();

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    sendmsg(sock_fd, &msg, 0);
    close(sock_fd);


}