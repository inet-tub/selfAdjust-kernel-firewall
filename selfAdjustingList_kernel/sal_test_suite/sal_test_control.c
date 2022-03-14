#include <linux/netlink.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <libnftnl/chain.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter.h>

#define NFT_MSG_GETTRAVNODES 25
#define NFT_MSG_RESETCHAIN 26


int main(){
    struct mnl_socket *nl;
    char buf [MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct nfgenmsg *genmsg;
    struct nlattr *attr;
    //uint32_t portid, type = NFTNL_OUTPUT_DEFAULT;
    struct nftnl_chain *t = NULL;
    int ret;
    int family;

    family = NFPROTO_IPV4;
    t = nftnl_chain_alloc();
    nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_RESETCHAIN, family, 0, 0);
    nftnl_chain_set_str(t, NFTNL_CHAIN_TABLE, "my_tab");
    nftnl_chain_set_str(t, NFTNL_CHAIN_NAME, "output_chain");
    nftnl_chain_nlmsg_build_payload(nlh, t);

    nl = mnl_socket_open(NETLINK_NETFILTER);
    mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
    //portid = mnl_socket_get_portid(nl);
    mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
    ret  = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    if(ret > 0){
        nlh =(void *) buf;
        printf("len: %u type: %hu, flags: %hu, nlmsg_seq: %u, portid: %u\n", nlh->nlmsg_len, nlh->nlmsg_type, nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid);
        genmsg = NLMSG_DATA(nlh);
        printf("family %u, version %d, res_id %d\n", genmsg->nfgen_family, genmsg->version, genmsg->res_id);
        attr = (void *) (genmsg + 1);
        uint32_t *nodes = (void *)(attr+1);
        //printf("len %hu type %hu %u\n", attr->nla_len, attr->nla_type, ntohl(*nodes));
        printf("len %hu type %hu %s\n", attr->nla_len, attr->nla_type, (char *)nodes);
    }

    mnl_socket_close(nl);
}