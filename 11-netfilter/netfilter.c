#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net_namespace.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vasiliy Mozhaev");
MODULE_DESCRIPTION("netfilter");
MODULE_VERSION("0.1");

static int banned_port = 0;
module_param(banned_port, int, 0644);
MODULE_PARM_DESC(banned_port, "tcp port to ban (0 = no ban)");

static struct nf_hook_ops nfho;

static unsigned int my_netfilter_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    if (!skb) {
        return NF_ACCEPT;
    }

    struct iphdr *ip_header = ip_hdr(skb);
    if (!ip_header || ip_header->protocol != IPPROTO_TCP) {
        return NF_ACCEPT;
    }

    struct tcphdr *tcp = tcp_hdr(skb);
    if (!tcp) {
        return NF_ACCEPT;
    }

    int dst_ip = ip_header->daddr;
    int src_ip = ip_header->saddr;
    int dst_port = ntohs(tcp->dest);
    int src_port = ntohs(tcp->source);

    pr_info("netfilter: %pI4:%u -> %pI4:%u\n", &src_ip, src_port, &dst_ip, dst_port);

    if (banned_port && dst_port == banned_port) {
        pr_info("netfilter: DROPPED %pI4:%u -> %pI4:%u\n", &src_ip, src_port, &dst_ip, dst_port);
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static int __init my_netfilter_init(void) {
    nfho.hook = my_netfilter_hook;
    nfho.hooknum = NF_INET_POST_ROUTING;
    nfho.pf = NFPROTO_IPV4;
    nfho.priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, &nfho)) {
        pr_err("netfilter: failed to register hook\n");
        return -ENODEV;
    }

    pr_info("netfilter: module was loaded\n");
    return 0;
}

static void __exit my_netfilter_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    pr_info("netfilter: module was unloaded\n");
}

module_init(my_netfilter_init);
module_exit(my_netfilter_exit);
