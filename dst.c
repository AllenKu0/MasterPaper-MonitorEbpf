#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/pkt_cls.h>
#include <uapi/linux/in.h>

#define GTPU_PORT 2152

int trace_gtpu_dst_ip(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + sizeof(*ip);
    if ((void *)udp + sizeof(*udp) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(udp->dest) != GTPU_PORT)
        return TC_ACT_OK;

    __u32 dst_ip = ip->daddr;

    // 印出目的 IP（最多三個格式符號）
    __u8 *s = (__u8 *)&ip->saddr;
    __u8 *d = (__u8 *)&ip->daddr;

    bpf_trace_printk("DST IP: %d.%d.%d\n", d[0], d[1], d[2]);
    bpf_trace_printk("DST IP LAST: %d\n", d[3]);

    return TC_ACT_OK;
}