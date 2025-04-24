#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// === const ===
// L2
#define ETH_SRC_OFF offsetof(struct ethhdr, h_source)
#define ETH_DST_OFF offsetof(struct ethhdr, h_dest)
// L3
#define IP_HLEN sizeof(struct iphdr)
#define IP_SRC_OFF ETH_HLEN + offsetof(struct iphdr, saddr)
#define IP_DST_OFF ETH_HLEN + offsetof(struct iphdr, daddr)
#define IP_CSUM_OFFSET ETH_HLEN + offsetof(struct iphdr, check)
// L4
#define TCP_HLEN sizeof(struct tcphdr)
#define UDP_HLEN sizeof(struct udphdr)
#define ICMP_HLEN sizeof(struct icmphdr)
#define TCP_CSUM_OFF ETH_HLEN + IP_HLEN + offsetof(struct tcphdr, check)
#define UDP_CSUM_OFF ETH_HLEN + IP_HLEN + offsetof(struct udphdr, check)

// Debug
#define NO_INFO 0
#define SOME_INFO 1
#define MORE_INFO 2
#define ALL_INFO 3

#ifndef DEBUG_LEVEL
// 0 -> No info
// 1 -> some info
// 2 -> more info
// 3 -> all info
#define DEBUG_LEVEL NO_INFO
#endif

#ifndef UTILS_H_
#define UTILS_H_

typedef struct interface Interface;

struct interface
{
    char name[10];
    const unsigned int ifnum;
    unsigned char mac[ETH_ALEN];
    __be32 ipv4;
};

// === function ===
static __always_inline void echo_mac(struct ethhdr *eth_h)
{
    bpf_printk("Ether");
    bpf_printk("  Source[0]:      %02x", eth_h->h_source[0]);
    bpf_printk("  Source[1]:      %02x", eth_h->h_source[1]);
    bpf_printk("  Source[2]:      %02x", eth_h->h_source[2]);
    bpf_printk("  Source[3]:      %02x", eth_h->h_source[3]);
    bpf_printk("  Source[4]:      %02x", eth_h->h_source[4]);
    bpf_printk("  Source[5]:      %02x", eth_h->h_source[5]);
    bpf_printk("  Destination[0]: %02x", eth_h->h_dest[0]);
    bpf_printk("  Destination[1]: %02x", eth_h->h_dest[1]);
    bpf_printk("  Destination[2]: %02x", eth_h->h_dest[2]);
    bpf_printk("  Destination[3]: %02x", eth_h->h_dest[3]);
    bpf_printk("  Destination[4]: %02x", eth_h->h_dest[4]);
    bpf_printk("  Destination[5]: %02x", eth_h->h_dest[5]);
    bpf_printk("  Ether type: %04x", bpf_ntohs(eth_h->h_proto));
};

static __always_inline void echo_ipv4(struct iphdr *ip_h)
{
    bpf_printk("IP");
    bpf_printk("  From: %pI4", &ip_h->saddr);
    bpf_printk("  To:   %pI4", &ip_h->daddr);
    // bpf_printk("  saddr[0]: %d\n", ip_h->saddr & 0xFF);
    // bpf_printk("  saddr[1]: %d\n", (ip_h->saddr >> 8) & 0xFF);
    // bpf_printk("  saddr[2]: %d\n", (ip_h->saddr >> 16) & 0xFF);
    // bpf_printk("  saddr[3]: %d\n", (ip_h->saddr >> 24) & 0xFF);
    // bpf_printk("  daddr[0]: %d\n", ip_h->daddr & 0xFF);
    // bpf_printk("  daddr[1]: %d\n", (ip_h->daddr >> 8) & 0xFF);
    // bpf_printk("  daddr[2]: %d\n", (ip_h->daddr >> 16) & 0xFF);
    // bpf_printk("  daddr[3]: %d\n", (ip_h->daddr >> 24) & 0xFF);
};

static __always_inline void echo_tcp(struct tcphdr *tcp_h)
{
    bpf_printk("TCP");
    bpf_printk("  source port: %-5d", bpf_ntohs(tcp_h->source));
    bpf_printk("  dest port:   %-5d", bpf_ntohs(tcp_h->dest));
}

static __always_inline void echo_udp(struct udphdr *udp_h)
{
    bpf_printk("UDP");
    bpf_printk("  source port: %-5d", bpf_ntohs(udp_h->source));
    bpf_printk("  dest port:   %-5d", bpf_ntohs(udp_h->dest));
}

static __always_inline unsigned int snat(struct __sk_buff *skb, struct iphdr *ip_h, struct interface *from)
{
    // 我們有關 rp_filter
    if (DEBUG_LEVEL >= SOME_INFO)
        bpf_printk("- SNAT");
    unsigned int csum = 0;
    csum = bpf_csum_diff(&ip_h->saddr, 4, &from->ipv4, 4, csum);
    // ----- change L4 header -----
    if (ip_h->protocol == IPPROTO_TCP)
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, 0, csum, 0);
    else if (ip_h->protocol == IPPROTO_UDP)
        bpf_l4_csum_replace(skb, UDP_CSUM_OFF, 0, csum, 0);
    // ----- change L3 header -----
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &from->ipv4, 4, 0);
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, 0, csum, 0);
    // ----- change L2 header -----
    bpf_skb_store_bytes(skb, ETH_SRC_OFF, &from->mac, 6, 0);
    return csum;
};

static __always_inline unsigned int dnat(struct __sk_buff *skb, struct iphdr *ip_h, struct interface *to)
{
    if (DEBUG_LEVEL >= SOME_INFO)
        bpf_printk("- DNAT");
    unsigned int csum = 0;
    csum = bpf_csum_diff(&ip_h->daddr, 4, &to->ipv4, 4, csum);
    // ----- change L4 header -----
    if (ip_h->protocol == IPPROTO_TCP)
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, 0, csum, 0);
    else if (ip_h->protocol == IPPROTO_UDP)
        bpf_l4_csum_replace(skb, UDP_CSUM_OFF, 0, csum, 0);
    // ----- change L3 header -----
    bpf_skb_store_bytes(skb, IP_DST_OFF, &to->ipv4, 4, 0);
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, 0, csum, 0);
    // ----- change L2 header -----
    bpf_skb_store_bytes(skb, ETH_DST_OFF, &to->mac, 6, 0);
    return csum;
};

static __always_inline unsigned int fnat(struct __sk_buff *skb, struct iphdr *ip_h, struct interface *from, struct interface *to)
{
    if (DEBUG_LEVEL >= SOME_INFO)
        bpf_printk("- Full NAT");
    unsigned int csum = 0;
    csum = bpf_csum_diff(&ip_h->saddr, 4, &from->ipv4, 4, csum);
    csum = bpf_csum_diff(&ip_h->daddr, 4, &to->ipv4, 4, csum);
    // ----- change L4 header -----
    // if (ip_h->protocol == IPPROTO_TCP)
    //     bpf_l4_csum_replace(skb, TCP_CSUM_OFF, 0, csum, 0);
    if (ip_h->protocol == IPPROTO_UDP)
        bpf_l4_csum_replace(skb, UDP_CSUM_OFF, 0, csum, 0);
    // ----- change L3 header -----
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &from->ipv4, 4, 0);
    bpf_skb_store_bytes(skb, IP_DST_OFF, &to->ipv4, 4, 0);
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, 0, csum, 0);
    // BPF_F_PSEUDO_HDR
    // ----- change L2 header -----
    bpf_skb_store_bytes(skb, ETH_SRC_OFF, &from->mac, 6, 0);
    bpf_skb_store_bytes(skb, ETH_DST_OFF, &to->mac, 6, 0);
    return 0;
}

#endif