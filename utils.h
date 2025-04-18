#include <linux/if_ether.h>
#include <linux/ip.h>
// #include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
// #include <bpf/bpf_helpers.h>

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
    bpf_printk("TCP\n");
    bpf_printk("  source port: %-5d\n", bpf_ntohs(tcp_h->source));
    bpf_printk("  dest port:   %-5d\n", bpf_ntohs(tcp_h->dest));
}

static __always_inline void echo_udp(struct udphdr *udp_h)
{
    bpf_printk("UDP\n");
    bpf_printk("  source port: %-5d\n", bpf_ntohs(udp_h->source));
    bpf_printk("  dest port:   %-5d\n", bpf_ntohs(udp_h->dest));
}
