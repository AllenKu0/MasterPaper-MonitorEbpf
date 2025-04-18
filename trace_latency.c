#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/pkt_cls.h>
#include <uapi/linux/in.h>

#define GTPU_PORT 2152
#define DEBUG_LEVEL 1
#define SOME_INFO 1

// key: packet hash / TEID, value: timestamp (ns)
BPF_HASH(gtpu_ingress_time, u32, u64);

// key: packet hash, value: processing time (ns)
BPF_HASH(gtpu_processing_time, u32, u64);

// struct mirror_config {
//     __u32 enable;
//     __u32 mirror_index; // cilium_vxlan
// };

// BPF_HASH(mirror_config_map, u32, struct mirror_config);

static inline int is_gtpu_packet(struct iphdr *ip, void *data, void *data_end) {
    struct ethhdr *eth = data;
    
    if ((void *)eth + sizeof(*eth) > data_end)
        return 0;

    // bpf_trace_printk("ETH proto: 0x%x\n", bpf_ntohs(eth->h_proto));
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;

    if ((void *)ip + sizeof(*ip) > data_end)
        return 0;

    // bpf_trace_printk("IP proto: %u\n", ip->protocol);
    if (ip->protocol != IPPROTO_UDP) {
        // bpf_trace_printk("is_gtpu_packet: not UDP protocol\n");
        return 0;
    }
        
    struct udphdr *udp = (void *)ip + sizeof(struct iphdr);

    if ((void *)udp + sizeof(struct udphdr) > data_end) {
        // bpf_trace_printk("is_gtpu_packet: memory out of bound \n");
        return 0;
    }
    // bpf_trace_printk("UDP dest: %u\n", bpf_ntohs(udp->dest));
   

    if (bpf_ntohs(udp->dest) == GTPU_PORT) {
        // bpf_trace_printk("is_gtpu_packet: is GTP-U Port\n");
        return 1;   
    }
        
    // bpf_trace_printk("is_gtpu_packet: not GTP-U Port\n");
    return 0;
}

int tc_ingress_info(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth = data;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    if (!is_gtpu_packet(ip, data, data_end))
        return TC_ACT_OK;

    u32 key = skb->hash;
    u64 ts = bpf_ktime_get_ns();
    gtpu_ingress_time.update(&key, &ts);

    if (DEBUG_LEVEL >= SOME_INFO)
        bpf_trace_printk("[Ingress] GTP-U packet timestamp saved: %u\n", key);

    // u32 cfg_key = 0;
    // struct mirror_config *cfg = mirror_config_map.lookup(&cfg_key);
    // if (cfg && cfg->enable) {
    //     int ret = bpf_clone_redirect(skb, cfg->mirror_index, 0);
    //     if (ret < 0 && DEBUG_LEVEL >= SOME_INFO)
    //         bpf_trace_printk("[Ingress] Mirror failed: %d (hash=%u)\n", ret, key);
    //     else
    //         bpf_trace_printk("[Mirror] GTP-U packet mirrored to ifindex=%d\n", cfg->mirror_index);
    // }

    return TC_ACT_OK;
}

int tc_egress_info(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth = data;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    if (!is_gtpu_packet(ip, data, data_end))
        return TC_ACT_OK;

    u32 key = skb->hash;
    u64 *start_ns = gtpu_ingress_time.lookup(&key);
    if (start_ns) {
        u64 now_ns = bpf_ktime_get_ns();
        u64 delta = now_ns - *start_ns;

        gtpu_processing_time.update(&key, &delta);
        gtpu_ingress_time.delete(&key);

        if (DEBUG_LEVEL >= SOME_INFO)
            bpf_trace_printk("[Egress] GTP-U packet delay = %llu ns (hash=%u)\n", delta, key);
    }

    return TC_ACT_OK;
}

