#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <linux/pkt_cls.h>
#include <uapi/linux/in.h>


#define GTPU_PORT 2152

struct mirror_config {
    __u32 enable;
    __u32 mirror_index; // cilium_vxlan
    __u32 mirror_dst_ip;
};

BPF_HASH(mirror_config_map, u32, struct mirror_config);
// 寫在宿主機綁CONTAINER網卡 並且轉道cilium_vxlan

static inline int is_gtpu_packet(struct iphdr *ip, void *data, void *data_end) {
    struct ethhdr *eth = data;
    
    if ((void *)eth + sizeof(*eth) > data_end)
        return 0;

    bpf_trace_printk("ETH proto: 0x%x\n", bpf_ntohs(eth->h_proto));
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;

    if ((void *)ip + sizeof(*ip) > data_end)
        return 0;

    bpf_trace_printk("IP proto: %u\n", ip->protocol);
    if (ip->protocol != IPPROTO_UDP) {
        bpf_trace_printk("is_gtpu_packet: not UDP protocol\n");
        return 0;
    }
        
    struct udphdr *udp = (void *)ip + sizeof(struct iphdr);

    if ((void *)udp + sizeof(struct udphdr) > data_end) {
        bpf_trace_printk("is_gtpu_packet: memory out of bound \n");
        return 0;
    }
    bpf_trace_printk("UDP dest: %u\n", bpf_ntohs(udp->dest));
   

    if (bpf_ntohs(udp->dest) == GTPU_PORT) {
        bpf_trace_printk("is_gtpu_packet: is GTP-U Port\n");
        return 1;   
    }
        
    bpf_trace_printk("is_gtpu_packet: not GTP-U Port\n");
    return 0;
}

int mirror_traffic(struct __sk_buff *skb) {
    u32 cfg_key = 0;
    struct mirror_config *cfg = mirror_config_map.lookup(&cfg_key);

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

    if (cfg && cfg->enable) {
        // 將封包鏡像到指定的介面（如 cilium_vxlan）
        int ret = bpf_clone_redirect(skb, cfg->mirror_index, 0);
        if (ret < 0) {
            bpf_trace_printk("Mirror failed: %d\n", ret);
        } else {
            bpf_trace_printk("Mirror success to ifindex %u\n", cfg->mirror_index);
        }

        // 修改目的 IP（若指定）
        if (cfg->mirror_dst_ip != 0) {
            __u32 old_ip = ip->daddr;
            __u32 new_ip = cfg->mirror_dst_ip;

            // 更新 checksum（忽略失敗處理）
            bpf_l3_csum_replace(skb, 
                offsetof(struct ethhdr, h_proto) + sizeof(struct iphdr) + offsetof(struct iphdr, check),
                old_ip, new_ip, sizeof(__u32));
            
            bpf_skb_store_bytes(skb, 
                offsetof(struct ethhdr, h_proto) + sizeof(struct iphdr) + offsetof(struct iphdr, daddr),
                &new_ip, sizeof(new_ip), 0);
        }
    }
    return TC_ACT_OK;
}