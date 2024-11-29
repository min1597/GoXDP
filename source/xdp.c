//go:build ignore

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>

#define MAX_MAP_LPM_ENTRIES 10000
#define MAX_MAP_HASH_ENTRIES 10000

/* Key for lpm_trie */
union key_4 {
	__u32 b32[2];
	__u8 b8[8];
};


struct statusMapVal {
  __u64 src_packets;
  __u64 src_size_packets;
  __u64 dst_packets;
  __u64 dst_size_packets;
};

struct grehdr
{
  __be16 flags;
  __be16 protocol;
};


/* Map for trie implementation */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, 8);
	__uint(value_size, 1);
	__uint(max_entries, MAX_MAP_HASH_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} blocked_ipv4 SEC(".maps");

struct {
	//__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, MAX_MAP_HASH_ENTRIES);
	__type(key, __u32);
	__type(value, struct statusMapVal);
} status SEC(".maps");

SEC("xdp")
int firewall(struct xdp_md *ctx){
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 packet_size = ctx->data_end-ctx->data;
    // We need to parse the ethernet header
    struct ethhdr *ether = data;
    // Check if the Ethernet header is malformed
    if (data + sizeof(*ether) > data_end) {
      return XDP_ABORTED;
    }
    //Ethernet header is not malformed
    if (ether->h_proto != bpf_htons(ETH_P_IP)) { 
    // If not IPv4 Traffic, pass the packet
      return XDP_PASS;
    }
    //move data pointer to pass the ethernet header
    data += sizeof(*ether);
    //parse the IPv4 packet
    struct iphdr *ip = data;
    // Check if the IPv4 header is malformed
    if (data + sizeof(*ip) > data_end) {
      return XDP_ABORTED;
    }

		union key_4 srcKey;
			/* Look up in the trie for lpm */
		srcKey.b32[0] = 32;
		srcKey.b8[4] = ip->saddr & 0xff;
		srcKey.b8[5] = (ip->saddr >> 8) & 0xff;
		srcKey.b8[6] = (ip->saddr >> 16) & 0xff;
		srcKey.b8[7] = (ip->saddr >> 24) & 0xff;
    
    __u32 *src_pointer = bpf_map_lookup_elem(&blocked_ipv4, &srcKey);
    if (src_pointer != NULL){
      __be32 ip_src_addr = (*ip).saddr;
      struct statusMapVal *stats_element = bpf_map_lookup_elem(&status, &ip_src_addr);  
      if (stats_element != NULL){
          stats_element->src_packets += 1;
          stats_element->src_size_packets += packet_size;
      } else {
        struct statusMapVal newData;
        newData.src_packets = 1;
        newData.src_size_packets = packet_size;
        newData.dst_packets = 0;
        newData.dst_size_packets = 0;
        bpf_map_update_elem(&status, &ip_src_addr, &newData, BPF_ANY);

      }
      return XDP_DROP;
    }
		union key_4 dstKey;
			/* Look up in the trie for lpm */
		dstKey.b32[0] = 32;
		dstKey.b8[4] = ip->daddr & 0xff;
		dstKey.b8[5] = (ip->daddr >> 8) & 0xff;
		dstKey.b8[6] = (ip->daddr >> 16) & 0xff;
		dstKey.b8[7] = (ip->daddr >> 24) & 0xff;
    
    __u32 *dst_pointer = bpf_map_lookup_elem(&blocked_ipv4, &dstKey);
    if (dst_pointer != NULL){
      __be32 ip_dst_addr = (*ip).daddr;
      struct statusMapVal *stats_element = bpf_map_lookup_elem(&status, &ip_dst_addr);  
      if (stats_element != NULL){
          stats_element->dst_packets += 1;
          stats_element->dst_size_packets += packet_size;
      } else {
        struct statusMapVal newData;
        newData.src_packets = 0;
        newData.src_size_packets = 0;
        newData.dst_packets = 1;
        newData.dst_size_packets = packet_size;
        bpf_map_update_elem(&status, &ip_dst_addr, &newData, BPF_ANY);
      }
      return XDP_DROP;
    }

    if (ip && ip->protocol == 47) { // Protocol 47: GRE
      struct grehdr *greh = (void *)ip + sizeof(struct iphdr);

      // Validate GRE Header
      if (unlikely((void *)(greh + 1) > data_end)) {
        return XDP_DROP;
      }

      // Skip GRE Header
      ip = (void *)greh + sizeof(struct grehdr);

      // Validate next protocol header
      if (unlikely((void *)(ip + 1) > data_end)) {
        return XDP_DROP;
      }
      union key_4 srcKey;
        /* Look up in the trie for lpm */
      srcKey.b32[0] = 32;
      srcKey.b8[4] = ip->saddr & 0xff;
      srcKey.b8[5] = (ip->saddr >> 8) & 0xff;
      srcKey.b8[6] = (ip->saddr >> 16) & 0xff;
      srcKey.b8[7] = (ip->saddr >> 24) & 0xff;
      
      __u32 *src_pointer = bpf_map_lookup_elem(&blocked_ipv4, &srcKey);
      if (src_pointer != NULL){
        __be32 ip_src_addr = (*ip).saddr;
        struct statusMapVal *stats_element = bpf_map_lookup_elem(&status, &ip_src_addr);  
        if (stats_element != NULL){
            stats_element->src_packets += 1;
            stats_element->src_size_packets += packet_size;
        } else {
          struct statusMapVal newData;
          newData.src_packets = 1;
          newData.src_size_packets = packet_size;
          newData.dst_packets = 0;
          newData.dst_size_packets = 0;
          bpf_map_update_elem(&status, &ip_src_addr, &newData, BPF_ANY);

        }
        return XDP_DROP;
      }
      union key_4 dstKey;
        /* Look up in the trie for lpm */
      dstKey.b32[0] = 32;
      dstKey.b8[4] = ip->daddr & 0xff;
      dstKey.b8[5] = (ip->daddr >> 8) & 0xff;
      dstKey.b8[6] = (ip->daddr >> 16) & 0xff;
      dstKey.b8[7] = (ip->daddr >> 24) & 0xff;
      
      __u32 *dst_pointer = bpf_map_lookup_elem(&blocked_ipv4, &dstKey);
      if (dst_pointer != NULL){
        __be32 ip_dst_addr = (*ip).daddr;
        struct statusMapVal *stats_element = bpf_map_lookup_elem(&status, &ip_dst_addr);  
        if (stats_element != NULL){
            stats_element->dst_packets += 1;
            stats_element->dst_size_packets += packet_size;
        } else {
          struct statusMapVal newData;
          newData.src_packets = 0;
          newData.src_size_packets = 0;
          newData.dst_packets = 1;
          newData.dst_size_packets = packet_size;
          bpf_map_update_elem(&status, &ip_dst_addr, &newData, BPF_ANY);
        }
        return XDP_DROP;
      }
    }
    return XDP_PASS;
} 