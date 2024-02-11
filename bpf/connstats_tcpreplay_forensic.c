#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include <stddef.h>
#include <string.h>

static __u64 fasthash_mix(__u64 h) {
	h ^= h >> 23;
	h *= 0x2127599bf4325c37ULL;
	h ^= h >> 47;
	return h;
}

__u64 fasthash64(const void *buf, __u64 len, __u64 seed)
{
	const __u64 m = 0x880355f21e6d1965ULL;
	const __u64 *pos = (const __u64 *)buf;
	const __u64 *end = pos + (len / 8);
	const unsigned char *pos2;
	__u64 h = seed ^ (len * m);
	__u64 v;

	while (pos != end) {
		v  = *pos++;
		h ^= fasthash_mix(v);
		h *= m;
	}

	pos2 = (const unsigned char*)pos;
	v = 0;

	switch (len & 7) {
	case 7: v ^= (__u64)pos2[6] << 48;
	case 6: v ^= (__u64)pos2[5] << 40;
	case 5: v ^= (__u64)pos2[4] << 32;
	case 4: v ^= (__u64)pos2[3] << 24;
	case 3: v ^= (__u64)pos2[2] << 16;
	case 2: v ^= (__u64)pos2[1] << 8;
	case 1: v ^= (__u64)pos2[0];
		h ^= fasthash_mix(v);
		h *= m;
	}

	return fasthash_mix(h);
}

struct packet_t {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8 protocol;
    bool syn;
    bool ack;
    bool fin;
    bool rst;
    uint64_t ts;
    //bool outbound;
    __u32 len;
    __u32 payload_size;
};
struct flow_tuple {
    struct in6_addr a_ip;
    struct in6_addr b_ip;
    __be16 a_port;
    __be16 b_port;
    __u8 protocol;
};
struct flow_metrics {
    struct flow_tuple flow_tuple;  
    __u32 packets_in;
    __u32 packets_out;
    __u64 bytes_in;
    __u64 payload_in;
    __u64 bytes_out;
    __u64 payload_out;
    __u64 ts_start;
    __u64 ts_current;
    __u8 fin_counter;
    __u8 flow_closed; // 0 flow open, 1 flow ended normally, 2 flow ended anormally
    bool syn_or_udp_to_rb;
};

struct flow_record {
    __u64 fhash;  
    struct flow_metrics metrics;
};

struct global_metrics {
    __u64 total_processedpackets; 
    __u64 total_tcpudppackets;
    __u64 total_tcppackets;
    __u64 total_udppackets;
    __u64 total_flows;
    __u64 total_tcpflows;
    __u64 total_udpflows;
    //__u64 total_hash_collisions; //agregado para pruebas de contar colisiones de hash
};

bool syndidntfitsentrb = false;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);    
} pipe SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 24);
    __type(key, __u64);
    __type(value, struct flow_metrics);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} flowstracker SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
//     __uint(max_entries, 1 << 24);
//     __type(key, __u64);
//     __type(value, struct flow_metrics);
//     __uint(map_flags, BPF_F_NO_PREALLOC);
// } flowstracker SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1 );
    __type(key, __u32);
    __type(value, struct global_metrics); // cambiar por una nueva struct que contenga las metricas glbaes
} globalmetrics SEC(".maps");

//para rastrear los flujos y hashs
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 1 << 24);
//     __type(key, struct flow_tuple);
//     __type(value, __u64);
//     __uint(map_flags, BPF_F_NO_PREALLOC);
// } flow_hash_map SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 1 << 24);
//     __type(key, struct flow_tuple);
//     __type(value, __u64);
//     __uint(map_flags, BPF_F_NO_PREALLOC);
// } hash_collisions_map SEC(".maps");

static inline int handle_ip_packet(uint8_t* head, uint8_t* tail, uint32_t* offset, struct packet_t* pkt) {
    struct ethhdr* eth = (void*)head;
    struct iphdr* ip;
    struct ipv6hdr* ipv6;

    switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
        *offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

        if (head + (*offset) > tail) { // If the next layer is not IP, let the packet pass
            return TC_ACT_OK;
        }

        ip = (void*)head + sizeof(struct ethhdr);

        if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
            return TC_ACT_OK;
        }

        // Create IPv4-Mapped IPv6 Address
        pkt->src_ip.in6_u.u6_addr32[3] = ip->saddr;
        pkt->dst_ip.in6_u.u6_addr32[3] = ip->daddr;

        // Pad the field before IP address with all Fs just like the RFC
        pkt->src_ip.in6_u.u6_addr16[5] = 0xffff;
        pkt->dst_ip.in6_u.u6_addr16[5] = 0xffff;

        pkt->protocol = ip->protocol;

        return 1; // We have a TCP or UDP packet!

    case ETH_P_IPV6:
        *offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

        if (head + (*offset) > tail) {
            return TC_ACT_OK;
        }

        ipv6 = (void*)head + sizeof(struct ethhdr);

        if (ipv6->nexthdr != IPPROTO_TCP && ipv6->nexthdr != IPPROTO_UDP) {
            return TC_ACT_OK;
        }

        pkt->src_ip = ipv6->saddr;
        pkt->dst_ip = ipv6->daddr;

        pkt->protocol = ipv6->nexthdr;

        return 1; // We have a TCP or UDP packet!

    default:
        return TC_ACT_OK;
    }
}

static inline int handle_ip_segment(uint8_t* head, uint8_t* tail, uint32_t* offset, struct packet_t* pkt) {
    struct tcphdr* tcp;
    struct udphdr* udp;

    switch (pkt->protocol) {
    case IPPROTO_TCP:
        tcp = (void*)head + *offset;
        *offset += tcp->doff * 4; // Actualizar el offset con el tamaño de la cabecera TCP

        pkt->src_port = tcp->source;
        pkt->dst_port = tcp->dest;
        pkt->syn = tcp->syn;
        pkt->ack = tcp->ack;
        pkt->fin = tcp->fin;
        pkt->rst = tcp->rst;
        pkt->ts = bpf_ktime_get_ns();

        return 1;

    case IPPROTO_UDP:
        udp = (void*)head + *offset;
        *offset += sizeof(struct udphdr); // Actualizar el offset con el tamaño de la cabecera UDP

        pkt->src_port = udp->source;
        pkt->dst_port = udp->dest;
        pkt->ts = bpf_ktime_get_ns();

        return 1;

    default:
        return TC_ACT_OK;
    }
}

static inline int ipv6_addr_cmp(struct in6_addr *a, struct in6_addr *b) {
    for (int i = 0; i < 4; i++) {
        if (a->s6_addr32[i] < b->s6_addr32[i])
            return -1;
        else if (a->s6_addr32[i] > b->s6_addr32[i])
            return 1;
    }
    return 0;
}

static inline void normalize_flow_id(struct flow_tuple *flow) {
    if (ipv6_addr_cmp(&flow->a_ip, &flow->b_ip) > 0 ||
        (ipv6_addr_cmp(&flow->a_ip, &flow->b_ip) == 0 && flow->a_port > flow->b_port)) {
        struct in6_addr temp_ip = flow->a_ip;
        flow->a_ip = flow->b_ip;
        flow->b_ip = temp_ip;

        __be16 temp_port = flow->a_port;
        flow->a_port = flow->b_port;
        flow->b_port = temp_port;
    }
}

static inline __u64 calculate_flow_id_hash(struct flow_tuple *flow) {
    struct flow_tuple normalized_flow = *flow;
    normalize_flow_id(&normalized_flow);
    return fasthash64(&normalized_flow, sizeof(struct flow_tuple), 123456789); // use a seed of your choice
}

static inline bool are_equal(struct in6_addr a, struct in6_addr b) {
    return ((a.s6_addr32[0] == b.s6_addr32[0]) &&
            (a.s6_addr32[1] == b.s6_addr32[1]) &&
            (a.s6_addr32[2] == b.s6_addr32[2]) &&
            (a.s6_addr32[3] == b.s6_addr32[3]));
}

static inline int submit_flow_record(__u64 flowhash, struct flow_metrics *flowmetrics) {
    struct flow_record *record = (struct flow_record *)bpf_ringbuf_reserve(&pipe, sizeof(struct flow_record), 0);
    if (!record) {
        return TC_ACT_OK;
    }
    record->fhash = flowhash;
    record->metrics = *flowmetrics;
    bpf_ringbuf_submit(record, 0);
    return 0;
}

static inline int update_metrics(struct packet_t* pkt, struct global_metrics *globalm) {
    //update global metrics total_packets, total_tcp_packets, total_udp_packets 
    __u32 keygb = 0;
    globalm->total_tcpudppackets += 1;
    if (pkt->protocol == IPPROTO_TCP) {
        globalm->total_tcppackets += 1;
    } else {
        globalm->total_udppackets += 1;
    }
    bpf_map_update_elem(&globalmetrics, &keygb, globalm, BPF_ANY); 

    //conformando el flow id
    struct flow_tuple flowtuple = {0};
    flowtuple.a_ip = pkt->src_ip;
    flowtuple.b_ip = pkt->dst_ip;
    flowtuple.a_port = bpf_ntohs(pkt->src_port);
    flowtuple.b_port = bpf_ntohs(pkt->dst_port);
    flowtuple.protocol = pkt->protocol;
   
    __u64 flowhash = 0;
    flowhash = calculate_flow_id_hash(&flowtuple);

    //code for hash collision detection
    // __u64 new_hash = calculate_flow_id_hash(&flowtuple);
    // __u64 *stored_hash = bpf_map_lookup_elem(&flow_hash_map, &flowtuple);
    // if (stored_hash) {
    //     if (*stored_hash != new_hash) {
    //         // Hash collision detected
    //         // Handle the collision as needed, for example, by logging a message
    //         //aumentar un contador de hash collisions y guardar esta flowtuple y su hash en el mapa global metrics
    //         //update global metrics total_hash_collisions
    //         globalm->total_hash_collisions += 1;
    //         bpf_map_update_elem(&globalmetrics, &keygb, globalm, BPF_ANY);
    //         //guardar esta flowtuple y su hash en el mapa globalmetrics
    //         bpf_map_update_elem(&hash_collisions_map, &flowtuple, &new_hash, BPF_ANY);
    //     }
    // } else {
    //     // No entry for this flow tuple yet, add one
    //     bpf_map_update_elem(&flow_hash_map, &flowtuple, &new_hash, BPF_ANY);
    // }
    // __u64 flowhash = new_hash;

    struct flow_metrics *flowmetrics = bpf_map_lookup_elem(&flowstracker, &flowhash);
    if (flowmetrics != NULL) {
        //flow exists -> update metrics
        flowmetrics->ts_current = pkt->ts;
        if (are_equal(pkt->src_ip, flowmetrics->flow_tuple.a_ip)) { 
            flowmetrics->packets_out += 1;
            flowmetrics->bytes_out += pkt->len;
            flowmetrics->payload_out += pkt->payload_size;
        } else { //update ingress metrics
            flowmetrics->packets_in += 1;
            flowmetrics->bytes_in += pkt->len;
            flowmetrics->payload_in += pkt->payload_size;
        }
        if (pkt->fin == true && pkt->ack == true) { // FIN/ACK segment observed
            flowmetrics->fin_counter += 1;
        }

        //check if flow ended //consider flow ended, send to userspace to be deleted from hash map and flowtable
        //after 2 fin packets and 1 ack are received consider flow ended normally, or if rst packet recieved consider flow ended anormally, -> delete flow from map
        if (flowmetrics->fin_counter>=2 && pkt->ack == true && pkt->fin == false && pkt->syn == false && pkt->rst == false) { //flow ended normally  
            flowmetrics->flow_closed = 1;
        } else if (pkt->rst == true) { //flow ended anormally
            flowmetrics->flow_closed = 2;
        } else { //flow still open -> update hash map and return
            long ret = bpf_map_update_elem(&flowstracker, &flowhash, flowmetrics, BPF_EXIST);
            if (ret != 0) {
                //bpf_printk("error updating flow %d\n", ret);
                return TC_ACT_OK;
            }
            return TC_ACT_OK;
        }
        
        // flow ended, delete from hash map
        bpf_map_delete_elem(&flowstracker, &flowhash);
        //send to userspace to be deleted from flowtable and saved to log
        if (submit_flow_record(flowhash, flowmetrics) == TC_ACT_OK) {
            return TC_ACT_OK;
        }
        return TC_ACT_OK;

    } else {
        //flow doesn't exist, create new flow
        struct flow_metrics new_flowm = {0};
        new_flowm.flow_tuple = flowtuple;
        new_flowm.ts_start = pkt->ts;    
        new_flowm.ts_current = pkt->ts;
        new_flowm.packets_out = 1;
        new_flowm.bytes_out = pkt->len;
        new_flowm.payload_out = pkt->payload_size;
        
        if ((pkt->syn == true && pkt->ack == false) || (pkt->protocol == IPPROTO_UDP)) { //new tcp syn or udp connection, add to flowstracker map
        
            //update total flows global metrics
            globalm->total_flows += 1;
            if (pkt->protocol == IPPROTO_TCP) {
                globalm->total_tcpflows += 1;
            } else {
                globalm->total_udpflows += 1;
            }
            bpf_map_update_elem(&globalmetrics, &keygb, globalm, BPF_ANY); 

            //add to flowstracker hash map
            long ret = bpf_map_update_elem(&flowstracker, &flowhash, &new_flowm, BPF_NOEXIST);
            if (ret != 0) {
                //bpf_printk("error adding new flow %d\n", ret); 
                // //maybe because map is full -> send to userspace via ringbuf to avoid losing flows
                new_flowm.syn_or_udp_to_rb = true;
                if (submit_flow_record(flowhash, &new_flowm) == TC_ACT_OK) {
                    return TC_ACT_OK;
                }   
                //if tcp set syndidntfitsentrb to true
                if (pkt->protocol == IPPROTO_TCP) {
                    syndidntfitsentrb = true; // didnt fit, sent to userspace via ringbuf successfully        
                }    
            }
            //syndidntfitsentrb = false;
        } else{          
            //es un tcp no syn que no existe en el hashmap, 
            //enviar a userspace para revisar alla si pertenece a un flujo que se inicio en el userspace por el ringbuf
            //pero solo si ya se envio alguna vez un syn a userspace
            //ademas senalizarlo
            if (syndidntfitsentrb == true) {
                new_flowm.syn_or_udp_to_rb = false;
                if (submit_flow_record(flowhash, &new_flowm) == TC_ACT_OK) {
                    return TC_ACT_OK;
                }
            }            
        }
        return TC_ACT_OK;
    }
    //return TC_ACT_OK;
}

SEC("classifier/ingress")
int connstatsin(struct __sk_buff* skb) {

    if (bpf_skb_pull_data(skb, 0) < 0) {
        //bpf_trace_printk("Ingress: error pulling data\n", sizeof("Ingress: error pulling data\n"));
        return TC_ACT_OK;
    }
    //bpf_trace_printk("Ingress: Pulling data\n", sizeof("Ingress: Pulling data\n"));
    // Incrementar el contador de paquetes

    //update global metrics total_packets, total_tcp_packets, total_udp_packets 
    __u32 keygb = 0;
    struct global_metrics *globalm = bpf_map_lookup_elem(&globalmetrics, &keygb);
    if (!globalm) {
        struct global_metrics new_globalm = {0};
        new_globalm.total_processedpackets = 1;
        bpf_map_update_elem(&globalmetrics, &keygb, &new_globalm, BPF_ANY);
        globalm = &new_globalm;
    } else {
        globalm->total_processedpackets += 1;
        bpf_map_update_elem(&globalmetrics, &keygb, globalm, BPF_ANY); 
    }

    //Only process unicast packets
    // if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
    //     //bpf_trace_printk("Ingress: Packet is not unicast\n", sizeof("Ingress: Packet is not unicast\n"));
    //     return TC_ACT_OK;
    // }  

    uint8_t* head = (uint8_t*)(long)skb->data;     // Start of the packet data
    uint8_t* tail = (uint8_t*)(long)skb->data_end; // End of the packet data

    if (head + sizeof(struct ethhdr) > tail) { // Not an Ethernet frame
        //bpf_trace_printk("Ingress: Not an Ethernet frame\n",sizeof("Ingress: Not an Ethernet frame\n"));
        return TC_ACT_OK;
    }

    struct packet_t pkt = { 0 };  

    uint32_t offset = 0;

    pkt.len = skb->len;
    //pkt.outbound = false;

    if (handle_ip_packet(head, tail, &offset, &pkt) == TC_ACT_OK) {
        //bpf_trace_printk("Ingress: handle_ip_packet returned TC_ACT_OK\n", sizeof("Ingress: handle_ip_packet returned TC_ACT_OK\n"));
        return TC_ACT_OK;
    }

    // Check if TCP/UDP header is fitting this packet
    if (head + offset + sizeof(struct tcphdr) > tail || head + offset + sizeof(struct udphdr) > tail) {
        //bpf_trace_printk("Ingress: TCP/UDP header does not fit in this packet\n", sizeof("Ingress: TCP/UDP header does not fit in this packet\n"));
        return TC_ACT_OK;
    }

    if (handle_ip_segment(head, tail, &offset, &pkt) == TC_ACT_OK) {
        //bpf_trace_printk("Ingress: handle_ip_segment returned TC_ACT_OK\n", sizeof("Ingress: handle_ip_segment returned TC_ACT_OK\n"));
        return TC_ACT_OK;
    }

    // Después de procesar las cabeceras IP y TCP/UDP
    pkt.payload_size = skb->len - offset;

    if (update_metrics(&pkt, globalm) == TC_ACT_OK) {
        //bpf_trace_printk("Ingress: update_metrics returned TC_ACT_OK\n", sizeof("Ingress: update_metrics returned TC_ACT_OK\n"));
        return TC_ACT_OK;
    }

    //bpf_trace_printk("Ingress: Packet processed successfully\n", sizeof("Ingress: Packet processed successfully\n"));
    return TC_ACT_OK;
}

// SEC("classifier/egress")
// int connstatsout(struct __sk_buff* skb) {

//     if (bpf_skb_pull_data(skb, 0) < 0) {
//         //bpf_trace_printk("Egress: error pulling data\n", sizeof("Egress: error pulling data\n"));
//         return TC_ACT_OK;
//     }
//     //bpf_trace_printk("Egress: Pulling data\n", sizeof("Egress: Pulling data\n"));

//     __u32 keygb = 0;
//     struct global_metrics *globalm = bpf_map_lookup_elem(&globalmetrics, &keygb);
//     if (!globalm) {
//         struct global_metrics new_globalm = {0};
//         new_globalm.total_processedpackets = 1;
//         bpf_map_update_elem(&globalmetrics, &keygb, &new_globalm, BPF_ANY);
//         globalm = &new_globalm;
//     } else {
//         globalm->total_processedpackets += 1;
//         bpf_map_update_elem(&globalmetrics, &keygb, globalm, BPF_ANY); 
//     }

//     // We only want unicast packets
// //     if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
// //         //bpf_trace_printk("Egress: Packet is not unicast\n", sizeof("Egress: Packet is not unicast\n"));
// //         return TC_ACT_OK;
// //     }  

//     uint8_t* head = (uint8_t*)(long)skb->data;     // Start of the packet data
//     uint8_t* tail = (uint8_t*)(long)skb->data_end; // End of the packet data

//     if (head + sizeof(struct ethhdr) > tail) { // Not an Ethernet frame
//         //bpf_trace_printk("Egress: Not an Ethernet frame\n", sizeof("Egress: Not an Ethernet frame\n"));
//         return TC_ACT_OK;
//     }

//     struct packet_t pkt = { 0 };    

//     uint32_t offset = 0;

//     pkt.len = skb->len;
//     pkt.outbound = true;

//     if (handle_ip_packet(head, tail, &offset, &pkt) == TC_ACT_OK) {
//         //bpf_trace_printk("Egress: handle_ip_packet returned TC_ACT_OK\n", sizeof("Egress: handle_ip_packet returned TC_ACT_OK\n"));
//         return TC_ACT_OK;
//     }

//     // Check if TCP/UDP header is fitting this packet
//     if (head + offset + sizeof(struct tcphdr) > tail || head + offset + sizeof(struct udphdr) > tail) {
//         //bpf_trace_printk("Egress: TCP/UDP header does not fit in this packet\n", sizeof("Egress: TCP/UDP header does not fit in this packet\n"));
//         return TC_ACT_OK;
//     }

//     if (handle_ip_segment(head, tail, &offset, &pkt) == TC_ACT_OK) {
//         //bpf_trace_printk("Egress: handle_ip_segment returned TC_ACT_OK\n", sizeof("Egress: handle_ip_segment returned TC_ACT_OK\n"));
//         return TC_ACT_OK;
//     }

//     if (update_metrics(&pkt, globalm) == TC_ACT_OK) {
//         //bpf_trace_printk("Egress: update_metrics returned TC_ACT_OK\n", sizeof("Egress: update_metrics returned TC_ACT_OK\n"));
//         return TC_ACT_OK;
//     }

//     //bpf_trace_printk("Egress: Packet processed successfully\n", sizeof("Egress: Packet processed successfully\n"));
//     return TC_ACT_OK;
// }

char _license[] SEC("license") = "Dual MIT/GPL";
