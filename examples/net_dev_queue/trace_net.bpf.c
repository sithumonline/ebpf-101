// go:build ignore

#include "vmlinux.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_tracing.h"
#include "printk.bpf.h"

char LICENSE[] SEC("license") = "GPL";

const char program[16] = "attack_connect";

static inline bool is_program(char a[])
{
    int flag = 1, i = 0;
    while (a[i] != '\0' && program[i] != '\0')
    {
        if (a[i] != program[i])
        {
            flag = 0;
            break;
        }
        i++;
    }
    return flag;
}

static inline int
get_ip(struct sk_buff *skb)
{
    char *hdr_hdr;
    __u16 mac_hdr;
    __u16 net_hdr;

    bpf_core_read(&hdr_hdr, sizeof(hdr_hdr), &skb->head);
    bpf_core_read(&mac_hdr, sizeof(mac_hdr), &skb->mac_header);
    bpf_core_read(&net_hdr, sizeof(net_hdr), &skb->network_header);

    if (net_hdr == 0)
    {
        net_hdr = mac_hdr + 14 /* MAC header size */;
    }

    char *ipaddr = hdr_hdr + net_hdr;

    __u8 ip_vers;
    bpf_core_read(&ip_vers, sizeof(ip_vers), ipaddr);
    ip_vers = ip_vers >> 4 & 0xf;

    if (ip_vers == 4)
    {
        struct iphdr iph_hdr;
        bpf_core_read(&iph_hdr, sizeof(iph_hdr), ipaddr);

        return iph_hdr.daddr;
    }

    return -1;
}

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u32);
} net_dev_queue SEC(".maps");

SEC("tp/net/net_dev_queue")
int handle_net_dev_queue(struct trace_event_raw_net_dev_template *ctx)
{
    char comm[16];
    bpf_get_current_comm(comm, 16);

    if (is_program(comm))
    {
        int res = get_ip((struct sk_buff *)ctx->skbaddr);

        // print res
        // bpf_printk("tp/net/net_dev_queue: %d", res);

        if (res != -1)
        {
            if (full_printk)
            {
                bpf_printk("tp/net/net_dev_queue: %pI4", &res);
            }
            else
            {
                bpf_printk("tp/net/net_dev_queue: %d", res);
            }

            __u32 key = res;
            __u32 *val = bpf_map_lookup_elem(&net_dev_queue, &key);
            if (val)
            {
                __sync_fetch_and_add(val, 1);
            }
            else
            {
                __u32 initval = 1;
                bpf_map_update_elem(&net_dev_queue, &key, &initval, BPF_ANY);
            }
        }
    }
    return 0;
}