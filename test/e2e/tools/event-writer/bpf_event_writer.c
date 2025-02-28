#include "bpf_helpers.h"
#include "bpf_helper_defs.h"
#include "bpf_endian.h"
#include "xdp/ebpfhook.h"
#include "event_writer.h"

SEC (".maps")
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct five_tuple);
    __type(value, uint8_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 512 * 4096);
} five_tuple_map;

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint8_t);
    __type(value, struct filter);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 1);
} filter_map;

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, uint32_t);
    __type(value, struct trace_notify);
    __uint(max_entries, 1);
} trc_buffer;

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, uint32_t);
    __type(value, struct drop_notify);
    __uint(max_entries, 1);
} drp_buffer;

SEC(".maps")
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 512 * 4096);
} cilium_events;

SEC(".maps")
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct metrics_key);
	__type(value, struct metrics_value);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 512 * 4096);
} cilium_metrics;

void update_metrics(uint64_t bytes, uint8_t direction,
					uint8_t reason, uint16_t line, uint8_t file)
{
	struct metrics_value *entry, new_entry = {};
	struct metrics_key key = {};

	key.reason = reason;
	key.dir    = direction;
	key.line   = line;
	key.file   = file;

	entry = bpf_map_lookup_elem(&cilium_metrics, &key);
	if (entry) {
		entry->count += 1;
		entry->bytes += bytes;
	} else {
		new_entry.count = 1;
		new_entry.bytes = bytes;
		bpf_map_update_elem(&cilium_metrics, &key, &new_entry, 0);
	}
}

void create_trace_ntfy_event(struct trace_notify* trc_elm)
{
    memset(trc_elm, 0, sizeof(struct trace_notify));
    trc_elm->type       = CILIUM_NOTIFY_TRACE;
	trc_elm->subtype    = 0;
	trc_elm->source     = 0;
	trc_elm->hash       = 0;
	trc_elm->len_orig   = 128;
	trc_elm->len_cap    = 128;
	trc_elm->version    = 1;
	trc_elm->src_label	= 0;
	trc_elm->dst_label	= 0;
	trc_elm->dst_id		= 0;
	trc_elm->reason		= 0;
	trc_elm->ifindex	= 0;
	trc_elm->ipv6		= 0;
}

void create_drop_event(struct drop_notify* drp_elm)
{
    memset(drp_elm, 0, sizeof(struct drop_notify));
    drp_elm->type       = CILIUM_NOTIFY_DROP;
	drp_elm->subtype    = 0;
	drp_elm->source     = 0;
	drp_elm->hash       = 0;
	drp_elm->len_orig   = 128;
	drp_elm->len_cap    = 128;
	drp_elm->version    = 1;
	drp_elm->src_label	= 0;
	drp_elm->dst_label	= 0;
	drp_elm->dst_id		= 0;
	drp_elm->line		= 0;
    drp_elm->file		= 0;
    drp_elm->ext_error	= 0;
	drp_elm->ifindex	= 0;
}

int extract_five_tuple_info(void* data, int bytes_to_copy, struct five_tuple* tup) {
    struct ethhdr *eth;
    uint8_t present = 1;

    if (data == NULL || tup == NULL) {
        return 1;
    }

    if (bytes_to_copy < sizeof(struct ethhdr)) {
        return 1;
    }

    eth = data;
    if (eth->ethertype != htons(0x0800)) {
        return 1;
    }

    if (bytes_to_copy < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        return 1;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);

    // Only process TCP or UDP packets
    if (iph->protocol != 6 && iph->protocol != 17) {
        return 1;
    }

    tup->srcIP = htonl(iph->saddr);
    tup->dstIP = htonl(iph->daddr);
    tup->proto = iph->protocol;

    if (tup->proto == 6) {
        if (bytes_to_copy < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
            return 1;
        }

        struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        tup->srcprt = htons(tcph->source);
        tup->dstprt = htons(tcph->dest);
    }
    else if (tup->proto == 17) {
        if (bytes_to_copy < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr)) {
            return 1;
        }

        struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        tup->srcprt = htons(udph->source);
        tup->dstprt = htons(udph->dest);
    }
    return 0;
}

int
check_filter(struct filter* flt, struct five_tuple* tup) {
    if (flt == NULL || tup == NULL) {
        return 1;
    }

    if (flt->srcIP != 0 && flt->srcIP != tup->srcIP) {
        return 1;
    }

    if (flt->dstIP != 0 && flt->dstIP != tup->dstIP) {
        return 1;
    }

    if (flt->srcprt != 0 && flt->srcprt != tup->srcprt) {
        return 1;
    }

    if (flt->dstprt != 0 && flt->dstprt != tup->dstprt) {
        return 1;
    }

    return 0;
}

SEC("xdp")
int
event_writer(xdp_md_t* ctx) {

    return XDP_PASS;
}