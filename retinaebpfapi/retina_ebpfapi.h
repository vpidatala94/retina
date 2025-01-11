#ifdef __cplusplus
extern "C"
{
#endif

#define CILIUM_MAP_PIN_PATH_PREFIX "/ebpf/global/"
#define CILIUM_METRICS_MAP "cilium_metrics"
#define CILIUM_EVENTS_MAP "cilium_events"

#define __u64 uint64_t
#define __u32 uint32_t
#define __u16 uint16_t
#define __u8 uint8_t
#define __be32 uint32_t
#define __be16 uint16_t
#define __be8 uint8_t
#define __s8 char

union v6addr {
    struct {
        __u32 p1;
        __u32 p2;
        __u32 p3;
        __u32 p4;
    };
    struct {
        __u64 d1;
        __u64 d2;
    };
    __u8 addr[16];
}__packed;

typedef uint8_t ipv6_address_t[16];
typedef struct _ip
{
    union
    {
        struct
        {
            uint32_t ip4;
            uint32_t pad1;
            uint32_t pad2;
            uint32_t pad3;
        } ip4;
        ipv6_address_t ip6;
    };
} ip;
typedef struct _trace_sock_notify_t
{
    uint8_t type;
    uint8_t xlate_point;
    ip dst_ip;
    uint16_t dst_port;
    uint64_t sock_cookie;
    uint64_t cgroup_id;
    uint8_t l4_proto;
    uint8_t ipv6 : 1;
    uint8_t pad : 7;
} trace_sock_notify_t;

typedef struct _metrics_map_key {
    __u8      reason;       /* 0: forwarded, >0 dropped */
    __u8      dir : 2,      /* 1: ingress 2: egress */
              pad : 6;
    __u16     line;         /* __MAGIC_LINE__ */
    __u8      file;         /* __MAGIC_FILE__, needs to fit __id_for_file */
    __u8    reserved[3];    /* reserved for future extension */
}metrics_map_key, *pmetrics_map_key;

typedef struct _metrics_map_value {
    __u64   count;
    __u64   bytes;
}metrics_map_value, *pmetrics_map_value;

#define NOTIFY_COMMON_HDR \
    __u8 type;            \
    __u8 subtype;         \
    __u16 source;         \
    __u32 hash;

#define NOTIFY_CAPTURE_HDR                          \
    NOTIFY_COMMON_HDR                               \
    __u32 len_orig; /* Length of original packet */ \
    __u16 len_cap;  /* Length of captured bytes */  \
    __u16 version;  /* Capture header version */

typedef struct _drop_notify_t
{
    NOTIFY_CAPTURE_HDR
        __u32 src_label;
    __u32 dst_label;
    __u32 dst_id; /* 0 for egress */
    __u16 line;
    __u8 file;
    __s8 ext_error;
    __u32 ifindex;
} drop_notify_t;

struct trace_notify {
    NOTIFY_CAPTURE_HDR
    __u32   src_label;
    __u32   dst_label;
    __u16   dst_id;
    __u8    reason;
    __u8    ipv6 : 1;
    __u8    pad : 7;
    __u32   ifindex;
    union {
        struct {
            __be32  orig_ip4;
            __u32   orig_pad1;
            __u32   orig_pad2;
            __u32   orig_pad3;
        };
        union v6addr orig_ip6;
    };
};

typedef int (*mapEnum_Callback)(
    _In_ void* key, 
    _In_ void* data,
    _In_ int dataLength
    );

typedef int (*ringBuffer_Callback)(
    _In_ void* data,
    _In_ size_t size
    );

DWORD
enumerate_cilium_metricsmap(
    _In_ mapEnum_Callback EnumCallback
    );

DWORD
register_cilium_eventsmap_callback(
    _In_ ringBuffer_Callback RingBufferCallback,
    _Out_ void** RingBuffer
    );

DWORD
unregister_cilium_eventsmap_callback(
    _In_ void* RingBuffer
    );

#ifdef __cplusplus
}
#endif
