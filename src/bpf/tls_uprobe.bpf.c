// clang-format off
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PAYLOAD_SIZE 4096

enum event_direction {
    DIR_INGRESS = 0, // SSL_read return
    DIR_EGRESS  = 1, // SSL_write entry
};

struct tls_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __u32 direction;
    __u32 len;
    __u8  data[MAX_PAYLOAD_SIZE];
};

struct active_ssl_read_t {
    const char *buf;
    __u64 start_ns;
    __s32 fd;
};

// Map to correlate SSL_read entry and return probes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64); // pid_tgid
    __type(value, struct active_ssl_read_t);
} active_reads SEC(".maps");

// Lock-free ring buffer for streaming events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); // 16 MB ring buffer
} tls_events SEC(".maps");

// Filter target PID (0 = trace all)
const volatile __u32 target_pid = 0;

// =========================================================================
// SSL_read Probes
// int SSL_read(SSL *ssl, void *buf, int num);
// =========================================================================

SEC("uprobe/SSL_read")
int BPF_UPROBE(uprobe_ssl_read_entry, void *ssl, const char *buf, int num) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (target_pid != 0 && pid != target_pid) {
        return 0;
    }

    struct active_ssl_read_t active = {};
    active.buf = buf;
    active.start_ns = bpf_ktime_get_ns();
    active.fd = -1; // To be extracted or updated

    bpf_map_update_elem(&active_reads, &pid_tgid, &active, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(uretprobe_ssl_read_return, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (target_pid != 0 && pid != target_pid) {
        return 0;
    }

    struct active_ssl_read_t *active = bpf_map_lookup_elem(&active_reads, &pid_tgid);
    if (!active) {
        return 0;
    }

    if (ret > 0) {
        struct tls_event_t *event = bpf_ring_buffer_reserve(&tls_events, sizeof(struct tls_event_t), 0);
        if (event) {
            event->timestamp_ns = active->start_ns;
            event->pid = pid;
            event->tid = (__u32)pid_tgid;
            event->fd = active->fd;
            event->direction = DIR_INGRESS;

            __u32 copy_len = ret > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : ret;
            event->len = ret;

            bpf_probe_read_user(event->data, copy_len, active->buf);
            bpf_ring_buffer_submit(event, 0);
        }
    }

    bpf_map_delete_elem(&active_reads, &pid_tgid);
    return 0;
}

// =========================================================================
// SSL_write Probes
// int SSL_write(SSL *ssl, const void *buf, int num);
// =========================================================================

SEC("uprobe/SSL_write")
int BPF_UPROBE(uprobe_ssl_write_entry, void *ssl, const char *buf, int num) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (target_pid != 0 && pid != target_pid) {
        return 0;
    }

    if (num > 0) {
        struct tls_event_t *event = bpf_ring_buffer_reserve(&tls_events, sizeof(struct tls_event_t), 0);
        if (event) {
            event->timestamp_ns = bpf_ktime_get_ns();
            event->pid = pid;
            event->tid = (__u32)pid_tgid;
            event->fd = -1;
            event->direction = DIR_EGRESS;

            __u32 copy_len = num > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : num;
            event->len = num;

            bpf_probe_read_user(event->data, copy_len, buf);
            bpf_ring_buffer_submit(event, 0);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
