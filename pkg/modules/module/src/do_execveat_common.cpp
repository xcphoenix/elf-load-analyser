#include <linux/fs.h>
#include <linux/sched.h>

#include "_dev.h"

struct exec_event {
    uint64_t ts;
    int fd;
    int flags;
    char filename[256];
};
BPF_PERF_OUTPUT(events);

int kprobe__do_execveat_common(struct pt_regs* ctx, int fd,
                               struct filename* filename, int flags) {
    // Returns the process ID in the lower 32 bits (kernel's view of the PID,
    // which in user space is usually presented as the thread ID),
    // and the thread group ID in the upper 32 bits (what user space often
    // thinks of as the PID). By directly setting this to a u32, we discard the
    // upper 32 bits.
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct exec_event event = {};
    bpf_probe_read_kernel(&(event.fd), sizeof(int), (void*)&fd);
    bpf_probe_read_kernel(&(event.flags), sizeof(int), (void*)&flags);
    bpf_probe_read_kernel_str(&(event.filename), sizeof(event.filename),
                              (void*)filename->name);
    uint64_t ns = bpf_ktime_get_ns();
    bpf_probe_read_kernel(&event.ts, sizeof(event.ts), (void*)(&ns));
    events.perf_submit((void*)ctx, (void*)&event, sizeof(event));
    return 0;
}