#include "common.h"

TDATA(exec_mm_release_event_type,  // exec_mm_release
      TEMPTY);
BPF_PERF_OUTPUT(exec_mm_release_events);

int kprobe__exec_mm_release(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    struct exec_mm_release_event_type e = {};
    init_tdata(&e);
    exec_mm_release_events.perf_submit((void *)ctx, &e, sizeof(e));

    return 0;
}