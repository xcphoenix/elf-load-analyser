#include "common.h"

TDATA(cleanup_sighand_event_type, TEMPTY);
BPF_PERF_OUTPUT(cleanup_sighand_events);

int kprobe__x__cleanup_sighand(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct cleanup_sighand_event_type e = {};
    init_tdata(&e);
    cleanup_sighand_events.perf_submit((void*)ctx, (void*)&e, sizeof(e));
    return 0;
}