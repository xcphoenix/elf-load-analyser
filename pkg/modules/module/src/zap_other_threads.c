#include "common.h"

TDATA(zap_other_threads_event_type, TEMPTY);
BPF_PERF_OUTPUT(zap_other_threads_events);

int kprobe__zap_other_threads(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct zap_other_threads_event_type e = {};
    init_tdata(&e);
    zap_other_threads_events.perf_submit((void*)ctx, (void*)&e, sizeof(e));
    return 0;
}