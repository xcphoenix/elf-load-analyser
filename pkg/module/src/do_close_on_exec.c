#include "common.h"

TDATA(do_close_on_exec_event_type, TEMPTY);
BPF_PERF_OUTPUT(do_close_on_exec_events);

int kprobe__do_close_on_exec(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct do_close_on_exec_event_type e = {};
    init_tdata(&e);
    do_close_on_exec_events.perf_submit((void*)ctx, (void*)&e, sizeof(e));
    return 0;
}