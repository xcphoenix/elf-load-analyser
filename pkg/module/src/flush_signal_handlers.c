#include "common.h"

TDATA(flush_signal_handlers_event_type, TEMPTY);
BPF_PERF_OUTPUT(flush_signal_handlers_events);

int kprobe__flush_signal_handlers(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct flush_signal_handlers_event_type e = {};
    init_tdata(&e);
    flush_signal_handlers_events.perf_submit((void*)ctx, (void*)&e, sizeof(e));
    return 0;
}