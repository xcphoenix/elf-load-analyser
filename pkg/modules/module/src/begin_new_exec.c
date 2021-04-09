// https://elixir.bootlin.com/linux/v5.10.7/source/fs/exec.c#L1775

#include "common.h"

TDATA(begin_new_exec_event_type, 
); 
BPF_PERF_OUTPUT(begin_new_exec_events);

int kprobe__begin_new_exec(struct pt_regs* ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct begin_new_exec_event_type event = {};
    init_tdata(&event);
    begin_new_exec_events.perf_submit((void*)ctx, &event, sizeof(event));
    return 0;
}