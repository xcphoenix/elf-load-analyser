// https://elixir.bootlin.com/linux/v5.10.7/source/fs/exec.c#L1775

#include "common.h"

TDATA(begin_new_exec_event_type, TEMPTY);
BPF_PERF_OUTPUT(call_event);

int kprobe__bprm_execve(struct pt_regs* ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct begin_new_exec_event_type event = {};
    init_tdata(&event);
    call_event.perf_submit((void*)ctx, &event, sizeof(event));
    return 0;
}