#include "common.h"

TDATA(x__set_task_comm_event_type,  // __set_task_comm_event_type
      char comm[256];               // task comm
);
BPF_PERF_OUTPUT(x__set_task_comm_events);

int kprobe__x__set_task_comm(struct pt_regs *ctx, struct task_struct *tsk,
                             const char *buf) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    struct x__set_task_comm_event_type e = {};
    init_tdata(&e);
    bpf_probe_read_kernel_str((void *)&e.comm, sizeof(e.comm), (void *)buf);
    x__set_task_comm_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));

    return 0;
}
