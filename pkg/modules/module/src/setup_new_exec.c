#include "common.h"
#include <uapi/linux/resource.h>

TDATA(setup_new_exec_event_type,  // setup_new_exec
      u64 rlim_cur;
      u64 rlim_max;);

TDATA(setup_new_exec_ret_event_type,  // setup_new_exece_ret_event_type
      u64 task_size;);

BPF_PERF_OUTPUT(setup_new_exec_events);
BPF_PERF_OUTPUT(setup_new_exec_ret_events);

int kprobe__setup_new_exec(struct pt_regs *ctx, struct linux_binprm *bprm) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    struct setup_new_exec_event_type e = {};
    init_tdata(&e);
    e.rlim_cur = (u64)bprm->rlim_stack.rlim_cur;
    e.rlim_max = (u64)bprm->rlim_stack.rlim_cur;
    
    setup_new_exec_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));
    
    return 0;
}

int kretprobe__setup_new_exec(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    struct setup_new_exec_ret_event_type e = {};
    init_tdata(&e);
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    e.task_size = t->mm->task_size;
    
    setup_new_exec_ret_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));
    
    return 0;
}