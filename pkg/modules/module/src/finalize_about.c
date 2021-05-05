#include "common.h"

TDATA(finalize_exec_event_type,  // finalize_exec_event
      /*
       * after create_elf_tables
       */
      u64 end_code;     // end_code
      u64 start_code;   // start_code
      u64 end_data;     // end_data
      u64 start_data;   // start_data
      u64 start_stack;  // start_stack
);
BPF_PERF_OUTPUT(finalize_exec_events);

TDATA(start_thread_event_type,  // start_thread_event
      u64 entry;                // new_ip
      u64 new_sp;               // sp
);
BPF_PERF_OUTPUT(start_thread_events);

int kprobe__finalize_exec(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    struct finalize_exec_event_type e = {};
    init_tdata(&e);

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    if (t) {
        e.end_code    = (u64)t->mm->end_code;
        e.start_code  = (u64)t->mm->start_code;
        e.end_data    = (u64)t->mm->end_data;
        e.start_data  = (u64)t->mm->start_data;
        e.start_stack = (u64)t->mm->start_stack;
    }

    finalize_exec_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));
    return 0;
}

int kprobe__start_thread(struct pt_regs *ctx, struct pt_regs *regs,
                         unsigned long new_ip, unsigned long new_sp) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    struct start_thread_event_type e = {
        .entry  = (u64)new_ip,
        .new_sp = (u64)new_sp,
    };
    init_tdata(&e);

    start_thread_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));
    return 0;
}