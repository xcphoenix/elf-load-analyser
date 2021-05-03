#include "common.h"

TDATA(expand_stack_event_type,  // call event
      u64 vma_start;            // old_start
      u64 vma_end;              // old_end
      u64 vma_new_start;        // new_start
      u64 start_stack;          // cur start_stack
);

BPF_PERF_OUTPUT(expand_stack_events);

int kprobe__expand_stack(struct pt_regs *ctx, struct vm_area_struct *vma,
                         unsigned long address) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    struct expand_stack_event_type e = {};
    init_tdata(&e);

    e.vma_start     = (u64)vma->vm_start;
    e.vma_end       = (u64)vma->vm_end;
    e.vma_new_start = (u64)address;

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    if (t) {
        e.start_stack = (u64)t->mm->start_stack;
    }

    expand_stack_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));

    return 0;
}