#include "common.h"

TDATA(arch_pick_mmap_layout_event_type,  // arch_pick_mmap_layout
      u64 mmap_base;);

BPF_PERF_OUTPUT(arch_pick_mmap_layout_events);

int kretprobe__arch_pick_mmap_layout(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }
    struct arch_pick_mmap_layout_event_type e = {};
    init_tdata(&e);
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    e.mmap_base = (u64)t->mm->mmap_base;

    arch_pick_mmap_layout_events.perf_submit((void *)ctx, (void *)&e,
                                             sizeof(e));
    return 0;
}