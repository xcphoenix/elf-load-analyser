#include "common.h"

TDATA(shift_arg_pages_event_type,  // call event
      u64 old_start;               // old_start
      u64 old_end;                 // old_end
      u64 new_start;               // new_start
      u64 new_end;                 // new_end
);

BPF_PERF_OUTPUT(shift_arg_pages_events);

int kprobe__shift_arg_pages(struct pt_regs *ctx, struct vm_area_struct *vma,
                            unsigned long shift) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    struct shift_arg_pages_event_type e = {};
    init_tdata(&e);

    e.old_start = (u64)vma->vm_start;
    e.old_end   = (u64)vma->vm_end;
    e.new_end   = (u64)e.old_end - shift;
    e.new_start = (u64)e.old_start - shift;

    shift_arg_pages_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));

    return 0;
}