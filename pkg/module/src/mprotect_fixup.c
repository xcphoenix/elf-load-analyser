#include "common.h"

TDATA(mprotect_fixup_event_type,  // mprotect_fixup_event_type
      u64 vma_end;                // vma_end
      u64 vma_start;              // vma_start
      u64 region_end;             // region_end
      u64 region_start;           // region_start
      u64 flags;                  // flags
);

BPF_PERF_OUTPUT(mprotect_fixup_events);
BPF_PERCPU_ARRAY(total_array, u32, 1);

int kprobe__setup_arg_pages(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    int zero = 0, one = 1;
    total_array.update(&zero, &one);
    return 0;
}

int kprobe__mprotect_fixup(struct pt_regs *ctx, struct vm_area_struct *vma,
                           struct vm_area_struct **pprev, unsigned long start,
                           unsigned long end, unsigned long newflags) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    int zero = 0, new_cnt = 2;
    u32 *cnt = total_array.lookup(&zero);
    if (!cnt || *cnt != 1) {
        return 0;
    }

    struct mprotect_fixup_event_type e = {};
    init_tdata(&e);

    e.vma_end      = (u64)vma->vm_end;
    e.vma_start    = (u64)vma->vm_start;
    e.region_start = (u64)start;
    e.region_end   = (u64)end;
    e.flags        = (u64)newflags;

    mprotect_fixup_events.perf_submit((void *)ctx, (void*)&e, sizeof(e));
    total_array.update(&zero, &new_cnt);
    return 0;
}