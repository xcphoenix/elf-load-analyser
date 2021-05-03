#include "common.h"

TDATA(x__vma_adjust_event_type,  // __vma_adjust_event_type
      u64 vma_start;             // vma_start
      u64 vma_end;               // vma_end
      u64 start;                 // start
      u64 end;                   // end
      u32 seq;                   // seq
);

BPF_PERF_OUTPUT(x__vma_adjust_events);
BPF_PERCPU_ARRAY(total_array, u32, 1);

#define CNT 2

int kprobe__shift_arg_pages(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    int zero = 0, one = 1;
    total_array.update(&zero, &one);

    return 0;
}

int kprobe__x__vma_adjust(struct pt_regs *ctx, struct vm_area_struct *vma,
                          unsigned long start, unsigned long end, pgoff_t pgoff,
                          struct vm_area_struct *insert,
                          struct vm_area_struct *expand) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    int zero = 0, new_cnt = 1;
    u32 *cnt = total_array.lookup(&zero);
    if (cnt == NULL || *cnt == 0 || *cnt > CNT) {
        return 0;
    }

    struct x__vma_adjust_event_type e = {};
    init_tdata(&e);

    e.vma_start = (u64)vma->vm_start;
    e.vma_end   = (u64)vma->vm_end;
    e.start     = (u64)start;
    e.end       = (u64)end;
    e.seq       = *cnt;

    x__vma_adjust_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));
    new_cnt = *cnt + 1;
    total_array.update(&zero, &new_cnt);

    return 0;
}