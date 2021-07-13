#include "common.h"

TDATA(move_page_tables_event_type,  // move_page_tables
      u64 old_start;                // old_start
      u64 new_start;                // new_start
      u64 length;                   // length
);
BPF_PERF_OUTPUT(move_page_tables_events);

int kprobe__move_page_tables(struct pt_regs *ctx, struct vm_area_struct *vma,
                             unsigned long old_addr,
                             struct vm_area_struct *new_vma,
                             unsigned long new_addr, unsigned long len) {
    if ((u32)bpf_get_current_pid_tgid() != (u64)_PID_) {
        return 0;
    }

    struct move_page_tables_event_type e = {};
    init_tdata(&e);

    e.old_start = (u64)old_addr;
    e.new_start = (u64)new_addr;
    e.length = (u64)len;

    move_page_tables_events.perf_submit((void*)ctx, (void*)&e, sizeof(e));

    return 0;
}