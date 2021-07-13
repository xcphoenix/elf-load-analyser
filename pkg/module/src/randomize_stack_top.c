#include <linux/mm.h>

#include "common.h"

TDATA(randomize_stack_top_event_type,  // randomize
      u64 stack_top;                   // stack_top
      u64 stack_top_aligned;           // stack_top after page aligned
      u64 actual_stack_top;            // ret val
);
BPF_PERF_OUTPUT(randomize_stack_top_events);
BPF_PERCPU_ARRAY(event_arr, struct randomize_stack_top_event_type, 1);

int kprobe__randomize_stack_top(struct pt_regs *ctx, unsigned long stack_top) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct randomize_stack_top_event_type e = {};
    init_tdata(&e);

    e.stack_top         = (u64)stack_top;
    e.stack_top_aligned = (u64)(PAGE_ALIGN(stack_top));

    int zero = 0;
    event_arr.update(&zero, &e);

    return 0;
}

int kretprobe__randomize_stack_top(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    int zero                                 = 0;
    struct randomize_stack_top_event_type *e = event_arr.lookup(&zero);
    if (!e) {
        return 0;
    }

    e->actual_stack_top = (u64)((unsigned long)PT_REGS_RC(ctx));
    randomize_stack_top_events.perf_submit((void *)ctx, e, sizeof(*e));

    return 0;
}