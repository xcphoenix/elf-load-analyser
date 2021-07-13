#include <linux/mm.h>

#include "common.h"

TDATA(setup_arg_pages_event_type,      // setup_arg_pages_event_type
      u64 stack_top;                   // stack_top
      int32_t executable_stack;        // stack executble status, 0: default, 1:
                                       // disable, 2: enable
      u64 stack_top_after_arch_align;  // aligned after arch_align_stack
      u64 stack_top_final;             // after PAGE_ALIGN, final val
      u64 vma_start;                   // before stack start
      u64 vma_end;                     // before stack end
      u64 mm_def_flags;                // mm->def_flags
      u64 stack_shift;                 // stack_shift
      u64 stack_expand;                // 128 pages
      u64 rlim_stack;                  // rlim_stack
      u64 bprm_rlim_stack_cur;         // bprm->rlim_stack.rlim_cur
      u64 page_mask;                   // macro PAGE_MASK
);
BPF_PERF_OUTPUT(setup_arg_pages_events);

BPF_PERCPU_ARRAY(total_array, u32, 1);  // for control arch_align_stack
BPF_PERCPU_ARRAY(event_array, struct setup_arg_pages_event_type, 1);

int kretprobe__arch_align_stack(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    int zero = 0, one = 1;
    int *cnt = total_array.lookup(&zero);
    if (cnt && *cnt != 0) {
        return 0;
    }

    struct setup_arg_pages_event_type *e = event_array.lookup(&zero);
    if (!e) {
        bpf_trace_printk("BUG - arch_align_stack: cann't found event object]");
        goto OUT;
    }

    e->stack_top_after_arch_align = (u64)((unsigned long)PT_REGS_RC(ctx));
    e->stack_top_final            = PAGE_ALIGN(e->stack_top_after_arch_align);
    e->stack_shift                = e->vma_end - e->stack_top_final;

    setup_arg_pages_events.perf_submit((void *)ctx, (void *)e, sizeof(*e));

OUT:
    total_array.update(&zero, &one);
    return 0;
}

int kprobe__setup_arg_pages(struct pt_regs *ctx, struct linux_binprm *bprm,
                            unsigned long stack_top, int executable_stack) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    struct setup_arg_pages_event_type e = {};
    init_tdata(&e);

    e.stack_top = (u64)stack_top;

    if (executable_stack == EXSTACK_ENABLE_X) {
        e.executable_stack = 2;
    } else if (executable_stack == EXSTACK_DISABLE_X) {
        e.executable_stack = 1;
    }

    e.vma_start    = (u64)bprm->vma->vm_start;
    e.vma_end      = (u64)bprm->vma->vm_end;
    e.mm_def_flags = (u64)bprm->mm->def_flags;

    e.stack_expand = (u64)131072UL;

    e.page_mask           = PAGE_MASK;
    e.bprm_rlim_stack_cur = (u64)bprm->rlim_stack.rlim_cur;
    e.rlim_stack          = e.bprm_rlim_stack_cur & e.page_mask;

    int zero = 0;
    event_array.update(&zero, &e);

    return 0;
}