#include "common.h"

TDATA(free_page_about_event_type, u32 type);
TDATA(free_pgd_range_event_type,  // free_pgd_range
      u64 addr;                   // addr
      u64 end;                    // end
      u64 floor;                  // floor
      u64 ceiling;                // ceiling
)

BPF_PERF_OUTPUT(tlb_gather_mmu_events);
BPF_PERF_OUTPUT(tlb_finish_mmu_events);
BPF_PERF_OUTPUT(free_pgd_range_events);

BPF_PERCPU_ARRAY(total_array, u32, 1);

int kprobe__shift_arg_pages(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    int zero = 0, one = 1;
    total_array.update(&zero, &one);

    return 0;
}

int kprobe__tlb_gather_mmu(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    int zero = 0;
    u32 *cnt = total_array.lookup(&zero);
    if (cnt == NULL || *cnt != 1) {
        return 0;
    }

    struct free_page_about_event_type e = {.type = 1};
    init_tdata(&e);
    tlb_gather_mmu_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));

    return 0;
}

int kprobe__tlb_finish_mmu(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    int zero = 0;
    u32 *cnt = total_array.lookup(&zero);
    if (cnt == NULL || *cnt != 1) {
        return 0;
    }

    struct free_page_about_event_type e = {.type = 2};
    init_tdata(&e);
    tlb_finish_mmu_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));

    return 0;
}

int kprobe__free_pgd_range(struct pt_regs *ctx, struct mmu_gather *tlb,
                           unsigned long addr, unsigned long end,
                           unsigned long floor, unsigned long ceiling) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    int zero = 0;
    u32 *cnt = total_array.lookup(&zero);
    if (cnt == NULL || *cnt != 1) {
        return 0;
    }

    struct free_pgd_range_event_type e = {};
    init_tdata(&e);
    e.addr    = (u64)addr;
    e.end     = (u64)end;
    e.floor   = (u64)floor;
    e.ceiling = (u64)ceiling;

    free_pgd_range_events.perf_submit((void*)ctx, (void*)&e, sizeof(e));

    return 0;
}