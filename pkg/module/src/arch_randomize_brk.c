#include "common.h"

TDATA(arch_randomize_brk_event_type,  // arch_randomize_brk
      u32 type;       // type: 0 未随机化前 type: 1 随机化后
      u64 start_brk;  // 堆的开始位置
      u64 brk;        // 堆的结束位置
);

BPF_PERF_OUTPUT(arch_randomize_brk_events);

// 获取堆随机化的值
int kretprobe__arch_randomize_brk(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    struct arch_randomize_brk_event_type e = {.type = 1};
    init_tdata(&e);
    e.start_brk = e.brk = (u64)PT_REGS_RC(ctx);
    arch_randomize_brk_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));
    return 0;
}

// 获取随机化之前堆的位置
int kretprobe__arch_setup_additional_pages(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct arch_randomize_brk_event_type e = {.type = 0};
    init_tdata(&e);

    e.start_brk = (u64)t->mm->start_brk;
    e.brk = (u64)t->mm->brk;

    arch_randomize_brk_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));
    return 0;
}