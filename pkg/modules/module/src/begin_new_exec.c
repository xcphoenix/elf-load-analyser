// https://elixir.bootlin.com/linux/v5.10.7/source/fs/exec.c#L1775

#include "common.h"

TDATA(begin_new_exec_event_type,  // begin_new_exec_event_type
                                  /// exec_mmap
      u32 vma_cnt;  // 理论上只有一个，初始化 struct linux_binprm
                    // 时在栈顶创建了一个匿名页大小的 VMA 存储参数
      u64 vma_start;     // vma_start
      u64 vma_end;       // vma_end
      u64 vma_flags;     // vma_flags
      u64 vm_page_prot;  // vm_page_prot
);
BPF_PERF_OUTPUT(begin_new_exec_events);

int kprobe__begin_new_exec(struct pt_regs* ctx, struct linux_binprm* bprm) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    struct begin_new_exec_event_type event = {};
    init_tdata(&event);

    event.vma_cnt = bprm->mm->map_count;
    if (event.vma_cnt == 1) {
        event.vma_start    = (u64)(bprm->mm->mmap->vm_start);
        event.vma_end      = (u64)(bprm->mm->mmap->vm_end);
        event.vma_flags    = (u64)(bprm->mm->mmap->vm_flags);
        event.vm_page_prot = (u64)(bprm->mm->mmap->vm_page_prot.pgprot);
    }

    begin_new_exec_events.perf_submit((void*)ctx, &event, sizeof(event));
    return 0;
}