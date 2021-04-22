#include "common.h"

#define INTERP_MAP 0x1000
#define VMA_MERGED 0x0100
#define MAPED_FLAG 0x0010
#define VALID_FLAG 0x0001  // valid flag

TDATA(vm_brk_flags_event_type,  // vm_brk_flags_event_type
      u32 type;                 // type: INTERP_MAP VMA_MERGED VMA_LINKED
      u64 start;                // start addr
      u64 length;               // map size
      u64 prot;                 // map prot
      // new vma prop
      u64 vma_start;  // vma start
      u64 vma_end;    // vma end
      u64 vma_off;    // vma pgoff
      u64 vma_flags;  // vma flags
      u64 vma_prot;   // vma page prot
);

BPF_PERF_OUTPUT(vm_brk_flags_events);
BPF_PERCPU_ARRAY(event_array, struct vm_brk_flags_event_type, 1);
BPF_PERCPU_ARRAY(total_array, u32, 1);

/**
 * +-- total_mapping_size
 * |
 * |~~ elf map bss segment -------------------+
 * |                                          |
 * +-- total_mapping_size                     |
 * |                                          |
 * |~~ elf interp map bss segment ------------+
 * |                                          |
 * +-- ...                  +-----------------+-----------------+
 *                          |  vm_brk_flags                     |
 *                          |  +---- do_brk_flags               |
 *                          |        +------------ vma_merge    |
 *                          |                      vma_link     |
 *                          +-----------------------------------+
 */

int kretprobe__vm_brk_flags(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    int zero = 0;

    struct vm_brk_flags_event_type *e = event_array.lookup(&zero);
    if (e) {
        vm_brk_flags_events.perf_submit((void *)ctx, (void *)e, sizeof(*e));
    }
    // clear
    event_array.delete(&zero);

    return 0;
}

int kretprobe__vma_merge(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    int zero = 0;
    struct vm_brk_flags_event_type *e;
    // 有返回值表示被 Merge，同时若存在 event 且有效
    if (PT_REGS_RC(ctx) && (e = event_array.lookup(&zero)) &&
        (e->type & VALID_FLAG)) {
        e->type |= VMA_MERGED | MAPED_FLAG;
        event_array.update(&zero, e);
    }

    return 0;
}

int kprobe__vma_link(struct pt_regs *ctx, struct mm_struct *mm,
                     struct vm_area_struct *vma, struct vm_area_struct *prev) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    int zero = 0;

    struct vm_brk_flags_event_type *e = event_array.lookup(&zero);
    if (!e || !(e->type & VALID_FLAG)) {
        return 0;
    }
    e->type |= MAPED_FLAG;
    e->vma_start = (unsigned long)vma->vm_start;
    e->vma_end   = (unsigned long)vma->vm_end;
    e->vma_off   = 0;  // bss直接设为0
    e->vma_flags = (unsigned long)vma->vm_flags;
    e->vma_prot  = (unsigned long)vma->vm_page_prot.pgprot; // TODO 属性有问题
    event_array.update(&zero, e);

    return 0;
}

int kprobe__vm_brk_flags(struct pt_regs *ctx, unsigned long addr,
                         unsigned long request, unsigned long flags) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    struct vm_brk_flags_event_type e = {
        .start  = (u64)addr,
        .length = (u64)request,
        .prot   = (u64)flags,
        .type   = VALID_FLAG,  // 有效数据
    };
    init_tdata(&e);

    // elf interp
    int zero = 0;
    u32 *cnt = total_array.lookup(&zero);
    if (cnt && *cnt > 1) {
        e.type = 1;
    }

    event_array.update(&zero, &e);
    return 0;
}

int kprobe__total_mapping_size(struct pt_regs *ctx, const struct elf_phdr *cmds,
                               int nr) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    int zero = 0;
    u32 *cnt = total_array.lookup(&zero), tmp = 0;
    if (!cnt) {
        cnt = &tmp;
    }
    (*cnt)++;
    total_array.update(&zero, cnt);
    return 0;
}