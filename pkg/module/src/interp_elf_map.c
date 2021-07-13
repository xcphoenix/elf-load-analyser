#include "common.h"

#if ELF_CLASS == ELFCLASS32
#define Elf_Xword Elf32_Word
#else
#define Elf_Xword Elf64_Xword
#endif

// cnt is total_array
#define IS_ELF_INTERRP_MAP(cnt) ((cnt) == 2)

// 映射事件
TDATA(interp_elf_map_event_type,  // elf map event type
      u64 vaddr;                  // elf文件中段的p_vaddr
      u64 shifted_addr;           // 偏移后的地址
      u64 aligned_addr;           // 偏移后的地址按页对齐
      u64 actual_addr;            // 真实地址
      u64 size;                   // 映射的区域大小
      u64 off;                    // 映射的部分在文件中的偏移量

      u64 vma_start;  // vma_start
      u64 vma_end;    // vma_end
      u64 vma_off;    // vma_off
      u64 vma_flags;  // 标志位

      u64 total_size;  // 映射部分的总大小
      u64 inode;       // inode名
);

// 映射属性相关
TDATA(interp_elf_map_prop_event_type,  // elf map event type
      TEMPTY;                          // empty
);

BPF_PERF_OUTPUT(interp_elf_map_events);
BPF_PERF_OUTPUT(interp_elf_map_prop_events);

BPF_PERCPU_ARRAY(emap_array, struct interp_elf_map_event_type, 1);
BPF_PERCPU_ARRAY(total_array, u32, 1);
BPF_PERCPU_ARRAY(map_array, u32, 1);

int kprobe__vma_link(struct pt_regs *ctx, struct mm_struct *mm,
                     struct vm_area_struct *vma, struct vm_area_struct *prev) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }

    int zero = 0;

    struct interp_elf_map_event_type *e = emap_array.lookup(&zero);
    if (!e) {
        return 0;
    }
    e->vma_start = (unsigned long)vma->vm_start;
    e->vma_end   = (unsigned long)vma->vm_end;
    e->vma_off   = (unsigned long)vma->vm_pgoff;
    e->vma_flags = (unsigned long)vma->vm_flags;
    emap_array.update(&zero, e);

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

int kprobe__elf_map(struct pt_regs *ctx, struct file *filep, unsigned long addr,
                    const struct elf_phdr *eppnt, int prot, int type,
                    unsigned long total_size) {
    u32 pid = (u32)bpf_get_current_pid_tgid();
    if (pid != _PID_) {
        return 0;
    }

    int zero = 0;
    struct interp_elf_map_event_type event = {};

    u32 *total_cnt_p = total_array.lookup(&zero);
    if (!total_cnt_p) {
        bpf_trace_printk("elf_map:: total_cnt_p is null");
        return 0;
    }
    bpf_trace_printk("total_cnt_p: %u", *total_cnt_p);

    if (!IS_ELF_INTERRP_MAP(*total_cnt_p)) {
        bpf_trace_printk("elf_map:: ignore");
        return 0;
    }

    event.shifted_addr = addr;
    event.total_size = total_size;
    if (filep) {
        event.inode = (u64)filep->f_path.dentry->d_inode->i_ino;
    }

    struct elf_phdr segment;
    bpf_probe_read_kernel(&segment, sizeof(segment), (void *)eppnt);
    event.off = segment.p_offset - ELF_PAGEOFFSET(segment.p_vaddr);
    event.aligned_addr = ELF_PAGESTART(addr);
    event.size =
        ELF_PAGEALIGN(segment.p_filesz + ELF_PAGEOFFSET(segment.p_vaddr));
    event.vaddr = segment.p_vaddr;

    if (event.total_size) {
        struct interp_elf_map_prop_event_type e = {};
        init_tdata(&e);
        interp_elf_map_prop_events.perf_submit((void *)ctx, (void *)&e,
                                               sizeof(e));
    }

    emap_array.update(&zero, &event);

    return 0;
}

int kretprobe__elf_map(struct pt_regs *ctx) {
    u32 pid = (u32)bpf_get_current_pid_tgid();
    if (pid != _PID_) {
        return 0;
    }

    int zero = 0;
    u32 *total_cnt_p, *map_count_p, map_count = 1;
    struct interp_elf_map_event_type *event;

    // arg check
    if (!(total_cnt_p = total_array.lookup(&zero)) ||  // elf self map check
        !IS_ELF_INTERRP_MAP(*total_cnt_p) ||
        !(event = emap_array.lookup(&zero))) {  // prop valid check
        bpf_trace_printk("elf_map_event check failed!");
        return 0;
    }

    unsigned long addr = PT_REGS_RC(ctx);

    map_count_p = map_array.lookup(&zero);
    if (!map_count_p) {
        return 0;
    }
    map_count = (map_count_p ? (*map_count_p) : 0) + 1;
    event->actual_addr = addr;
    map_array.update(&zero, &map_count);
    init_tdata(event);
    interp_elf_map_events.perf_submit((void *)ctx, (void *)event,
                                      sizeof(*event));
    return 0;
}