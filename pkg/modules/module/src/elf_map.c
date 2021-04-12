#include "common.h"

#ifdef _DEV_
#define _ISDYN_ 0
#define _ENTRY_ 0
#endif

#if ELF_CLASS == ELFCLASS32
#define Elf_Xword Elf32_Word
#else
#define Elf_Xword Elf64_Xword
#endif

// 只检查 ELF 的映射
#define ELF_SELF 1

// cnt is total_array
#define IS_ELF_SELF_MAP(cnt) ((cnt) == 1)

// 映射事件
TDATA(elf_map_event_type,  // elf map event type
      u64 vaddr;           // elf文件中段的p_vaddr
      u64 shifted_addr;    // 偏移后的地址
      u64 aligned_addr;    // 偏移后的地址按页对齐
      u64 actual_addr;     // 真实地址
      u64 size;            // 映射的区域大小
      u64 off;             // 映射的部分在文件中的偏移量

      int64_t prot;        // 权限
      int64_t type;        // 标志位
      u64 total_size;      // 映射部分的总大小
      u64 inode;           // inode名
);

// 映射属性相关
TDATA(elf_map_prop_event_type,  // elf map event type
      u64 load_addr;            // 加载地址
      u64 load_bias;            // 加载偏移

      // addr without load_bias
      u64 e_entry; u64 start_code;  // 代码段开始地址
      u64 start_data;               // 数据段开始地址
      u64 end_code;                 // 代码段结束地址
      u64 end_data;                 // 数据段结束地址
      u64 elf_bss;                  // bss段开始地址(最后一块)
      u64 elf_brk;                  // brk结束地址

      u64 first_paged;  // 第一次按页对齐的值
      u64 rnd;          // 随机偏移
      u32 max_align;    // 最大对齐长度
      _Bool is_dyn; _Bool with_interp; _Bool is_rnd;

      /*
       * ignore
       */
      unsigned long vaddr;  // 第一次的虚拟地址
);

BPF_PERF_OUTPUT(elf_map_events);
BPF_PERF_OUTPUT(elf_map_prop_events);

BPF_PERCPU_ARRAY(emap_array, struct elf_map_event_type, 1);
BPF_PERCPU_ARRAY(prop_array, struct elf_map_prop_event_type, 1);
BPF_PERCPU_ARRAY(total_array, u32, 1);
BPF_PERCPU_ARRAY(map_array, u32, 1);
BPF_PERCPU_ARRAY(rnd_array, unsigned long, 1);

static u32 update_align(Elf_Xword align, u32 before);

int kprobe__set_brk(struct pt_regs *ctx, unsigned long start, unsigned long end,
                    int prot) {
    u32 pid = (u32)bpf_get_current_pid_tgid();
    if (pid != _PID_) {
        return 0;
    }

    int zero = 0;

    struct elf_map_prop_event_type *prop_p = prop_array.lookup(&zero);
    if (!prop_p) {
        bpf_trace_printk("prop: not found!");
        return 0;
    }
#ifdef _X_DEBUG_
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    bpf_trace_printk("set_brk: current mmap cnt: %d\n", t->mm->map_count);
#endif
    elf_map_prop_events.perf_submit((void *)ctx, (void *)prop_p,
                                    sizeof(struct elf_map_prop_event_type));
    prop_array.delete(&zero);
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

int kretprobe__arch_mmap_rnd(struct pt_regs *ctx) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    int zero = 0;
    unsigned long rnd = PT_REGS_RC(ctx);
    rnd_array.update(&zero, &rnd);
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
    struct elf_map_event_type event = {};

    u32 *total_cnt_p = total_array.lookup(&zero);
    if (!total_cnt_p) {
        bpf_trace_printk("elf_map:: total_cnt_p is null");
        return 0;
    }
    bpf_trace_printk("total_cnt_p: %u", *total_cnt_p);

    // 忽略 interp 的处理
    if (!IS_ELF_SELF_MAP(*total_cnt_p)) {
        bpf_trace_printk("elf_map:: ignore");
        return 0;
    }

    event.shifted_addr = addr;
    event.prot = prot;
    event.type = type;
    event.total_size = total_size;
    if (filep) {
        // struct file open_file = {};
        // bpf_probe_read_kernel(&open_file, sizeof(open_file), (void *)filep);
        // struct dentry open_dentry = {};
        // bpf_probe_read_kernel(&open_dentry, sizeof(open_dentry), (void
        // *)open_file.f_path.dentry); struct inode open_inode = {};
        // bpf_probe_read_kernel(&open_inode, sizeof(open_inode), (void
        // *)open_dentry.d_inode);

        // struct inode open_inode = {};
        // bpf_probe_read_kernel(&open_inode, sizeof(open_inode), (void
        // *)filep->f_path.dentry->d_inode);
        event.inode = (u64)filep->f_path.dentry->d_inode->i_ino;
        // bpf_trace_printk("ino: %ul", filep->f_path.dentry->d_inode->i_ino);
    }

    struct elf_phdr segment;
    bpf_probe_read_kernel(&segment, sizeof(segment), (void *)eppnt);
    event.off = segment.p_offset - ELF_PAGEOFFSET(segment.p_vaddr);
    event.aligned_addr = ELF_PAGESTART(addr);
    event.size =
        ELF_PAGEALIGN(segment.p_filesz + ELF_PAGEOFFSET(segment.p_vaddr));
    event.vaddr = segment.p_vaddr;

#ifdef _X_DEBUG_
    if (event.total_size) {
        bpf_trace_printk("map total size: 0x%llx", event.total_size);
    }
    bpf_trace_printk(
        "vaddr: 0x%llx, vaddr with bias: 0x%llx, real addr: 0x%llx",
        event.vaddr, event.shifted_addr, event.aligned_addr);
    bpf_trace_printk("size: 0x%llx, offset: 0x%llx", event.size, event.off);
    bpf_trace_printk("prot: %ld, type: %ld\n", event.prot, event.type);
#endif

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct elf_map_prop_event_type *prop_p = prop_array.lookup(&zero);
    if (!prop_p) {
        return 0;
    }

    // 如果是ELF文件本身第一次映射
    if (event.total_size) {
        bpf_trace_printk("First mapping");

        init_tdata(prop_p);
        prop_p->e_entry = _ENTRY_;
        prop_p->vaddr = segment.p_vaddr;

        if (!_ISDYN_) {
#ifdef _X_DEBUG_
            bpf_trace_printk("\t- type: ET_EXEC\n");
#endif
        } else if (_ISDYN_) {
            prop_p->is_dyn = 1;
#ifdef _X_DEBUG_
            bpf_trace_printk("\t- type: ET_DYN");
#endif
            if (event.shifted_addr) {
                prop_p->with_interp = 1;
#ifdef _X_DEBUG_
                bpf_trace_printk("\t- with interp");
                bpf_trace_printk("\t- set base addr: ELF_ET_DYN_BASE");
#endif
                if (t->flags & PF_RANDOMIZE) {
                    // 随机偏移
                    unsigned long *rnd_p = rnd_array.lookup(&zero);
                    if (!rnd_p) {
                        return 0;
                    }
                    prop_p->is_rnd = 1;
                    prop_p->rnd = (u64)*rnd_p;
#ifdef _X_DEBUG_
                    bpf_trace_printk("\t- append rnd: 0x%lx", *rnd_p);
#endif
                }
#ifdef _X_DEBUG_
                // 获取最大的对齐属性并对齐
                bpf_trace_printk("\t- align as maximum alignment");
#endif
            }
            prop_p->first_paged = event.shifted_addr - event.vaddr;
#ifdef _X_DEBUG_
            bpf_trace_printk(
                "\t- pre for first map, value: 0x%lx after ELF_PAGESTART\n",
                event.shifted_addr - event.vaddr);
#endif
        }
        prop_p->load_addr = segment.p_vaddr - segment.p_offset;
        prop_p->load_bias = event.shifted_addr - event.vaddr;
    }

    prop_p->max_align = update_align(segment.p_align, prop_p->max_align);

    unsigned long tmp_ul = segment.p_vaddr;
    if ((segment.p_flags & PF_X) && tmp_ul < prop_p->start_code) {
        prop_p->start_code = tmp_ul;
    }
    if (prop_p->start_data < tmp_ul) {
        prop_p->start_data = tmp_ul;
    }

    tmp_ul = segment.p_vaddr + segment.p_filesz;
    if (tmp_ul > prop_p->elf_bss) {
        prop_p->elf_bss = tmp_ul;
    }
    if ((segment.p_flags & PF_X) && prop_p->end_code < tmp_ul)
        // 更新代码段的结束位置
        prop_p->end_code = tmp_ul;
    if (prop_p->end_data < tmp_ul)
        // 更新数据段的结束位置，在代码段之后
        prop_p->end_data = tmp_ul;

    tmp_ul = segment.p_vaddr + segment.p_memsz;
    if (tmp_ul > prop_p->elf_brk) {
        prop_p->elf_brk = tmp_ul;
    }

    bpf_trace_printk("update event and prop");
    prop_array.update(&zero, prop_p);
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
    struct elf_map_event_type *event;
    struct elf_map_prop_event_type *prop;

    // arg check
    if (!(total_cnt_p = total_array.lookup(&zero)) ||  // elf self map check
        !IS_ELF_SELF_MAP(*total_cnt_p) ||
        !(event = emap_array.lookup(&zero)) ||  // emap valid check
        !(prop = prop_array.lookup(&zero))) {   // prop valid check
        bpf_trace_printk("elf_map_event check failed!");
        return 0;
    }

    unsigned long addr = PT_REGS_RC(ctx);

    map_count_p = map_array.lookup(&zero);
    if (!map_count_p) {
        return 0;
    }
    if ((*map_count_p) == 0) {
        if (prop->is_dyn) {
            prop->load_bias +=
                (addr - ELF_PAGESTART(prop->load_bias + prop->vaddr));
            prop->load_addr += prop->load_bias;
        }
        prop_array.update(&zero, prop);
    }
    map_count = (map_count_p ? (*map_count_p) : 0) + 1;
    event->actual_addr = addr;

    // update map cnt
    map_array.update(&zero, &map_count);
    // update event and submit
    init_tdata(event);
    elf_map_events.perf_submit((void *)ctx, (void *)event, sizeof(*event));
    return 0;
}

static u32 update_align(Elf_Xword align, u32 before) {
    if (align != 0 && ((align & (align - 1)) == 0)) {
        return before > align ? before : align;
    }
    return before;
}