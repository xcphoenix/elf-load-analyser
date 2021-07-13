#include "common.h"
#include <linux/mm_types.h>

TDATA(x_install_special_mapping_event_type,  // _install_special_mapping
      u64 addr;                              // addr
      u64 len;                               // len
      u64 vm_flags;                          // flags
      char name[256];                        // map name
)
BPF_PERF_OUTPUT(x_install_special_mapping_events);

int kprobe__x_install_special_mapping(struct pt_regs *ctx, struct mm_struct *mm,
                                      unsigned long addr, unsigned long len,
                                      unsigned long vm_flags,
                                      const struct vm_special_mapping *spec) {
    if ((u32)bpf_get_current_pid_tgid() != _PID_) {
        return 0;
    }

    struct x_install_special_mapping_event_type e = {
        .addr = (u64)addr,
        .len = (u64)len,
        .vm_flags = (u64)vm_flags,
    };
    init_tdata(&e);

    bpf_probe_read_kernel_str(&e.name, sizeof(e.name), (void*)spec->name);
    x_install_special_mapping_events.perf_submit((void*)ctx, (void*)&e, sizeof(e));
    
    return 0;
}