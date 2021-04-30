#include "common.h"

TDATA(set_mm_exe_file_event_type,  // set_mm_exe_file_event_type
      char exe_filename[256];      // exe filename, same with linux_binprm->filename
);
BPF_PERF_OUTPUT(set_mm_exe_file_events);

int kprobe__set_mm_exe_file(struct pt_regs *ctx, struct mm_struct *mm,
                            struct file *new_exe_file) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct set_mm_exe_file_event_type e = {};
    init_tdata(&e);

    char *iname = new_exe_file->f_path.dentry->d_iname;
    bpf_probe_read_kernel_str(&e.exe_filename, sizeof(e.exe_filename), (void*)iname);
    
    set_mm_exe_file_events.perf_submit((void *)ctx, &e, sizeof(e));
    return 0;
}
