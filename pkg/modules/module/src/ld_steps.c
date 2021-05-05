#include "common.h"

// 阶段事件
// 1. 动态链接器自举
// 2. 装载共享对象
// 3. 重定位和初始化
// 4. 控制权交给用户程序
TDATA(step_event, TEMPTY);

BPF_PERF_OUTPUT(bootstrap_finished_events);
BPF_PERF_OUTPUT(start_user_prog_events);

/**
 * 当动态链接自举成功后调用 `__rtld_malloc_init_stubs`
 *
 * The rtld startup code calls __rtld_malloc_init_stubs after the
 * first self-relocation to adjust the pointers to the minimal
 * implementation below.
 */
int bootstrap_finished(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct step_event e = {};
    init_tdata(&e);

    bootstrap_finished_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));
    return 0;
}

/**
 * 控制权交给用户程序
 */
int start_user_prog(struct pt_regs *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != _PID_) {
        return 0;
    }
    struct step_event e = {};
    init_tdata(&e);

    start_user_prog_events.perf_submit((void *)ctx, (void *)&e, sizeof(e));
    return 0;
}
