package module

import (
	_ "embed" // embed for setup_arg_pages
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"os"
)

//go:embed src/setup_arg_pages.c.k
var setupArgPagesEventSource string

type setupArgPageEvent struct {
	enhance.TimeEventResult

	StackTop               uint64
	ExecutableStackStatus  int32
	StackTopAfterArchAlign uint64
	StackTopFinal          uint64
	VmaStart               uint64
	VmaEnd                 uint64
	DefFlags               uint64
	StackShift             uint64
	StackExpand            uint64
	RlimStack              uint64
	BprmRlimStackCur       uint64
	PageMask               uint64
}

func (s setupArgPageEvent) Render() *data.AnalyseData {
	var mappedStatus = [...]string{
		"默认",
		"不可执行",
		"可执行",
	}
	pageSize := uint64(os.Getpagesize())
	res := data.NewSet(
		form.NewMarkdown("开始执行处理栈的最后操作：更新栈的权限，重分配栈的位置，扩展栈空间等操作"),
		form.NewFmtList(form.Fmt{
			{"栈随机化后位置为: %x", s.StackTop},
			{helper.IfElse(
				s.ExecutableStackStatus >= 0 && int(s.ExecutableStackStatus) < len(mappedStatus),
				fmt.Sprintf("栈的状态: %s", mappedStatus[s.ExecutableStackStatus]),
				"BUG: 栈状态无效",
			)},
			{"栈顶经 arch_align_stack 处理后的值为: %x", s.StackTopAfterArchAlign},
			{"栈顶最终的位置为: %x", s.StackTopFinal},
			{"临时栈区域为: [%x, %x], 占用 %d pages", s.VmaStart, s.VmaEnd, (s.VmaEnd - s.VmaStart) / pageSize},
			{"栈需要偏移的值: %x", s.StackShift},
			{"栈仍需扩展的空间大小为: %d pages", s.StackExpand / pageSize},
			{"栈的最大资源限制值为: %d pages (bprm->rlim_stack.rlim_cur: %x & PAGE_MASK: %x), 可通过 ulimit 查看和修改资源限制",
				s.RlimStack / pageSize, s.BprmRlimStackCur, s.PageMask},
		}),
	)
	return data.NewAnalyseData(res)
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "setup_arg_pages",
		Source:  setupArgPagesEventSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__setup_arg_pages", "setup_arg_pages", -1),
			bcc.NewKretprobeEvent("kretprobe__arch_align_stack", "arch_align_stack", -1),
		},
	})
	m.RegisterOnceTable("setup_arg_pages_events", modules.RenderHandler(setupArgPageEvent{}, nil))
	factory.Register(m)
}
