package module

import (
	_ "embed" // embed for randomize_stack_top
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/randomize_stack_top.c.k
var randomizeStackTopSource string

type randomizeStackTopEvent struct {
	enhance.TimeEventResult

	StackTop        uint64
	StackTopAligned uint64
	ActualStackTop  uint64
}

func (r randomizeStackTopEvent) Render() *data.AnalyseData {
	var randomizeValue = int64(r.StackTopAligned - r.ActualStackTop)
	res := data.NewSet(
		form.NewMarkdown("随机化栈顶位置"),
		form.NewFmtList(form.Fmt{
			{"理论上的栈顶位置 (STACK_TOP): %x", r.StackTop},
			{"理论上的栈顶位置 (STACK_TOP) 按页对齐后: %x", r.StackTopAligned},
			{"偏移后的栈顶位置: %x", r.ActualStackTop},
			{"随机偏移值为：%x", helper.IfElse(randomizeValue > 0, randomizeValue, -randomizeValue)},
			{"栈向 %s 增长", helper.IfElse(randomizeValue < 0, "上", "下")},
		}),
	)
	return data.NewAnalyseData(res)
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "randomize_stack_top",
		Source: randomizeStackTopSource,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__randomize_stack_top", "randomize_stack_top", -1),
			ebpf.NewKretprobeEvent("kretprobe__randomize_stack_top", "randomize_stack_top", -1),
		},
	})
	m.RegisterOnceTable("randomize_stack_top_events", monitor.RenderHandler(randomizeStackTopEvent{}, nil))
	factory.Register(m)
}
