package module

import (
	_ "embed" // embed for randomize_stack_top
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
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
		form.NewList(
			fmt.Sprintf("理论上的栈顶位置 (STACK_TOP): %x", r.StackTop),
			fmt.Sprintf("理论上的栈顶位置 (STACK_TOP) 按页对齐后: %x", r.StackTopAligned),
			fmt.Sprintf("偏移后的栈顶位置: %x", r.ActualStackTop),
			fmt.Sprintf("随机偏移值为：%x", helper.IfElse(randomizeValue > 0, randomizeValue, -randomizeValue)),
			fmt.Sprintf("栈向 %s 增长", helper.IfElse(randomizeValue < 0, "上", "下")),
		),
	)
	return data.NewAnalyseData(res)
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "randomize_stack_top",
		Source:  randomizeStackTopSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__randomize_stack_top", "randomize_stack_top", -1),
			bcc.NewKretprobeEvent("kretprobe__randomize_stack_top", "randomize_stack_top", -1),
		},
	})
	m.RegisterOnceTable("randomize_stack_top_events", modules.RenderHandler(&randomizeStackTopEvent{}))
	factory.Register(m.Mm())
}
