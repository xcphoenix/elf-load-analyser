package module

import (
	_ "embed" // embed for expand_stack
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
)

//go:embed src/expand_stack.c.k
var expandStackSource string

type expandStackEvent struct {
	enhance.TimeEventResult
	VmaStart    uint64
	VmaEnd      uint64
	VmaNewStart uint64
	StartStack  uint64
}

func (e expandStackEvent) Render() *data.AnalyseData {
	res := form.NewMarkdown(fmt.Sprintf("扩展栈空间至 %x", e.VmaNewStart)).
		WithContents(fmt.Sprintf("当前栈地址为: %x(来自 binprm-> p)", e.StartStack))
	return data.NewAnalyseData(res).
		PutExtra(virtualm.VmaFlag, virtualm.AdjustVmaEvent{
			VmaStart:    e.VmaStart,
			VmaEnd:      e.VmaEnd,
			AdjustStart: e.VmaNewStart,
			AdjustEnd:   e.VmaEnd,
		})
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:     "expand_stack",
		Source:   expandStackSource,
		Events:   []*ebpf.Event{ebpf.NewKprobeEvent("kprobe__expand_stack", "expand_stack", -1)},
		CanMerge: true,
	})
	m.RegisterOnceTable("expand_stack_events", monitor.RenderHandler(expandStackEvent{}, nil))
	factory.Register(m)
}
