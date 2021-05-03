package module

import (
	_ "embed" // embed for shift_arg_pages
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/shift_arg_pages.c.k
var shiftArgPagesSource string

type shiftArgPagesEvent struct {
	enhance.TimeEventResult

	OldStart uint64
	OldEnd   uint64
	NewStart uint64
	NewEnd   uint64
}

func (s shiftArgPagesEvent) Render() *data.AnalyseData {
	res := data.NewSet(
		form.NewMarkdown("开始准备移动栈到最终位置"),
		form.NewList(fmt.Sprintf("[%x, %x] => [%x, %x]", s.OldStart, s.OldEnd, s.NewStart, s.NewEnd)),
	)
	return data.NewAnalyseData(res)
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "shift_arg_pages",
		Source:  shiftArgPagesSource,
		Events:  []*bcc.Event{bcc.NewKprobeEvent("kprobe__shift_arg_pages", "shift_arg_pages", -1)},
	})
	m.RegisterOnceTable("shift_arg_pages_events", modules.RenderHandler(&shiftArgPagesEvent{}))
	factory.Register(m.Mm())
}
