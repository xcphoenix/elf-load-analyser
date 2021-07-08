package module

import (
	_ "embed" // embed for flush_signal_handlers
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/flush_signal_handlers.c.k
var flushSignalHandlersSource string

type flushSignalHandlersEvent struct {
	enhance.TimeEventResult
}

func (z flushSignalHandlersEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("刷新进程的所有信号处理器"))
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Name:     "flush_signal_handlers",
		Source:   flushSignalHandlersSource,
		Events:   []*bcc.Event{bcc.NewKprobeEvent("kprobe__flush_signal_handlers", "flush_signal_handlers", -1)},
		CanMerge: true,
	})
	m.RegisterOnceTable("flush_signal_handlers_events", modules.RenderHandler(flushSignalHandlersEvent{}, nil))
	factory.Register(m)
}
