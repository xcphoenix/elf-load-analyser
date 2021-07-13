package module

import (
	_ "embed" // embed for flush_signal_handlers
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
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
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:     "flush_signal_handlers",
		Source:   flushSignalHandlersSource,
		Events:   []*ebpf.Event{ebpf.NewKprobeEvent("kprobe__flush_signal_handlers", "flush_signal_handlers", -1)},
		CanMerge: true,
	})
	m.RegisterOnceTable("flush_signal_handlers_events", monitor.RenderHandler(flushSignalHandlersEvent{}, nil))
	factory.Register(m)
}
