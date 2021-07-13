package module

import (
	_ "embed" // embed for flush_thread
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/flush_thread.c.k
var flushThreadSource string

type flushThreadEvent struct {
	enhance.TimeEventResult
}

func (z flushThreadEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("初始化进程结构体 TLS 元数据"))
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:     "flush_thread",
		Source:   flushThreadSource,
		Events:   []*ebpf.Event{ebpf.NewKprobeEvent("kprobe__flush_thread", "flush_thread", -1)},
		CanMerge: true,
	})
	m.RegisterOnceTable("flush_thread_events", monitor.RenderHandler(flushThreadEvent{}, nil))
	factory.Register(m)
}
