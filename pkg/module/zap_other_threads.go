package module

import (
	_ "embed" // embed for zap_other_threads
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/zap_other_threads.c.k
var zapOtherThreadsSource string

type zapOtherThreadEvent struct {
	enhance.TimeEventResult
}

func (z zapOtherThreadEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("开始删除线程组中的其他线程，向除本线程外的其他线程发送 SIGKILL 信号"))
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:     "zap_other_threads",
		Source:   zapOtherThreadsSource,
		Events:   []*ebpf.Event{ebpf.NewKprobeEvent("kprobe__zap_other_threads", "zap_other_threads", -1)},
		CanMerge: true,
	})
	m.RegisterOnceTable("zap_other_threads_events", monitor.RenderHandler(zapOtherThreadEvent{}, nil))
	factory.Register(m)
}
