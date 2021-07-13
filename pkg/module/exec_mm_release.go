package module

import (
	_ "embed" // embed for exec_mm_release
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/exec_mm_release.c.k
var execMmReleaseSource string

type execMmReleaseEvent struct {
	enhance.TimeEventResult
}

func (e execMmReleaseEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("释放进程中旧的虚拟内存"))
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:     "exec_mm_release",
		Source:   execMmReleaseSource,
		Events:   []*ebpf.Event{ebpf.NewKprobeEvent("kprobe__exec_mm_release", "exec_mm_release", -1)},
		CanMerge: true,
	})
	m.RegisterOnceTable("exec_mm_release_events", monitor.RenderHandler(execMmReleaseEvent{}, nil))
	factory.Register(m)
}
