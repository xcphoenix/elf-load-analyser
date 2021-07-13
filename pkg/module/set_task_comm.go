package module

import (
	_ "embed" // embed for __set_task_comm
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/x__set_task_comm.c.k
var xSetTaskCommSource string

type xSetTaskCommEvent struct {
	enhance.TimeEventResult
	Comm [256]byte
}

func (x xSetTaskCommEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("设置进程名：" + helper.TrimBytes2Str(x.Comm[:])))
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:     "__set_task_comm",
		Source:   xSetTaskCommSource,
		Events:   []*ebpf.Event{ebpf.NewKprobeEvent("kprobe__x__set_task_comm", "__set_task_comm", -1)},
		CanMerge: true,
	})
	m.RegisterOnceTable("x__set_task_comm_events", monitor.RenderHandler(xSetTaskCommEvent{}, nil))
	factory.Register(m)
}
