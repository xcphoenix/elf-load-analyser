package module

import (
	_ "embed" // embed for do_close_on_exec
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/do_close_on_exec.c.k
var doCloseOnExecSource string

type doCloseOnExecEvent struct {
	enhance.TimeEventResult
}

func (z doCloseOnExecEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("在进程打开的文件描述符表中，关闭设置了 close_on_exec 状态的文件"))
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:     "do_close_on_exec",
		Source:   doCloseOnExecSource,
		Events:   []*ebpf.Event{ebpf.NewKprobeEvent("kprobe__do_close_on_exec", "do_close_on_exec", -1)},
		CanMerge: true,
	})
	m.RegisterOnceTable("do_close_on_exec_events", monitor.RenderHandler(doCloseOnExecEvent{}, nil))
	factory.Register(m)
}
