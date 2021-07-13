package module

import (
	_ "embed" // for embed ebpf source
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/bprm_execve.c.k
var bprmExecveSrc string

type bprmExecveEvent struct {
	enhance.TimeEventResult
}

func (a bprmExecveEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("开始执行新程序..."))
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "bprm_execve",
		Source: bprmExecveSrc,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__bprm_execve", "bprm_execve", -1),
		},
		CanMerge: true,
	})
	m.RegisterOnceTable("bprm_execve_events", monitor.RenderHandler(bprmExecveEvent{}, nil))
	factory.Register(m)
}
