package module

import (
	_ "embed" // embed for ebpf source
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
)

//go:embed src/setup_new_exec.c.k
var setupNewExecSource string

type setupNewExecEvent struct {
	enhance.TimeEventResult
	RlimCur uint64
	RlimMax uint64
}

func (s setupNewExecEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(data.NewSet(
		form.NewMarkdown("初始化程序"),
		form.NewFmtList(form.Fmt{
			{"rlim_cur: 0x%x", s.RlimCur},
			{"rlim_max: 0x%x", s.RlimMax},
		}),
	))
}

type setupNewExecRetEvent struct {
	enhance.TimeEventResult
	TaskSize uint64
}

func (s setupNewExecRetEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown(fmt.Sprintf("虚拟空间大小：0x%x", s.TaskSize))).
		PutExtra(virtualm.VmaFlag, virtualm.NewVMIndicatrixEvent("TaskSize", s.TaskSize))
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "setup_new_exec",
		Source: setupNewExecSource,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__setup_new_exec", "setup_new_exec", -1),
			ebpf.NewKretprobeEvent("kretprobe__setup_new_exec", "setup_new_exec", -1),
		},
		CanMerge: true,
	})
	m.RegisterOnceTable("setup_new_exec_events", monitor.RenderHandler(setupNewExecEvent{}, nil))
	m.RegisterOnceTable("setup_new_exec_ret_events", monitor.RenderHandler(setupNewExecRetEvent{}, nil))
	factory.Register(m)
}
