package module

import (
	_ "embed" // embed for bcc source
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/handler/virtualm"
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
		form.NewList(fmt.Sprintf("rlim_cur: 0x%x", s.RlimCur)),
		form.NewList(fmt.Sprintf("rlim_max: 0x%x", s.RlimMax)),
	))
}

type setupNewExecRetEvent struct {
	enhance.TimeEventResult
	TaskSize uint64
}

func (s setupNewExecRetEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown(fmt.Sprintf("虚拟空间大小：0x%x", s.TaskSize))).
		PutExtra(virtualm.VmaFlag, virtualm.TaskSizeVMEvent{TaskSize: s.TaskSize})
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "setup_new_exec",
		Source:  setupNewExecSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__setup_new_exec", "setup_new_exec", -1),
			bcc.NewKretprobeEvent("kretprobe__setup_new_exec", "setup_new_exec", -1),
		},
	})
	m.RegisterOnceTable("setup_new_exec_events", modules.RenderHandler(&setupNewExecEvent{}))
	m.RegisterOnceTable("setup_new_exec_ret_events", modules.RenderHandler(&setupNewExecRetEvent{}))
	factory.Register(m.Mm())
}
