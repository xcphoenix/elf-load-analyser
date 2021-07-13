package module

import (
	_ "embed" // embed for finalize_about
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
)

//go:embed src/finalize_about.c.k
var finalizeAboutSource string

type finalizeExecEvent struct {
	enhance.TimeEventResult
	EndCode    uint64
	StartCode  uint64
	EndData    uint64
	StartData  uint64
	StartStack uint64
}

func (f finalizeExecEvent) Render() *data.AnalyseData {
	res := data.NewSet(
		form.NewFmtList(form.Fmt{
			{"代码段: [%x, %x]", f.StartCode, f.EndCode},
			{"数据段: [%x, %x]", f.StartData, f.EndData},
			{"栈的开始地址: %x", f.StartStack},
		}),
		form.NewMarkdown("在将执行权交给用户程序或解释器前,存储栈资源限制"),
	)
	return data.NewAnalyseData(res).
		PutExtra(virtualm.VmaFlag, virtualm.NewVMIndicatrixEvent("StartStack", f.StartStack))
}

type startThreadEvent struct {
	enhance.TimeEventResult
	Entry uint64
	NewSp uint64
}

func (s startThreadEvent) Render() *data.AnalyseData {
	res := data.NewSet(
		form.NewMarkdown("准备将程序执行权交给用户程序(或解释器)"),
		form.NewFmtList(form.Fmt{
			{"程序入口地址为(eip): %x", s.Entry},
			{"栈顶地址(esp): %x", s.NewSp},
		}),
	)
	return data.NewAnalyseData(res)
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "finalize",
		Source: finalizeAboutSource,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__finalize_exec", "finalize_exec", -1),
			ebpf.NewKprobeEvent("kprobe__start_thread", "start_thread", -1),
		},
		CanMerge: true,
	})
	m.RegisterOnceTable("finalize_exec_events", monitor.RenderHandler(finalizeExecEvent{}, nil))
	m.RegisterOnceTable("start_thread_events", monitor.RenderHandler(startThreadEvent{}, nil))
	factory.Register(m)
}
