package module

import (
	_ "embed" // for embed ebpf source
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
)

//go:embed src/begin_new_exec.c.k
var beginNewExecSrc string

type beginNewExecEvent struct {
	enhance.TimeEventResult

	VmaCnt      uint32
	VmaStart    uint64
	VmaEnd      uint64
	VmaFlags    uint64
	VmaPageProt uint64
}

func (a beginNewExecEvent) Render() *data.AnalyseData {
	result := data.NewSet(form.NewMarkdown("开始为新程序做准备"))

	// exec_mmap
	result.Combine(form.NewMarkdown("映射二进制参数内存结构体到当前进程中"))
	if a.VmaCnt != 1 {
		return data.NewOtherAnalyseData(data.BugStatus, "数据异常！", nil)
	}
	result.Combine(form.NewFmtList(form.Fmt{
		{"Vma [0x%x, 0x%x]", a.VmaStart, a.VmaEnd},
		{"Vma flags: %x Vma prot: %x", a.VmaFlags, a.VmaPageProt},
	}))

	return data.NewAnalyseData(result).
		PutExtra(virtualm.VmaFlag, virtualm.MapVmaEvent{
			NewVma: virtualm.BuildVma(a.VmaStart, a.VmaEnd, a.VmaFlags, 0, virtualm.StackMap),
		})
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "begin_new_exec",
		Source: beginNewExecSrc,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__begin_new_exec", "begin_new_exec", -1),
		},
		CanMerge: true,
	})
	m.RegisterOnceTable("begin_new_exec_events", monitor.RenderHandler(beginNewExecEvent{}, nil))
	factory.Register(m)
}
