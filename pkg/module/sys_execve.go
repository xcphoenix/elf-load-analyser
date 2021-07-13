package module

import (
	_ "embed" // for embed ebpf source
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"strings"
)

type sysExecveEvent struct {
	enhance.TimeEventResult
}

func (e sysExecveEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("start call"))
}

type sysExecveRetEvent struct {
	enhance.TimeEventResult
	Ret int8
}

func (s sysExecveRetEvent) Render() *data.AnalyseData {
	if s.Ret != 0 {
		return data.NewOtherAnalyseData(data.RunErrStatus, fmt.Sprintf("execve failed, return %d", s.Ret), nil)
	}
	return data.NewAnalyseData(form.NewMarkdown("execve success"))
}

//go:embed src/execve.c.k
var execveSource string

func init() {
	entry := "call_event"
	fnName := bpf.GetSyscallFnName("execve")
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "syscall:execve",
		Source: execveSource,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("syscall__execve", fnName, -1),
			ebpf.NewKretprobeEvent("do_ret_sys_execve", fnName, -1),
		},
		LazyInit: func(mm *monitor.Monitor, param ebpf.PreParam) bool {
			mm.IsEnd = len(param.Interp) == 0 || !strings.Contains(param.Interp, "ld-linux")
			return false
		},
	})
	m.RegisterOnceTable(entry, monitor.RenderHandler(sysExecveEvent{}, nil))
	m.RegisterOnceTable("ret_event", monitor.RenderHandler(sysExecveRetEvent{}, nil))
	m.SetMark("ret_event", monitor.EndTag)
	factory.Register(m)
}
