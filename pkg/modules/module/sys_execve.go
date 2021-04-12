package module

import (
	_ "embed" // for embed bcc source
	"fmt"

	"github.com/xcphoenix/elf-load-analyser/pkg/factory"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/enhance"
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
		return data.NewErrAnalyseData("", data.RunError, fmt.Sprintf("execve failed, return %d", s.Ret))
	}
	return data.NewAnalyseData(form.NewMarkdown("execve success"))
}

//go:embed src/execve.c.k
var execveSource string

func init() {
	entry := "call_event"
	fnName := bpf.GetSyscallFnName("execve")
	m := modules.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "syscall:execve",
		Source:  execveSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("syscall__execve", fnName, -1),
			bcc.NewKretprobeEvent("do_ret_sys_execve", fnName, -1),
		},
		IsEnd: true,
	})
	m.RegisterOnceTable(entry, func(d []byte) (*data.AnalyseData, error) {
		return modules.Render(d, &sysExecveEvent{}, true)
	})
	m.RegisterOnceTable("ret_event", func(d []byte) (*data.AnalyseData, error) {
		return modules.Render(d, &sysExecveRetEvent{}, true)
	})
	m.SetMark(entry, enhance.StartMark)
	factory.Register(m.Mm())
}
