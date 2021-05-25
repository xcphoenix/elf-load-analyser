package module

import (
	_ "embed" // for embed bcc source
	"fmt"
	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
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
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "syscall:execve",
		Source:  execveSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("syscall__execve", fnName, -1),
			bcc.NewKretprobeEvent("do_ret_sys_execve", fnName, -1),
		},
		LazyInit: func(mm *modules.MonitorModule, param bcc.PreParam) bool {
			mm.IsEnd = len(param.Interp) == 0 || !strings.Contains(param.Interp, "ld-linux")
			return false
		},
	})
	m.RegisterOnceTable(entry, modules.RenderHandler(sysExecveEvent{}, nil))
	m.RegisterOnceTable("ret_event", modules.RenderHandler(sysExecveRetEvent{}, nil))
	factory.Register(m)
}
