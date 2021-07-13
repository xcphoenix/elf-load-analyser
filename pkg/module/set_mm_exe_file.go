package module

import (
	_ "embed" // embed for set_mm_exe_file
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/set_mm_exe_file.c.k
var setMmExeFileSource string

type setMMExeFileEvent struct {
	enhance.TimeEventResult
	ExeFilename [256]byte
}

func (s setMMExeFileEvent) Render() *data.AnalyseData {
	res := form.NewMarkdown("修改 mm->exe_file 为 " + helper.TrimBytes2Str(s.ExeFilename[:])).
		WithContents("> 可以通过 /proc/[pid]/exe 查看")
	return data.NewAnalyseData(res)
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "set_mm_exe_file",
		Source: setMmExeFileSource,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__set_mm_exe_file", "set_mm_exe_file", -1),
		},
		CanMerge: true,
	})
	m.RegisterOnceTable("set_mm_exe_file_events", monitor.RenderHandler(setMMExeFileEvent{}, nil))
	factory.Register(m)
}
