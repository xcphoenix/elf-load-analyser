package module

import (
	_ "embed" // embed for set_mm_exe_file
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/set_mm_exe_file.c.k
var setMmExeFileSource string

type setMMExeFileEvent struct {
	enhance.TimeEventResult
	ExeFilename [256]byte
}

func (s setMMExeFileEvent) Render() *data.AnalyseData {
	res := form.NewMarkdown("修改 mm->exe_file 为 " + data.TrimBytes2Str(s.ExeFilename[:])).
		WithContents("> 可以通过 /proc/[pid]/exe 查看")
	return data.NewAnalyseData(res)
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "set_mm_exe_file",
		Source:  setMmExeFileSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__set_mm_exe_file", "set_mm_exe_file", -1),
		},
	})
	m.RegisterOnceTable("set_mm_exe_file_events", modules.RenderHandler(&setMMExeFileEvent{}))
	factory.Register(m.Mm())
}
