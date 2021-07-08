package module

import (
	_ "embed" // for embed bcc source
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

// about stack 512byte limit,
// see: https://stackoverflow.com/questions/53627094/ebpf-track-values-longer-than-stack-size
//go:embed src/alloc_bprm.c.k
var allowBprmSource string

type allocBprmEvent struct {
	enhance.TimeEventResult
	Filename    [256]byte
	Fdpath      [256]byte
	Interp      [256]byte
	CurTopOfMem uint64
	RlimCur     uint64
	RlimMax     uint64
}

func (a allocBprmEvent) Render() *data.AnalyseData {
	res := data.NewSet(
		form.NewMarkdown("分配空间，保存二进制文件参数"),
		form.NewFmtList(form.Fmt{
			{"filename: %q", helper.TrimBytes2Str(a.Filename[:])},
			{"fdpath:   %q", helper.TrimBytes2Str(a.Fdpath[:])},
			{"interp:   %q", helper.TrimBytes2Str(a.Interp[:])},
			{"rlimit stack cur:   0x%X", a.RlimCur},
			{"rlimit stack max:   0x%X", a.RlimMax},
			{"current of top mem: 0x%X", a.CurTopOfMem},
		}),
	)
	return data.NewAnalyseData(res)
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Name:   "alloc_bprm",
		Source: allowBprmSource,
		Events: []*bcc.Event{
			bcc.NewKretprobeEvent("kretprobe__alloc_bprm", "alloc_bprm", -1),
		},
		IsEnd:    false,
		CanMerge: true,
	})
	m.RegisterOnceTable("alloc_bprm_events", modules.RenderHandler(allocBprmEvent{}, nil))
	factory.Register(m)
}
