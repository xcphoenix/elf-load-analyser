package module

import (
	_ "embed" // embed for mprotect_fixup
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
)

//go:embed src/mprotect_fixup.c.k
var mprotectFixupSource string

type mprotectFixupEvent struct {
	enhance.TimeEventResult

	VmaEnd      uint64
	VmaStart    uint64
	RegionEnd   uint64
	RegionStart uint64
	Flags       uint64
}

func (m mprotectFixupEvent) Render() *data.AnalyseData {
	res := data.NewSet(
		form.NewMarkdown("修改栈 vma 权限"),
		form.NewFmtList(form.Fmt{
			{"修改的 vma: [%x, %x]", m.VmaStart, m.VmaEnd},
			{"修改的区域: [%x, %x]", m.RegionStart, m.RegionEnd},
			{"flags: %x", m.Flags},
		}),
	)
	return data.NewAnalyseData(res).
		PutExtra(virtualm.VmaFlag, virtualm.MprotectFixupEvent{
			Start: m.RegionStart,
			End:   m.RegionEnd,
			Flags: m.Flags,
		})
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Name:   "mprotect_fixup",
		Source: mprotectFixupSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__setup_arg_pages", "setup_arg_pages", -1),
			bcc.NewKprobeEvent("kprobe__mprotect_fixup", "mprotect_fixup", -1),
		},
	})

	m.RegisterOnceTable("mprotect_fixup_events", modules.RenderHandler(mprotectFixupEvent{}, nil))
	factory.Register(m)
}
