package module

import (
	_ "embed" // embed for arch_setup_additional_pages
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance/virtualm"
)

//go:embed src/arch_setup_additional_pages.c.k
var archSetupAdditionalPagesSource string

type xInstallSpecialMappingEvent struct {
	enhance.TimeEventResult
	Addr  uint64
	Len   uint64
	Flags uint64
	Name  [256]byte
}

func (x xInstallSpecialMappingEvent) Render() *data.AnalyseData {
	mappedName := data.TrimBytes2Str(x.Name[:])
	return data.NewAnalyseData(form.NewMarkdown("映射特殊页: "+mappedName)).
		PutExtra(virtualm.VmaFlag, virtualm.MapVmaEvent{
			NewVma: virtualm.BuildVma(x.Addr, x.Addr+x.Len, x.Flags, 0, mappedName),
		})
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "_install_special_mapping",
		Source:  archSetupAdditionalPagesSource,
		Events: []*bcc.Event{
			bcc.NewKprobeEvent("kprobe__x_install_special_mapping", "_install_special_mapping", -1),
		},
		CanMerge: true,
	})
	m.RegisterTable("x_install_special_mapping_events", true, modules.RenderHandler(xInstallSpecialMappingEvent{}, nil))
	factory.Register(m)
}
