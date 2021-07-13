package module

import (
	_ "embed" // embed for arch_setup_additional_pages
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
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
	mappedName := helper.TrimBytes2Str(x.Name[:])
	return data.NewAnalyseData(form.NewMarkdown("映射特殊页: "+mappedName)).
		PutExtra(virtualm.VmaFlag, virtualm.MapVmaEvent{
			NewVma: virtualm.BuildVma(x.Addr, x.Addr+x.Len, x.Flags, 0, mappedName),
		})
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "_install_special_mapping",
		Source: archSetupAdditionalPagesSource,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__x_install_special_mapping", "_install_special_mapping", -1),
		},
		CanMerge: true,
	})
	m.RegisterTable("x_install_special_mapping_events", true, monitor.RenderHandler(xInstallSpecialMappingEvent{}, nil))
	factory.Register(m)
}
