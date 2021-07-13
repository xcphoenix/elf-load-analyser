package module

import (
	_ "embed" // embed for move_page_tables
	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/ebpf"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/monitor"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/move_page_tables.c.k
var movePageTablesSource string

type movePageTablesEvent struct {
	enhance.TimeEventResult

	OldStart uint64
	NewStart uint64
	Length   uint64
}

func (m movePageTablesEvent) Render() *data.AnalyseData {
	res := form.NewMarkdown(fmt.Sprintf("向下移动页表，旧地址: %x, 新地址: %x, 长度: %x", m.OldStart, m.NewStart, m.Length))
	return data.NewAnalyseData(res)
}

func init() {
	m := monitor.NewPerfMonitor(&monitor.Monitor{
		Name:   "move_page_tables",
		Source: movePageTablesSource,
		Events: []*ebpf.Event{
			ebpf.NewKprobeEvent("kprobe__move_page_tables", "move_page_tables", -1),
		},
		CanMerge: true,
	})
	m.RegisterOnceTable("move_page_tables_events", monitor.RenderHandler(movePageTablesEvent{}, nil))
	factory.Register(m)
}
