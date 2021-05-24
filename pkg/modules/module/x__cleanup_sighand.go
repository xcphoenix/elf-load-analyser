package module

import (
	_ "embed" // embed for __cleanup_sighand
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules"
	"github.com/xcphoenix/elf-load-analyser/pkg/modules/perf"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/enhance"
)

//go:embed src/x__cleanup_sighand.c.k
var xCleanupSighandSource string

type xCleanupSighandEvent struct {
	enhance.TimeEventResult
}

func (z xCleanupSighandEvent) Render() *data.AnalyseData {
	return data.NewAnalyseData(form.NewMarkdown("使当前进程的信号处理描述符私有"))
}

func init() {
	m := perf.NewPerfResolveMm(&modules.MonitorModule{
		Monitor: "unshare_sighand",
		// __cleanup_sighand 是 unshare_sighand 的最后一步，由于无法监控 unshare_sighand 函数，这里用 __clean_sighand 来替代
		Source:   xCleanupSighandSource,
		Events:   []*bcc.Event{bcc.NewKprobeEvent("kprobe__x__cleanup_sighand", "__cleanup_sighand", -1)},
		CanMerge: true,
	})
	m.RegisterOnceTable("cleanup_sighand_events", modules.RenderHandler(xCleanupSighandEvent{}, nil))
	factory.Register(m)
}
