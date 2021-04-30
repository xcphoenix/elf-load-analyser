package enhance

import (
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/plugin"
)

func init() {
	plugin.RegisterPlugin(&statusFilterHandler{}, 0x1)
}

type statusFilterHandler struct{}

func (s statusFilterHandler) Handle(dataCollection []*data.AnalyseData) ([]*data.AnalyseData, []plugin.ReqHandler) {
	newDataCollection := make([]*data.AnalyseData, len(dataCollection))

	var cnt = 0
	for _, d := range dataCollection {
		if helper.IsNotNil(d) && data.IsValid(d.Status) {
			newDataCollection[cnt] = d
			cnt++
		}
	}

	return newDataCollection[:cnt], nil
}
