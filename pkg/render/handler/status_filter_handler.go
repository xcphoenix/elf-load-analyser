package handler

import (
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/plugin"
)

func init() {
	plugin.RegisterHandler(&statusFilterHandler{}, 0x1)
}

type statusFilterHandler struct{}

func (s statusFilterHandler) Handle(dataCollection []*data.AnalyseData) ([]*data.AnalyseData, []plugin.ReqHandler) {
	newDataCollection := make([]*data.AnalyseData, len(dataCollection))

	var cnt = 0
	for _, d := range dataCollection {
		if data.IsValid(d.Status) {
			newDataCollection[cnt] = d
			cnt++
		}
	}

	return newDataCollection[:cnt], nil
}
