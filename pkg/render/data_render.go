package render

import (
	"debug/elf"
	"errors"
	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	_ "github.com/xcphoenix/elf-load-analyser/pkg/render/enhance" // import plugin handlers
	"github.com/xcphoenix/elf-load-analyser/pkg/render/plugin"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
)

var dataCenter = make([]*data.AnalyseData, 3)

// PreAnalyse 环境预分析
func PreAnalyse(param *bcc.PreParam) {
	// env
	d, _ := doRender(NewEnvRender())
	dataCenter[0] = d
	// elf
	elfRender, e := NewElfRender(param.Path)
	if e != nil {
		var formatErr *elf.FormatError
		if ok := errors.As(e, &formatErr); ok {
			log.Fatalf("Invalid elf file, %v", e)
		} else {
			log.Fatalf("Analyse target binary form error, %v", e)
		}
	}
	param.Header, param.IsDyn, param.Interp = elfRender.elfData()

	d, _ = doRender(elfRender)
	dataCenter[1] = d
}

// DoAnalyse 执行数据分析
func DoAnalyse(p *data.Pool) ([]*data.AnalyseData, []plugin.ReqHandler) {
	dataList := p.Data()

	var wg sync.WaitGroup
	wg.Add(len(dataList))
	for _, analyseData := range dataList {
		analyseData := analyseData
		go func() {
			defer wg.Done()
			analyseData.WaitReady()
		}()
	}

	wg.Wait()
	log.Info("The collection of analyse data is all ready")
	log.Info("Start to render data")

	var reqHandlers []plugin.ReqHandler
	for _, handler := range plugin.RenderPlugins() {
		modDataList, tmpHandlers := handler.Handle(dataList)
		dataList = modDataList
		if len(tmpHandlers) > 0 {
			reqHandlers = append(reqHandlers, tmpHandlers...)
		}
	}

	d, _ := doRender(NewAnalyseRender(dataList))
	dataCenter[2] = d
	return dataCenter, reqHandlers
}
