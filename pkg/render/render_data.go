package render

import (
	"debug/elf"
	"errors"
	"net/http"
	"sort"
	"sync"

	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"

	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
)

var dataCenter = make([]*data.AnalyseData, 3)
var dataHandlerList orderedDataRenderList

// RegisterHandler 注册数据处理器
func RegisterHandler(name string, d DataRenderHandler, order int) {
	dataHandlerList = append(dataHandlerList, orderedDataRender{
		render: d,
		order:  order,
		name:   name,
	})
}

type orderedDataRender struct {
	render DataRenderHandler
	order  int
	name   string
}

type orderedDataRenderList []orderedDataRender

func (o orderedDataRenderList) Len() int {
	return len(o)
}

func (o orderedDataRenderList) Less(i, j int) bool {
	if o[i].order != o[j].order {
		return o[i].order > o[j].order
	}
	return o[i].name > o[j].name
}

func (o orderedDataRenderList) Swap(i, j int) {
	o[i], o[j] = o[j], o[i]
}

// DataRenderHandler 渲染数据处理器
type DataRenderHandler interface {
	Handle(dataCollection []*data.AnalyseData) []ReqHandler
}

// ReqHandler 请求处理器
type ReqHandler struct {
	Pattern string
	Handler func(http.ResponseWriter, *http.Request)
}

// BuildReqHandler 创建请求处理器
func BuildReqHandler(pattern string, handler func(http.ResponseWriter, *http.Request)) ReqHandler {
	return ReqHandler{Pattern: pattern, Handler: handler}
}

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
			log.Errorf("Invalid elf file, %v", e)
		} else {
			log.Errorf("Analyse target binary form error, %v", e)
		}
	}
	param.Header, param.IsDyn, param.Interp = elfRender.elfData()
	d, _ = doRender(elfRender)
	dataCenter[1] = d
}

// DoAnalyse 执行数据分析
func DoAnalyse(p *factory.Pool) ([]*data.AnalyseData, []ReqHandler) {
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
	var reqHandlers []ReqHandler
	sort.Sort(dataHandlerList)
	for _, handler := range dataHandlerList {
		tmpHandlers := handler.render.Handle(dataList)
		reqHandlers = append(reqHandlers, tmpHandlers...)
	}

	d, err := doRender(NewAnalyseRender(dataList))
	if err != nil {
		log.Errorf("ChartsRender analyse data error, %v", err)
	}
	dataCenter[2] = d
	return dataCenter, reqHandlers
}
