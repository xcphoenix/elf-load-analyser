package render

import (
	"debug/elf"
	"errors"
	"net/http"

	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"

	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
)

var dataCenter = make([]*data.AnalyseData, 3)
var dataHandlerList []DataRenderHandler

// RegisterHandler 注册数据处理器
func RegisterHandler(d DataRenderHandler) {
	dataHandlerList = append(dataHandlerList, d)
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
	param.Header, param.IsDyn, param.Interp = elfRender.ElfData()
	d, _ = doRender(elfRender)
	dataCenter[1] = d
}

// DoAnalyse 执行数据分析
func DoAnalyse(p *factory.Pool) ([]*data.AnalyseData, []ReqHandler) {
	dataList := p.Data()

	var reqHandlers []ReqHandler
	for _, handler := range dataHandlerList {
		tmpHandlers := handler.Handle(dataList)
		reqHandlers = append(reqHandlers, tmpHandlers...)
	}

	d, err := doRender(NewAnalyseRender(dataList))
	if err != nil {
		log.Errorf("ChartsRender analyse data error, %v", err)
	}
	dataCenter[2] = d
	return dataCenter, reqHandlers
}
