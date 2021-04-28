package plugin

import (
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"net/http"
	"sort"
)

var pluginList []RenderPlugin
var plugin2Priority = make(map[int]int)

// RegisterPlugin 注册数据处理器
func RegisterPlugin(d RenderPlugin, priority int) {
	idx := len(pluginList)

	pluginList = append(pluginList, d)
	plugin2Priority[idx] = priority
}

func RenderPlugins() []RenderPlugin {
	// sort
	sort.Slice(pluginList, func(i, j int) bool {
		if plugin2Priority[i] < plugin2Priority[j] {
			plugin2Priority[i], plugin2Priority[j] = plugin2Priority[j], plugin2Priority[i]
			return true
		}
		return false
	})
	return pluginList
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

// RenderPlugin 渲染数据处理器
type RenderPlugin interface {
	Handle(dataCollection []*data.AnalyseData) ([]*data.AnalyseData, []ReqHandler)
}
