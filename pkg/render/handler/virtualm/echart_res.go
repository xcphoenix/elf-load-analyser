package virtualm

import (
	_ "embed" // embed echarts assets file
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/plugin"
	"net/http"
)

//go:embed res/echarts.min.js
var echartsJs string

//go:embed res/bulma.min.css
var echartsCSS string

func BuildAssertReqHandler() []plugin.ReqHandler {
	jsHandler := plugin.BuildReqHandler("/assets/echarts.min.js", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(echartsJs))
		if err != nil {
			log.Warnf("Js resource load error, %v", err)
		}
	})
	cssHandler := plugin.BuildReqHandler("/assets/bulma.min.css", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(echartsCSS))
		if err != nil {
			log.Warnf("Js resource load error, %v", err)
		}
	})
	return []plugin.ReqHandler{jsHandler, cssHandler}
}
