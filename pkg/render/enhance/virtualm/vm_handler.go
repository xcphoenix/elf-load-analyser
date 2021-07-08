package virtualm

import (
	"bytes"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/plugin"
	"net/http"
	"strconv"
	"strings"

	_ "embed" // embed for step js func
)

const (
	VmaFlag = "_VMA_"
)

//go:embed vm_step.txt
var stepJsFunc string

func init() {
	plugin.RegisterPlugin(newVMShowDataHandler(), 0x100)
}

type vmShowDataHandler struct {
	htmlCache map[string][]byte
}

func newVMShowDataHandler() *vmShowDataHandler {
	return &vmShowDataHandler{htmlCache: map[string][]byte{}}
}

func (v vmShowDataHandler) Handle(dataCollection []*data.AnalyseData) ([]*data.AnalyseData, []plugin.ReqHandler) {
	vm := newVirtualMemory()
	const apiPrefix = "/vm/model/"
	cnt := 0
	var lastIdx = new(int)

	var vmHandlers []plugin.ReqHandler
	for _, analyseData := range dataCollection {
		if val, ok := analyseData.ExtraByKey(VmaFlag); ok {
			event, ok := val.(VMEvent)
			if !ok {
				continue
			}

			diff := vm.ApplyEvent(event)

			url := apiPrefix + strconv.Itoa(cnt)
			cnt++
			bar := vm.RenderCharts("/assets/")
			vmHandlers = append(vmHandlers, plugin.BuildReqHandler(url, func(w http.ResponseWriter, r *http.Request) {
				if _, ok := v.htmlCache[url]; !ok {
					var buf bytes.Buffer
					err := bar.Render(&buf)
					if err != nil {
						log.Warnf("Render vm model failed, %v", err)
					}

					// 暴力添加自定义 js go-echarts添加自定义函数会被无情转义...
					var bufBytes = buf.Bytes()
					var idx = strings.LastIndex(url, "/")
					if idx >= 0 {
						var curIdx = url[idx+1:]
						replacedStr := strings.Replace(string(bufBytes), "</body>", "<script>"+
							fmt.Sprintf(stepJsFunc, curIdx, *lastIdx)+
							"</script></body>", 1)
						bufBytes = []byte(replacedStr)
					}

					v.htmlCache[url] = bufBytes
				}
				_, err := w.Write(v.htmlCache[url])
				if err != nil {
					log.Warnf("Render vm model failed, %v", err)
				}
			}))

			analyseData.Change(func(set data.ContentSet) data.Content {
				md := form.NewMarkdown().AppendLink("内存模型", url)
				if diff = strings.TrimSpace(diff); len(diff) != 0 {
					md.Append(form.NewMarkdown("VMA 变化: ")).AppendCode("shell", diff)
				} else {
					md.Append(form.NewMarkdown("<br />"))
				}
				return data.NewSet(md, set)
			})
		}
	}

	*lastIdx = cnt - 1

	return dataCollection, append(vmHandlers, BuildAssertReqHandler()...)
}
