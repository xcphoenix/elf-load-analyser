package virtualm

import (
	"bytes"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/data/form"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
	"github.com/xcphoenix/elf-load-analyser/pkg/render"
	"net/http"
	"strconv"
	"strings"
)

const VmaFlag = "_VMA_"

func init() {
	render.RegisterHandler("vm_render", NewVMShowDataHandler(), 0x10)
}

type VMShowDataHandler struct {
	htmlCache map[string][]byte
}

func NewVMShowDataHandler() *VMShowDataHandler {
	return &VMShowDataHandler{htmlCache: map[string][]byte{}}
}

func (v VMShowDataHandler) Handle(dataCollection []*data.AnalyseData) []render.ReqHandler {
	vm := newVirtualMemory()
	const apiPrefix = "/vm/model/"
	cnt := 0

	var vmHandlers []render.ReqHandler
	for _, analyseData := range dataCollection {
		if val, ok := analyseData.ExtraByKey(VmaFlag); ok {
			event, ok := val.(VMEvent)
			if !ok {
				continue
			}
			diff := vm.ApplyEvent(event)
			url := apiPrefix + strconv.Itoa(cnt)
			bar := vm.ChartsRender("/assets/")
			vmHandlers = append(vmHandlers, render.BuildReqHandler(url, func(w http.ResponseWriter, r *http.Request) {
				if _, ok := v.htmlCache[url]; !ok {
					var buf bytes.Buffer
					err := bar.Render(&buf)
					if err != nil {
						log.Warnf("Render vm model failed, %v", err)
					}
					v.htmlCache[url] = buf.Bytes()
				}
				_, err := w.Write(v.htmlCache[url])
				if err != nil {
					log.Warnf("Render vm model failed, %v", err)
				}
			}))
			cnt++
			analyseData.Change(func(set data.ContentSet) data.Content {
				md := form.NewMarkdown().AppendLink("内存模型", url)
				if len(strings.TrimSpace(diff)) != 0 {
					md.Append(form.NewMarkdown("VMA 变化: ")).AppendCode("shell", diff)
				} else {
					md.Append(form.NewMarkdown("<br />"))
				}
				return data.NewSet(md, set)
			})
		}
	}
	return append(vmHandlers, BuildAssertReqHandler()...)
}
