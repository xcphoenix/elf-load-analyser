package web

import (
	"encoding/json"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
	"net/http"
	"sync"
)

var serialDataBytes []byte
var once sync.Once

func AnalyseReportService(w http.ResponseWriter, _ *http.Request) {
	once.Do(func() {
		var err error
		serialDataBytes, err = json.Marshal(analyseDataCenter)
		if err != nil {
			log.Errorf("Serialize report data failed, %v", err)
		}
	})
	_, _ = w.Write(serialDataBytes)
}
