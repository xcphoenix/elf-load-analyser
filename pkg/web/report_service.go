package web

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
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
			log.Fatalf("Serialize report data failed, %v", err)
		}
	})
	_, _ = w.Write(serialDataBytes)
}
