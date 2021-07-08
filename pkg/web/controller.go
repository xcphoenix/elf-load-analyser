package web

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/core/xflag"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/render"
	"github.com/xcphoenix/elf-load-analyser/pkg/render/plugin"
	"net"
	"net/http"
	"strconv"
	"syscall"
)

var (
	port              uint
	analyseDataCenter []*data.AnalyseData
)

var XFlagSet = xflag.OpInject(&xflag.FlagValue{
	Target: &port,
	Name:   "port",
	Usage:  "web port, use random port value by default",
	Validator: func() error {
		if port >= 65535 {
			return fmt.Errorf("invalid port: %v", port)
		}
		return nil
	},
})

// VisualAnalyseData 数据展示
func VisualAnalyseData(p *data.Pool) {
	renderedData, reqHandlers := render.DoAnalyse(p)
	go startWebService(renderedData, reqHandlers)
}

func startWebService(d []*data.AnalyseData, reqHandlers []plugin.ReqHandler) {
	analyseDataCenter = d
	http.Handle("/", FrontedService())
	http.HandleFunc("/api/report", AnalyseReportService)

	for _, handler := range reqHandlers {
		http.HandleFunc(handler.Pattern, handler.Handler)
	}

	for {
		addr, err := getAnyFreeAddr()
		if err != nil {
			log.Fatalf("Cannot start web server: %v", err)
		}

		//goland:noinspection ALL
		log.Infof("Try to start web server on http://%s", addr)
		log.Info("you can view analysis report through this link")
		err = http.ListenAndServe(addr, nil)
		if err != nil {
			errType := syscall.EADDRINUSE
			if port != 0 && errors.Is(err, errType) {
				log.Warnf("Failed to start web service on defined port: %d, %v", port, err)
				log.Warn("Retry use random port...")
				port = 0
				continue
			}
			log.Fatalf("Failed to start web service, %v", err)
		}
		break
	}
}

func getAnyFreeAddr() (string, error) {
	if port != 0 {
		return "0.0.0.0:" + strconv.Itoa(int(port)), nil
	}

	var listener *net.TCPListener
	var addr *net.TCPAddr
	var err error

	if addr, err = net.ResolveTCPAddr("tcp", "0.0.0.0:0"); err == nil {
		listener, err = net.ListenTCP("tcp", addr)
	}
	if err != nil {
		return "", err
	}

	defer func() {
		if listener == nil {
			return
		}
		e := listener.Close()
		if e != nil {
			log.Fatalf("Release random port error, %v", e)
		}
	}()
	return "0.0.0.0:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), nil
}
