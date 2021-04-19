package web

import (
	"errors"
	_ "net/http/pprof"

	"fmt"
	"github.com/xcphoenix/elf-load-analyser/pkg/core/xflag"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
	"github.com/xcphoenix/elf-load-analyser/pkg/render"
	"net"
	"net/http"
	"strconv"
	"syscall"
)

var (
	port              uint
	analyseDataCenter []*data.AnalyseData
)

var XFlagSet = xflag.OpInject(&port, "port", uint(0), "web server port, default use random",
	func() error {
		if port >= 65535 {
			return fmt.Errorf("invalid port: %v", port)
		}
		return nil
	})

// VisualAnalyseData 数据展示
func VisualAnalyseData(p *factory.Pool) {
	renderedData, reqHandlers := render.DoAnalyse(p)
	go startWebService(renderedData, reqHandlers)
}

func startWebService(d []*data.AnalyseData, reqHandlers []render.ReqHandler) {
	analyseDataCenter = d
	http.Handle("/", FrontedService())
	http.HandleFunc("/api/report", AnalyseReportService)

	for _, handler := range reqHandlers {
		http.HandleFunc(handler.Pattern, handler.Handler)
	}

	// 程序的主流程，若定义的端口被占用，使用随机端口
	for {
		addr, err := getAnyFreeAddr()
		if err != nil {
			log.Errorf("Cannot start web server: %v", err)
		}

		//goland:noinspection ALL
		log.Infof(log.Em("Try to start web server on %s"), "http://"+addr)
		log.Infof(log.Em("you can view analysis report through this link"))
		err = http.ListenAndServe(addr, nil)
		if err != nil {
			errType := syscall.EADDRINUSE
			if port != 0 && errors.Is(err, errType) {
				log.Warnf("Failed to start web service on defined port: %d, %v", port, err)
				log.Warn("Retry use random port...")
				port = 0
				continue
			}
			log.Errorf("Failed to start web service, %v", err)
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
			log.Errorf("Release random port error, %v", e)
		}
	}()
	return "0.0.0.0:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), nil
}
