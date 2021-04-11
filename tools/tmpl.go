package tools

import (
	_ "embed" // embed template files
	"flag"
	"strings"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/helper"
)

type MonitorModel struct {
	EventType      string
	BccSourceFile  string
	BccSourceValue string
	MonitorType    string
	MonitorName    string
	TraceName      string
	FnName         string
}

func NewMonitorModel(traceCFun, fnName string, isSysCall bool) *MonitorModel {
	traceCFun = strings.ToUpper(traceCFun)
	camelTraceCFun := CamelName(traceCFun)
	if len(fnName) == 0 {
		// default set kretprobe
		fnName = "kretprobe__" + traceCFun
	}
	return &MonitorModel{
		FnName:         fnName,
		MonitorName:    traceCFun,
		MonitorType:    camelTraceCFun,
		BccSourceFile:  traceCFun + ".cpp.k",
		BccSourceValue: camelTraceCFun + "Source",
		EventType:      camelTraceCFun + "Event",
		TraceName:      helper.IfElse(isSysCall, bpf.GetSyscallFnName(traceCFun), traceCFun).(string),
	}
}

var (
	//go:embed template/monitor.tpl
	monitorTpl string
	//go:embed template/bcc.tpl
	bccCodeTpl string
)

var (
	isSysCall bool
	traceCFun string
	fnName    string
)

func init() {
	flag.BoolVar(&isSysCall, "s", false, "is syscall")
	flag.StringVar(&fnName, "f", "", "bcc function name")
	flag.StringVar(&traceCFun, "t", "", "trace c function in kernel")
	flag.Parse()
}

func main() {
	//if len(traceCFun) == 0 {
	//	log.Fatal("Trace c function cannot be null")
	//}
	//mTmpl, err := template.New("monitor").Parse(monitorTpl)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//monitorModel := NewMonitorModel(traceCFun, fnName, isSysCall)

}

func CamelName(name string) string {
	name = strings.ReplaceAll(name, "_", " ")
	name = strings.Title(name)
	return strings.ReplaceAll(name, " ", "")
}
