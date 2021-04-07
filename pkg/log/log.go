package log

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/phoenixxc/elf-load-analyser/pkg/core/xflag"

	"github.com/phoenixxc/elf-load-analyser/pkg/state"
)

type Level int8

const (
	DLevel Level = iota
	ILevel
	WLevel
	ELevel
)

var (
	curLevelDesc string
	currentLevel Level
	defaultFlags = log.Lmicroseconds | log.Ltime

	debugLogger logger = newBaseLogger(DLevel, os.Stdout, "D ", defaultFlags).SetHandle(minor)
	infoLogger  logger = newBaseLogger(ILevel, os.Stdout, "I ", defaultFlags)
	warnLogger  logger = newBaseLogger(WLevel, os.Stdout, "W ", defaultFlags).SetHandle(warn)
	errorLogger logger = newBaseLogger(ELevel, os.Stderr, "E ", defaultFlags).SetHandle(err)
)

var XFlagSet = xflag.OpInject(&curLevelDesc, "log", "info",
	"log Level[info debug warn error], default: info", setConfigLevel)

type logger interface {
	Level() Level
	Log(a interface{})
	Logf(format string, a ...interface{})
}

func ConfigLevel() Level {
	return currentLevel
}

func setConfigLevel() error {
	currentLevel = ILevel
	if len(curLevelDesc) == 0 {
		return nil
	}
	switch curLevelDesc {
	case "debug":
		currentLevel = DLevel
	case "info":
		currentLevel = ILevel
	case "warn":
		currentLevel = WLevel
	case "error":
		currentLevel = ELevel
	default:
		return fmt.Errorf("invalid log Level %q", curLevelDesc)
	}
	return nil
}

type baseLogger struct {
	log    *log.Logger
	level  Level
	handle func(s string) string
}

func newBaseLogger(level Level, w io.Writer, prefix string, flag int) *baseLogger {
	return &baseLogger{level: level, log: log.New(w, prefix, flag)}
}

func (b *baseLogger) SetHandle(handle func(s string) string) *baseLogger {
	b.handle = handle
	return b
}

func (b baseLogger) Log(a interface{}) {
	message := fmt.Sprint(a)
	wrapMsg := message
	if b.handle != nil {
		wrapMsg = b.handle(message)
	}
	b.log.Println(wrapMsg)
}

func (b baseLogger) Logf(format string, a ...interface{}) {
	b.Log(fmt.Sprintf(format, a...))
}

func (b baseLogger) Level() Level {
	return b.level
}

func Info(a interface{}) {
	innerLog(infoLogger, a)
}

func Infof(format string, a ...interface{}) {
	innerLogf(infoLogger, format, a...)
}

func Warn(a interface{}) {
	innerLog(warnLogger, a)
}

func Warnf(format string, a ...interface{}) {
	innerLogf(warnLogger, format, a...)
}

func Debug(a interface{}) {
	innerLog(debugLogger, a)
}

func Debugf(format string, a ...interface{}) {
	innerLogf(debugLogger, format, a...)
}

func Error(e error) {
	innerLog(errorLogger, e)
	state.WithError(e)
	os.Exit(1)
}

func Errorf(format string, a ...interface{}) {
	innerLogf(errorLogger, format, a...)
	var err error
	if len(a) > 0 {
		if e, ok := a[len(a)-1].(error); ok {
			err = e
		}
	}
	state.WithError(err)
	os.Exit(1)
}

func innerLog(log logger, a interface{}) {
	if log.Level() >= ConfigLevel() {
		log.Log(appendPkgLine(a))
	}
}

func innerLogf(log logger, format string, a ...interface{}) {
	if log.Level() >= ConfigLevel() {
		log.Logf(appendPkgLine(format), a...)
	}
}

// #2
func appendPkgLine(a interface{}) string {
	pkg := getPkgLine()
	return fmt.Sprintf(italic("%-9s")+" - %v", pkg, a)
}

// #1
// NOTE: cache pkg
func getPkgLine() (pkg string) {
	_, pkg, _, _ = runtime.Caller(4)
	pkgPrefix, cmdPrefix := "pkg", "cmd"
	if idx := strings.LastIndex(pkg, "/"); idx != -1 {
		pkg = pkg[:idx]
	}
	if idx := strings.Index(pkg, pkgPrefix); idx != -1 {
		pkg = pkg[idx+len(pkgPrefix)+1:]
	} else if idx := strings.Index(pkg, cmdPrefix); idx != -1 {
		pkg = pkg[idx:]
	}
	if strings.ContainsRune(pkg, '/') {
		var buf bytes.Buffer
		pkgList := strings.Split(pkg, "/")
		for i := range pkgList {
			if i != len(pkgList)-1 {
				buf.WriteString(pkgList[i][0:1])
				buf.WriteRune('/')
			} else {
				buf.WriteString(pkgList[i])
			}
		}
		return buf.String()
	}
	return
}
