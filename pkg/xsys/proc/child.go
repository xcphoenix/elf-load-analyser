package proc

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"

	log "github.com/sirupsen/logrus"
)

const (
	childFlagEnv  = "_CHILD_46cf632ae5fb1e8cbb556aa49964ac7d"
	childArgsFlag = "_ARGS_51cee58d2009745b72acb79005a881e4"
)

var procArg = struct {
	args string
	path string

	user     string
	uid, gid uint32

	iFile, oFile, eFile string
	iFd, oFd, eFd       uintptr
	childDaemon         bool
}{}

// 获取程序路径
func GetProgPath() string {
	return procArg.path
}

// 控制流分离
func ControlDetach() {
	transExecPath, isChild := os.LookupEnv(childFlagEnv)
	if isChild {
		execProcess(transExecPath)
		return
	}
}

// 是否是主程序执行流
func IsMainControl() bool {
	_, isChild := os.LookupEnv(childFlagEnv)
	return !isChild
}

// 创建子进程，返回进程 pid
func CreateProcess() int {
	execArgs := procArg.args
	args := os.Args

	pwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Get pwd error, %v", err)
	}
	childEnvItem := fmt.Sprintf("%s=%s", childFlagEnv, procArg.path)
	childArgItem := fmt.Sprintf("%s=%s", childArgsFlag, strings.TrimSpace(execArgs))
	childPID, err := syscall.ForkExec(args[0], args, &syscall.ProcAttr{ //nolint:gosec
		Dir: pwd,
		Env: append(os.Environ(), childEnvItem, childArgItem),
		Sys: &syscall.SysProcAttr{
			Setsid: true,
			Credential: &syscall.Credential{
				Uid: procArg.uid,
				Gid: procArg.gid,
			},
		},
		Files: []uintptr{procArg.iFd, procArg.oFd, procArg.eFd},
	})
	if err != nil {
		log.Fatalf("Create proc failed, %v", err)
	}

	log.Infof("Create child proc %d(parent: %d) success", childPID, os.Getppid())

	// 关闭子进程
	if !procArg.childDaemon {
		state.RegisterHandler(state.Exit, func(_ error) error {
			log.Infof("Start close child progress if live..")
			_ = syscall.Kill(childPID, syscall.SIGKILL)
			return nil
		})
	}

	return childPID
}

// 唤醒子进程
func WakeUpChild(childPID int) {
	err := syscall.Kill(childPID, syscall.SIGUSR1)
	if err != nil {
		log.Fatalf("Wake child proc error, %v", err)
	}
	log.Infof("Wake child proc success")
}

func execProcess(execPath string) {
	// wait until parent load bcc modules ok
	startSignals := make(chan os.Signal, 1)
	signal.Notify(startSignals, syscall.SIGUSR1)
	<-startSignals

	argsEnv, _ := os.LookupEnv(childArgsFlag)
	execArgs := []string{execPath}
	execArgs = append(execArgs, strings.Fields(argsEnv)...)
	if err := syscall.Exec(execPath, execArgs, os.Environ()); err != nil {
		log.Fatalf("Call binary failed, %v", err)
	}
	os.Exit(0)
}
