package proc

import (
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/xcphoenix/elf-load-analyser/pkg/core/xflag"

	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"

	"github.com/xcphoenix/elf-load-analyser/pkg/log"
	"golang.org/x/sys/unix"
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
}{}

type fileFd struct {
	fd    *uintptr
	file  *string
	read  bool
	other uintptr
}

func fd(fd *uintptr, file *string, read bool, other uintptr) *fileFd {
	return &fileFd{file: file, read: read, other: other, fd: fd}
}

func (ffd *fileFd) getFd() error {
	file := *ffd.file
	if len(file) == 0 {
		*ffd.fd = ffd.other
		return nil
	}
	var f *os.File
	var e error
	if ffd.read {
		f, e = os.Open(file)
	} else {
		f, e = os.OpenFile(file, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	}
	if e != nil {
		return e
	}
	state.RegisterHandler(state.Exit, func(_ error) error {
		log.Debugf("Close file: %s", f.Name())
		return f.Close()
	})
	*ffd.fd = f.Fd()
	return nil
}

// XFlagSet 属于此模块的命令行参数
var XFlagSet = xflag.OpInject(&procArg.args, "args", "", "program parameter, split by space", nil).
	Inject(&procArg.path, "path", "", "program path", pathHandle).
	Inject(&procArg.user, "user", "", "runner user", userHandle).
	OpInject(&procArg.iFile, "in", "", "program stdin", fd(&procArg.iFd, &procArg.iFile, true, 0).getFd).
	OpInject(&procArg.oFile, "out", "", "program stdout", fd(&procArg.oFd, &procArg.oFile, false, 1).getFd).
	OpInject(&procArg.eFile, "err", "", "program stderr", fd(&procArg.eFd, &procArg.eFile, false, 2).getFd)

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
		log.Errorf("Get pwd error, %v", err)
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
		log.Errorf("Create proc failed, %v", err)
	}

	log.Infof("Create child proc %d(parent: %d) success", childPID, os.Getppid())
	return childPID
}

// 唤醒子进程
func WakeUpChild(childPID int) {
	err := syscall.Kill(childPID, syscall.SIGUSR1)
	if err != nil {
		log.Errorf("Wake child proc error, %v", err)
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
		log.Errorf("Call binary failed, %v", err)
	}
	os.Exit(0)
}

func userHandle() error {
	s := strings.TrimSpace(procArg.user)
	if len(s) != 0 {
		u, err := user.Lookup(s)
		if err == nil {
			uid, _ := strconv.Atoi(u.Uid)
			gid, _ := strconv.Atoi(u.Gid)
			procArg.uid, procArg.gid = uint32(uid), uint32(gid)
			return nil
		}
	}
	return fmt.Errorf("invalid user")
}

func pathHandle() error {
	if len(procArg.path) == 0 {
		return fmt.Errorf("path can't be null")
	}
	absPath, err := filepath.Abs(procArg.path)
	if err != nil {
		return fmt.Errorf("invalid path, %w", err)
	}
	procArg.path = absPath

	if err := unix.Access(procArg.path, unix.X_OK); err != nil {
		return err
	}
	return nil
}
