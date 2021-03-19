package proc

import (
    "fmt"
    "github.com/phoenixxc/elf-load-analyser/pkg/core"
    "github.com/phoenixxc/elf-load-analyser/pkg/log"
    "golang.org/x/sys/unix"
    "os"
    "os/signal"
    "os/user"
    "path/filepath"
    "strconv"
    "strings"
    "syscall"
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

    needClosedFile []*os.File
}{}

var XFlagSet = core.InjectFlag(&procArg.args, "args", "", "(optional) program parameter, split by space", nil).
    InjectFlag(&procArg.path, "path", "", "program path", pathHandle).
    InjectFlag(&procArg.user, "user", "", "runner user", userHandle).
    InjectFlag(&procArg.iFile, "in", "", "(optional) program stdin", func() (e error) {
        procArg.iFd, e = getFd(procArg.iFile, true, 0)
        return
    }).
    InjectFlag(&procArg.oFile, "out", "", "(optional) program stdout", func() (e error) {
        procArg.oFd, e = getFd(procArg.oFile, false, 1)
        return
    }).
    InjectFlag(&procArg.eFile, "err", "", "(optional) program stderr", func() (e error) {
        procArg.eFd, e = getFd(procArg.eFile, false, 2)
        return
    })

func GetProgPath() string {
    return procArg.path
}

func ControlDetach() {
    transExecPath, isChild := os.LookupEnv(childFlagEnv)
    if isChild {
        execProcess(transExecPath)
        return
    }
}

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

func WakeUpChild(childPID int) {
    err := syscall.Kill(childPID, syscall.SIGUSR1)
    if err != nil {
        log.Errorf("Wake child proc error, %v", err)
    }
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

func getFd(file string, read bool, other uintptr) (uintptr, error) {
    if len(file) == 0 {
        return other, nil
    }
    var f *os.File
    var e error
    if read {
        f, e = os.Open(file)
    } else {
        f, e = os.OpenFile(file, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
    }
    if e != nil {
        return 0, fmt.Errorf("open %s error: %w", file, e)
    }
    procArg.needClosedFile = append(procArg.needClosedFile, f)
    return f.Fd(), nil
}
