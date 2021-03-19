package main

import (
    "flag"
    "github.com/phoenixxc/elf-load-analyser/pkg/bcc"
    "github.com/phoenixxc/elf-load-analyser/pkg/core"
    "github.com/phoenixxc/elf-load-analyser/pkg/env"
    "github.com/phoenixxc/elf-load-analyser/pkg/factory"
    "github.com/phoenixxc/elf-load-analyser/pkg/log"
    _ "github.com/phoenixxc/elf-load-analyser/pkg/modules/module"
    "github.com/phoenixxc/elf-load-analyser/pkg/proc"
    "github.com/phoenixxc/elf-load-analyser/pkg/render"
    "github.com/phoenixxc/elf-load-analyser/pkg/web"
    "os"
    "os/signal"
    "syscall"
)

func init() {
    core.AddCmdFlags(proc.XFlagSet, log.XFlagSet, web.XFlagSet)
    core.ParseCmdFlags()
}

func main() {
    preProcessing()
    env.CheckEnv()
    render.PreAnalyse(render.NewCtx(flag.Lookup("path").Value.String()))

    childPID := proc.CreateProcess()

    pool, _ := factory.LoadMonitors(bcc.NewCtx(childPID))
    proc.WakeUpChild(childPID)

    web.VisualAnalyseData(pool)

    log.Info(log.Emphasize("Press [CTRL+C] to exit"))
    exit := make(chan os.Signal, 1)
    signal.Notify(exit, os.Interrupt, syscall.SIGTERM)
    <-exit

    // TODO 中止的资源回收操作由状态机触发
}

func preProcessing() {
    // child
    transExecPath, isChild := os.LookupEnv(proc.ChildFlagEnv)
    if isChild {
        proc.ExecProcess(transExecPath)
        return
    }
    // banner
    env.EchoBanner()
}
