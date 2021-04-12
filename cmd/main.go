package main

import (
	proc2 "github.com/xcphoenix/elf-load-analyser/pkg/xsys/proc"
	"os"
	"os/signal"
	"syscall"

	"github.com/xcphoenix/elf-load-analyser/pkg/core/xflag"

	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"
	"github.com/xcphoenix/elf-load-analyser/pkg/env"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	"github.com/xcphoenix/elf-load-analyser/pkg/log"
	_ "github.com/xcphoenix/elf-load-analyser/pkg/modules/module"
	"github.com/xcphoenix/elf-load-analyser/pkg/render"
	"github.com/xcphoenix/elf-load-analyser/pkg/web"
)

func main() {
	if proc2.IsMainControl() {
		xflag.AddCmdFlags(proc2.XFlagSet, log.XFlagSet, web.XFlagSet)
		xflag.ParseCmdFlags()
	}

	proc2.ControlDetach()
	env.CheckEnv()

	param := bcc.BuildCtx(proc2.GetProgPath())
	render.PreAnalyse(&param)

	param.Pid = proc2.CreateProcess()
	state.PushState(state.ProcessCreated)

	pool := factory.LoadMonitors(param)
	state.PushState(state.MonitorLoaded)
	proc2.WakeUpChild(param.Pid)

	web.VisualAnalyseData(pool)

	log.Info(log.Em("Press [CTRL+C] to exit"))
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGTSTP)
	<-exit

	state.PushState(state.Exit)
}
