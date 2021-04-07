package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/phoenixxc/elf-load-analyser/pkg/core/xflag"

	"github.com/phoenixxc/elf-load-analyser/pkg/bcc"
	"github.com/phoenixxc/elf-load-analyser/pkg/env"
	"github.com/phoenixxc/elf-load-analyser/pkg/factory"
	"github.com/phoenixxc/elf-load-analyser/pkg/log"
	_ "github.com/phoenixxc/elf-load-analyser/pkg/modules/module"
	"github.com/phoenixxc/elf-load-analyser/pkg/proc"
	"github.com/phoenixxc/elf-load-analyser/pkg/render"
	"github.com/phoenixxc/elf-load-analyser/pkg/state"
	"github.com/phoenixxc/elf-load-analyser/pkg/web"
)

func init() {
	xflag.AddCmdFlags(proc.XFlagSet, log.XFlagSet, web.XFlagSet)
	xflag.ParseCmdFlags()
}

func main() {
	proc.ControlDetach()
	env.CheckEnv()

	render.PreAnalyse(render.NewCtx(proc.GetProgPath()))

	childPID := proc.CreateProcess()
	state.PushState(state.ProcessCreated)

	pool, _ := factory.LoadMonitors(bcc.NewCtx(childPID))
	state.PushState(state.MonitorLoaded)
	proc.WakeUpChild(childPID)

	web.VisualAnalyseData(pool)

	log.Info(log.Em("Press [CTRL+C] to exit"))
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)
	<-exit

	state.PushState(state.Exit)
}
