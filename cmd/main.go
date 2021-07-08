package main

import (
	"context"
	"github.com/xcphoenix/elf-load-analyser/pkg/data"
	"github.com/xcphoenix/elf-load-analyser/pkg/xsys/proc"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/xcphoenix/elf-load-analyser/pkg/core/xflag"

	"github.com/xcphoenix/elf-load-analyser/pkg/bcc"
	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"
	"github.com/xcphoenix/elf-load-analyser/pkg/env"
	"github.com/xcphoenix/elf-load-analyser/pkg/factory"
	_ "github.com/xcphoenix/elf-load-analyser/pkg/modules/module" // import modules
	"github.com/xcphoenix/elf-load-analyser/pkg/render"
	"github.com/xcphoenix/elf-load-analyser/pkg/web"
)

func main() {
	if proc.IsMainControl() {
		xflag.DefaultBind(proc.XFlagSet, web.XFlagSet).Parse()
	}

	proc.ControlDetach()
	env.CheckEnv()

	var param = bcc.PreParam{
		Path: proc.GetProgPath(),
	}
	render.PreAnalyse(&param)

	param.Pid = proc.CreateProcess()
	state.UpdateState(state.ProcessCreated)

	var pool = data.NewDataPool()
	factory.Load(context.Background(), pool, param)
	state.UpdateState(state.MonitorLoaded)

	proc.WakeUpChild(param.Pid)

	web.VisualAnalyseData(pool)

	log.Info("Press [CTRL+C] to exit")
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGTSTP)
	<-exit

	state.UpdateState(state.Exit)
}
