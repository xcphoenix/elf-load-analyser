package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"
)

type FatalError string

func (f FatalError) Error() string {
	return string(f)
}

type ExitStateHook struct{}

func (e ExitStateHook) Levels() []log.Level {
	return []log.Level{log.FatalLevel}
}

func (e ExitStateHook) Fire(entry *log.Entry) error {
	state.WithError(FatalError(entry.Message))
	return nil
}

func init() {
	log.AddHook(ExitStateHook{})

	var customFormatter = new(log.TextFormatter)
	customFormatter.TimestampFormat = "15:04:05"
	customFormatter.FullTimestamp = true
	log.SetFormatter(customFormatter)
}
