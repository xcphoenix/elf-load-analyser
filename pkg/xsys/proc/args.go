package proc

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/xcphoenix/elf-load-analyser/pkg/core/state"
	"github.com/xcphoenix/elf-load-analyser/pkg/core/xflag"
	"golang.org/x/sys/unix"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

type fileFd struct {
	fd    *uintptr
	file  *string
	read  bool
	other uintptr
}

func newFileFd(fd *uintptr, file *string, read bool, other uintptr) *fileFd {
	return &fileFd{file: file, read: read, other: other, fd: fd}
}

func (ffd *fileFd) Fd() error {
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

var XFlagSet = xflag.OpInject(
	xflag.NewFlagValue(&procArg.args, "args", "program parameter, split by space"),
).Inject(
	xflag.NewFlagValue(&procArg.path, "path", "program path").
		WithValidator(pathValidator),
	xflag.NewFlagValue(&procArg.user, "user", "runner user").
		WithValidator(userValidator),
	xflag.NewFlagValue(&procArg.iFile, "in", "program stdin").
		WithValidator(newFileFd(&procArg.iFd, &procArg.iFile, true, 0).Fd),
	xflag.NewFlagValue(&procArg.oFile, "out", "program stdout").
		WithValidator(newFileFd(&procArg.oFd, &procArg.oFile, false, 1).Fd),
	xflag.NewFlagValue(&procArg.eFile, "err", "program stderr").
		WithValidator(newFileFd(&procArg.eFd, &procArg.eFile, false, 2).Fd),
	xflag.NewFlagValue(&procArg.childDaemon, "daemon", "child process daemon"),
)

func userValidator() error {
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

func pathValidator() error {
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
