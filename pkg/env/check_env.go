package env

import (
	"bytes"
	"runtime"

	"github.com/phoenixxc/elf-load-analyser/pkg/helper"
	"github.com/phoenixxc/elf-load-analyser/pkg/log"
)

// requiredConfigs kernel required configuration,
// see https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration
var requiredConfigs = []string{
	"CONFIG_BPF",
	"CONFIG_BPF_SYSCALL",
	"CONFIG_BPF_JIT",
	helper.IfElse(GetKernelVersion() >= "4.7", "CONFIG_HAVE_EBPF_JIT", "CONFIG_HAVE_BPF_JIT").(string),
	"CONFIG_BPF_EVENTS",
	// "CONFIG_IKHEADERS",
}

// 检查 BCC 环境
func CheckEnv() {
	EchoBanner()

	os, arch := GetSysOS(), runtime.GOARCH
	log.Infof("OS: %s\tARCH: %s", os, arch)

	// Check os
	helper.EqualWithTip("linux", os, "Unsupported platform, just work on linux")

	// Check kernel version
	if GetKernelVersion() < "4.1" {
		log.Errorf("Kernel version too old, linux kernel version 4.1 or newer is required\n" +
			"You can see \"https://github.com/iovisor/bcc/blob/master/INSTALL.md\"")
	}

	// Check kernel config
	for _, entry := range requiredConfigs {
		if _, ok := GetKernelConfigs()[entry]; !ok {
			log.Errorf(generalConfigTip())
		}
	}
}

func generalConfigTip() string {
	var buffer bytes.Buffer
	buffer.WriteString("Check EBPF kernel config error\n" +
		"The kernel should have been compiled with the following flags set:")
	for i := range requiredConfigs {
		buffer.WriteString("\n\t")
		buffer.WriteString(requiredConfigs[i])
	}
	buffer.WriteString("\nyou can check your kernel config use cmd `zcat /proc/config.gz | zgrep '^[^#].*BPF.*'`\n" +
		"for more information, see `https://github.com/iovisor/bcc/blob/master/INSTALL.md#kernel-configuration`")
	return buffer.String()
}
